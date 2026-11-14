//! Native installation for iPadn.
//!
//! Talks to this device's own installation service, the one desktop tools
//! reach over USB, through a loopback VPN and either an imported certificate
//! pairing record (legacy_lockdown, iOS 16) or remote pairing file (RSD).
//! Unlike a manifest (`itms-services`) install, the system keeps the package's App
//! Store purchase record and replaces an App Store copy in place.
//!
//! On iOS 27 and later the pairing file itself can be made on the device; see
//! [`pairing`].
//!
//! Every entry point takes a JSON request and returns a JSON reply the caller
//! frees with `iPadnNativeFree`; nothing here aborts or unwinds into Swift.

use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use idevice::afc::{AfcClient, opcode::AfcFopenMode};
use idevice::installation_proxy::InstallationProxyClient;
use idevice::remote_pairing::{
    RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
};
use idevice::rsd::RsdHandshake;
use idevice::tcp::{adapter::Adapter, handle::AdapterHandle};
use idevice::{IdeviceError, RsdService};
use serde::Deserialize;
use serde_json::{Value as Json, json};
use tokio::io::AsyncReadExt;

mod legacy;
mod legacy_heartbeat;
#[cfg(test)]
mod test_wire;
mod legacy_transport;
mod installation_query;
mod io_diagnostics;
mod pairing;

#[cfg(test)]
mod tests;

const STAGING_DIRECTORY: &str = "PublicStaging";
const STAGED_PACKAGE: &str = "PublicStaging/ipadn-native.ipa";
const UPLOAD_CHUNK: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const MAX_REPLY: u32 = 64 * 1024 * 1024;

pub const PHASE_CONNECT: i32 = 0;
pub const PHASE_UPLOAD: i32 = 1;
pub const PHASE_INSTALL: i32 = 2;

static CANCELLED: AtomicBool = AtomicBool::new(false);

pub type ProgressCallback = extern "C" fn(context: *mut c_void, phase: i32, done: u64, total: u64);

#[derive(Clone, Copy)]
struct Progress {
    callback: Option<ProgressCallback>,
    context: *mut c_void,
}
// The caller guarantees `context` outlives the call and may be used from any thread.
unsafe impl Send for Progress {}
unsafe impl Sync for Progress {}

impl Progress {
    fn report(&self, phase: i32, done: u64, total: u64) {
        if let Some(callback) = self.callback {
            callback(self.context, phase, done, total);
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Transport {
    /// Existing RPPairing/RSD path remains the default for old callers.
    #[default]
    RemotePairing,
    LegacyLockdown,
}

#[derive(Deserialize)]
pub(crate) struct Request {
    #[serde(default)]
    transport: Transport,
    /// Imported RPPairing record, or certificate-based plist for legacy_lockdown.
    pairing_file: String,
    /// Address of this device through the loopback VPN, normally 10.7.0.1.
    host: String,
    /// Remote pairing service port, or exactly 62078 for legacy_lockdown.
    port: u16,
    bundle_id: String,
    #[serde(default)]
    ipa: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    /// A replacement purchase record (iTunesMetadata.plist, base64). The
    /// system keeps it instead of the package's own; iPadn uses it to mark
    /// the installed version as the newest so the App Store offers no update.
    #[serde(default)]
    metadata: Option<String>,
}

/// A failure tagged with the step it happened in, so the app can explain it.
pub(crate) struct Failure {
    stage: &'static str,
    message: String,
    diagnostics: Vec<String>,
}

pub(crate) fn fail<E: std::fmt::Debug>(stage: &'static str) -> impl FnOnce(E) -> Failure {
    move |error| failure(stage, format!("{error:?}"))
}

pub(crate) fn failure(stage: &'static str, message: impl Into<String>) -> Failure {
    Failure { stage, message: message.into(), diagnostics: Vec::new() }
}

struct RemoteSession {
    adapter: AdapterHandle,
    handshake: RsdHandshake,
}

/// A legacy lockdown socket is never used as an RSD tunnel, or vice versa.
enum Session {
    Remote(RemoteSession),
    Legacy(legacy::LegacySession),
}

impl installation_query::Service for Session {
    async fn open(&mut self) -> Result<InstallationProxyClient, Failure> {
        self.installation_proxy().await
    }
    fn record(&self, entry: String) { self.record_query(entry); }
    fn allows_legacy_retry(&self) -> bool { matches!(self, Self::Legacy(_)) }
    async fn guard<T>(&self, work: impl std::future::Future<Output = Result<T, Failure>>) -> Result<T, Failure> {
        self.guard(work).await
    }
}

impl Session {
    async fn guard<T>(&self, work: impl std::future::Future<Output = Result<T, Failure>>) -> Result<T, Failure> {
        match self {
            Self::Legacy(session) => session.guard(work).await,
            Self::Remote(_) => work.await,
        }
    }

    fn finish(&self, result: Result<Json, Failure>) -> Result<Json, Failure> {
        let Self::Legacy(session) = self else { return result };
        let diagnostics = session.diagnostics();
        match result {
            Ok(mut reply) => {
                reply["connection_diagnostics"] = json!(diagnostics);
                Ok(reply)
            }
            Err(mut error) => {
                error.diagnostics.extend(diagnostics);
                Err(error)
            }
        }
    }

    async fn installation_proxy(&mut self) -> Result<InstallationProxyClient, Failure> {
        match self {
            Self::Remote(s) => InstallationProxyClient::connect_rsd(&mut s.adapter, &mut s.handshake)
                .await.map_err(fail("installation_proxy")),
            Self::Legacy(s) => s.service::<InstallationProxyClient>().await,
        }
    }

    async fn afc(&mut self) -> Result<AfcClient, Failure> {
        match self {
            Self::Remote(s) => AfcClient::connect_rsd(&mut s.adapter, &mut s.handshake)
                .await.map_err(fail("afc")),
            Self::Legacy(s) => s.service::<AfcClient>().await,
        }
    }

    fn service_error(&self, stage: &'static str, error: IdeviceError) -> Failure {
        match self {
            Self::Legacy(_) => legacy::safe_error(stage, error),
            Self::Remote(_) => fail(stage)(error),
        }
    }

    fn record_query(&self, entry: String) {
        if let Self::Legacy(session) = self { session.record_query(entry); }
    }

    async fn close(&mut self) {
        if let Self::Legacy(s) = self { s.close().await; }
    }
}

async fn connect(request: &Request) -> Result<Session, Failure> {
    let ip: IpAddr = request.host.parse()
        .map_err(|_| failure("request", "host must be a numeric IP address"))?;
    if request.pairing_file.trim().is_empty() || request.port == 0 {
        return Err(failure("request", "missing pairing file or service port"));
    }
    match request.transport {
        Transport::RemotePairing => connect_remote(request, ip).await.map(Session::Remote),
        Transport::LegacyLockdown => legacy::LegacySession::connect(request, ip).await.map(Session::Legacy),
    }
}

async fn connect_remote(request: &Request, ip: IpAddr) -> Result<RemoteSession, Failure> {
    let address = SocketAddr::new(ip, request.port);
    let mut pairing = RpPairingFile::read_from_file(&request.pairing_file)
        .await
        .map_err(fail("pairing_file"))?;
    let hostname = request.hostname.as_deref().unwrap_or("iPadn");

    let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(address))
        .await
        .map_err(|_| failure("connect", "timed out"))?
        .map_err(fail("connect"))?;
    let mut client = RemotePairingClient::new(RpPairingSocket::new(stream), hostname);

    // Verify only. A rejected file must not start a new pairing: that would
    // raise a trust prompt and silently replace the user's file.
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        client.attempt_pair_verify().await?;
        client.validate_pairing(&mut pairing).await
    })
    .await
    .map_err(|_| failure("pairing", "timed out"))?
    .map_err(fail("pairing"))?;

    tokio::time::timeout(HANDSHAKE_TIMEOUT, open_tunnel(&mut client, address))
        .await
        .map_err(|_| failure("tunnel", "timed out"))?
        .map_err(fail("tunnel"))
}

async fn open_tunnel(
    client: &mut RemotePairingClient<RpPairingSocket<tokio::net::TcpStream>>,
    mut address: SocketAddr,
) -> Result<RemoteSession, IdeviceError> {
    address.set_port(client.create_tcp_listener().await?);
    let stream = tokio::net::TcpStream::connect(address).await?;
    let tunnel = connect_tls_psk_tunnel_native(stream, client.encryption_key()).await?;

    let invalid = |what: &str| IdeviceError::InternalError(format!("invalid tunnel {what}"));
    let client_ip: IpAddr =
        tunnel.info.client_address.parse().map_err(|_| invalid("client address"))?;
    let server_ip: IpAddr =
        tunnel.info.server_address.parse().map_err(|_| invalid("server address"))?;
    let mtu = tunnel.info.mtu as usize;
    let rsd_port = tunnel.info.server_rsd_port;

    let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), client_ip, server_ip);
    adapter.set_mss(mtu.clamp(576, 8192) - 60);
    let mut adapter = adapter.to_async_handle();
    let handshake = RsdHandshake::new(adapter.connect(rsd_port).await?).await?;
    Ok(RemoteSession { adapter, handshake })
}

async fn lookup(session: &mut Session, bundle_id: &str) -> Result<Json, Failure> {
    let attributes = [
        "CFBundleIdentifier",
        "CFBundleShortVersionString",
        "CFBundleVersion",
        "SignerIdentity",
        "IsPlaceholder",
        "iTunesMetadata",
    ];
    let mut options = plist::Dictionary::new();
    options.insert("ApplicationType".into(), "Any".into());
    options.insert("BundleIDs".into(), plist::Value::Array(vec![bundle_id.into()]));
    options.insert(
        "ReturnAttributes".into(),
        plist::Value::Array(attributes.into_iter().map(Into::into).collect()),
    );
    let mut message = plist::Dictionary::new();
    message.insert("Command".into(), "Lookup".into());
    message.insert("ClientOptions".into(), plist::Value::Dictionary(options));

    let mut result = installation_query::run_with_retry(session, &plist::Value::Dictionary(message)).await?;
    let Some(plist::Value::Dictionary(app)) = result.remove(bundle_id) else {
        return Ok(json!({ "installed": false }));
    };
    Ok(describe(&app))
}

/// What iPadn reports about one installed app.
fn describe(app: &plist::Dictionary) -> Json {
    let text = |key: &str| app.get(key).and_then(|value| value.as_string()).map(str::to_string);
    let metadata = match app.get("iTunesMetadata") {
        Some(plist::Value::Data(data)) => plist::from_bytes::<plist::Dictionary>(data).ok(),
        Some(plist::Value::Dictionary(dictionary)) => Some(dictionary.clone()),
        _ => None,
    }
    .unwrap_or_default();
    let number = |key: &str| {
        metadata.get(key).and_then(|value| {
            value
                .as_unsigned_integer()
                .map(|number| number.to_string())
                .or_else(|| value.as_signed_integer().map(|number| number.to_string()))
                .or_else(|| value.as_string().map(str::to_string))
        })
    };
    json!({
        "installed": true,
        "bundle_id": text("CFBundleIdentifier"),
        "name": text("CFBundleDisplayName").or_else(|| text("CFBundleName")),
        "version": text("CFBundleShortVersionString"),
        "build": text("CFBundleVersion"),
        "signer": text("SignerIdentity"),
        "placeholder": app.get("IsPlaceholder").and_then(|value| value.as_boolean()).unwrap_or(false),
        "store_item_id": number("itemId"),
        "store_version_id": number("softwareVersionExternalIdentifier"),
        "has_purchase_record": metadata.contains_key("com.apple.iTunesStore.downloadInfo"),
        "manifest_install": metadata.contains_key("enterpriseInstallURL"),
    })
}

/// Every app the user installed, with the same details as `lookup`.
async fn list(session: &mut Session) -> Result<Json, Failure> {
    let attributes = [
        "CFBundleIdentifier",
        "CFBundleDisplayName",
        "CFBundleName",
        "CFBundleShortVersionString",
        "CFBundleVersion",
        "SignerIdentity",
        "IsPlaceholder",
        "iTunesMetadata",
    ];
    let mut options = plist::Dictionary::new();
    options.insert("ApplicationType".into(), "User".into());
    options.insert(
        "ReturnAttributes".into(),
        plist::Value::Array(attributes.into_iter().map(Into::into).collect()),
    );
    let mut message = plist::Dictionary::new();
    message.insert("Command".into(), "Lookup".into());
    message.insert("ClientOptions".into(), plist::Value::Dictionary(options));

    let result = installation_query::run_with_retry(session, &plist::Value::Dictionary(message))
        .await.map_err(|mut e| { if e.stage == "lookup" { e.stage = "list"; } e })?;
    let apps: Vec<Json> = result
        .iter()
        .filter_map(|(bundle_id, value)| {
            let plist::Value::Dictionary(app) = value else { return None };
            let mut entry = describe(app);
            if entry["bundle_id"].is_null() {
                entry["bundle_id"] = json!(bundle_id);
            }
            Some(entry)
        })
        .collect();
    Ok(json!(apps))
}

async fn checked_io<T>(
    session: &Session,
    stage: &'static str,
    work: impl std::future::Future<Output = Result<T, IdeviceError>>,
) -> Result<T, Failure> {
    session.guard(async { tokio::time::timeout(IO_TIMEOUT, work).await
        .map_err(|_| failure(stage, "timed out"))?
        .map_err(|e| session.service_error(stage, e))
    }).await
}

async fn upload(session: &mut Session, path: &str, progress: Progress) -> Result<(), Failure> {
    let mut file = tokio::fs::File::open(path).await.map_err(fail("package"))?;
    let total = file.metadata().await.map_err(fail("package"))?.len();
    let mut afc = session.afc().await?;
    let info = session.guard(async {
        tokio::time::timeout(IO_TIMEOUT, afc.get_file_info(STAGING_DIRECTORY)).await
            .map_err(|_| failure("upload", "timed out"))
    }).await?;
    if info.is_err() {
        checked_io(session, "upload", afc.mk_dir(STAGING_DIRECTORY)).await?;
    }

    let mut buffer = vec![0u8; UPLOAD_CHUNK];
    let mut sent = 0u64;
    progress.report(PHASE_UPLOAD, 0, total);
    let (outcome, closed) = {
        let mut descriptor = checked_io(session, "upload",
            afc.open(STAGED_PACKAGE, AfcFopenMode::WrOnly)).await?;
        // Streamed in chunks: reading a whole package into memory gets a phone
        // app killed for packages of a few hundred megabytes.
        let outcome: Result<(), Failure> = loop {
            if CANCELLED.load(Ordering::SeqCst) {
                break Err(failure("cancelled", "cancelled"));
            }
            let read = match file.read(&mut buffer).await {
                Ok(0) => break Ok(()),
                Ok(read) => read,
                Err(error) => break Err(fail("package")(error)),
            };
            if let Err(error) = checked_io(session, "upload", descriptor.write_entire(&buffer[..read])).await {
                break Err(error);
            }
            sent += read as u64;
            progress.report(PHASE_UPLOAD, sent, total);
        };
        // Close even after a failed write, or the device-side descriptor leaks.
        (outcome, checked_io(session, "upload", descriptor.close()).await)
    };
    let complete = outcome.is_ok() && closed.is_ok() && sent == total;
    if !complete {
        let _ = checked_io(session, "upload", afc.remove(STAGED_PACKAGE)).await;
    }
    outcome?;
    closed?;
    if sent != total {
        return Err(failure("package", "package changed while uploading"));
    }
    Ok(())
}

async fn remove_staged(session: &mut Session) {
    let _ = tokio::time::timeout(LOOKUP_TIMEOUT, async {
        if let Ok(mut afc) = session.afc().await {
            let _ = checked_io(session, "upload", afc.remove(STAGED_PACKAGE)).await;
        }
    }).await;
}

async fn checked_lookup(session: &mut Session, bundle_id: &str) -> Result<Json, Failure> {
    tokio::time::timeout(LOOKUP_TIMEOUT, lookup(session, bundle_id))
        .await
        .map_err(|_| failure("lookup", "timed out"))?
}

async fn checked_list(session: &mut Session) -> Result<Json, Failure> {
    tokio::time::timeout(LOOKUP_TIMEOUT, list(session))
        .await
        .map_err(|_| failure("list", "timed out"))?
}

async fn install(request: &Request, progress: Progress) -> Result<Json, Failure> {
    let package = request.ipa.as_deref().filter(|s| !s.is_empty())
        .ok_or_else(|| failure("request", "missing ipa"))?;
    if request.bundle_id.trim().is_empty() {
        return Err(failure("request", "missing bundle_id"));
    }
    // Reject malformed metadata before uploading, not after modifying staging.
    let metadata = decode_metadata(request.metadata.as_deref())?;
    progress.report(PHASE_CONNECT, 0, 1);
    let mut session = connect(request).await?;
    let outcome = install_in_session(request, package, metadata, progress, &mut session).await;
    session.close().await;
    session.finish(outcome)
}

fn decode_metadata(encoded: Option<&str>) -> Result<Option<Vec<u8>>, Failure> {
    use base64::Engine;
    encoded.map(|text| {
        let bytes = base64::engine::general_purpose::STANDARD.decode(text)
            .map_err(|_| failure("request", "metadata is not valid base64"))?;
        plist::from_bytes::<plist::Dictionary>(&bytes)
            .map_err(|_| failure("request", "metadata must be a plist dictionary"))?;
        Ok(bytes)
    }).transpose()
}

async fn install_in_session(
    request: &Request,
    package: &str,
    metadata: Option<Vec<u8>>,
    progress: Progress,
    session: &mut Session,
) -> Result<Json, Failure> {
    let before = checked_lookup(session, &request.bundle_id).await?;
    progress.report(PHASE_CONNECT, 1, 1);

    upload(session, package, progress).await?;
    if CANCELLED.load(Ordering::SeqCst) {
        remove_staged(session).await;
        return Err(failure("cancelled", "cancelled"));
    }

    // Upgrade replaces an installed copy in place and keeps its data; the
    // system reads the purchase record and licence from the package itself.
    let upgrade = before["installed"] == json!(true);
    let mut options = plist::Dictionary::new();
    options.insert("CFBundleIdentifier".into(), request.bundle_id.clone().into());
    if let Some(record) = &metadata {
        options.insert("iTunesMetadata".into(), plist::Value::Data(record.clone()));
    }
    let options = Some(plist::Value::Dictionary(options));
    let mut client = match session.installation_proxy().await {
        Ok(client) => client,
        Err(error) => {
            remove_staged(session).await;
            return Err(error);
        }
    };
    if CANCELLED.load(Ordering::SeqCst) {
        drop(client);
        remove_staged(session).await;
        return Err(failure("cancelled", "cancelled"));
    }
    progress.report(PHASE_INSTALL, 0, 100);
    let report = |(percent, progress): (u64, Progress)| async move {
        progress.report(PHASE_INSTALL, percent.min(100), 100);
    };
    // Timing out stops waiting, not the system's in-progress install. The
    // caller must check inventory before retrying after this ambiguous result.
    // Heartbeat loss makes completion unknown too. Keep the staged input and
    // never replay Install/Upgrade automatically after this ambiguous outcome.
    let result = session.guard(async { Ok(tokio::time::timeout(INSTALL_TIMEOUT, async {
        if upgrade {
            client.upgrade_with_callback(STAGED_PACKAGE, options, report, progress).await
        } else {
            client.install_with_callback(STAGED_PACKAGE, options, report, progress).await
        }
    }).await) }).await?;
    drop(client);
    // Keep the staged package if completion is unknown: the system may still
    // be reading it. Do not delete an install's input just because we timed out.
    let result = result.map_err(|_| failure("install",
        "timed out waiting for installation; the system may still finish; check inventory before retrying"))?;
    remove_staged(session).await;
    if let Err(error) = result {
        return Err(session.service_error("install", error));
    }

    // InstallationProxy's Complete alone is not evidence that the app or its
    // purchase metadata survived. Never silently convert failed lookup to null.
    let after = checked_lookup(session, &request.bundle_id).await
        .map_err(|_| failure("verify", "install completed but post-install lookup failed; check inventory before retrying"))?;
    verify_installation(&request.bundle_id, &before, &after, metadata.as_deref())?;
    Ok(json!({ "ok": true, "upgraded": upgrade, "before": before, "after": after }))
}

fn verify_installation(bundle_id: &str, before: &Json, after: &Json, metadata: Option<&[u8]>) -> Result<(), Failure> {
    let unverified = || failure("verify", "install completed but application or purchase metadata could not be verified; check inventory before retrying");
    if after["installed"] != json!(true) || after["bundle_id"].as_str() != Some(bundle_id)
        || after["placeholder"] == json!(true)
    {
        return Err(unverified());
    }
    if let Some(bytes) = metadata {
        let expected: plist::Dictionary = plist::from_bytes(bytes).map_err(|_| unverified())?;
        let mut app = plist::Dictionary::new();
        app.insert("iTunesMetadata".into(), plist::Value::Dictionary(expected.clone()));
        let described = describe(&app);
        for field in ["store_item_id", "store_version_id"] {
            if !described[field].is_null() && after[field] != described[field] {
                return Err(unverified());
            }
        }
        if expected.contains_key("com.apple.iTunesStore.downloadInfo")
            && after["has_purchase_record"] != json!(true)
        {
            return Err(unverified());
        }
    } else if before["has_purchase_record"] == json!(true) {
        if after["has_purchase_record"] != json!(true)
            || (!before["store_item_id"].is_null() && before["store_item_id"] != after["store_item_id"])
        {
            return Err(unverified());
        }
    }
    Ok(())
}

fn run<R, F, Fut>(request: *const c_char, work: F) -> *mut c_char
where
    R: serde::de::DeserializeOwned,
    F: FnOnce(R) -> Fut,
    Fut: std::future::Future<Output = Result<Json, Failure>>,
{
    let reply = (|| {
        if request.is_null() {
            return Err(failure("request", "null request"));
        }
        let text = unsafe { CStr::from_ptr(request) }.to_str().map_err(fail("request"))?;
        let request: R = serde_json::from_str(text)
            .map_err(|_| failure("request", "invalid request JSON or fields"))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(fail("runtime"))?;
        let reply = runtime.block_on(work(request));
        // Tunnel tasks hold sockets; do not wait on them indefinitely.
        runtime.shutdown_timeout(Duration::from_secs(2));
        reply
    })();
    let reply = reply.unwrap_or_else(|failure| {
        json!({ "ok": false, "stage": failure.stage, "message": failure.message,
                "connection_diagnostics": failure.diagnostics })
    });
    CString::new(reply.to_string())
        .unwrap_or_else(|_| {
            CString::new(r#"{"ok":false,"stage":"reply","message":"invalid reply"}"#).unwrap()
        })
        .into_raw()
}

/// Installs or upgrades `ipa`. Blocks until the system finishes.
///
/// # Safety
/// `request` must be a valid NUL-terminated string. `context` must stay valid
/// for the whole call; `progress` may be invoked from another thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iPadnNativeInstall(
    request: *const c_char,
    progress: Option<ProgressCallback>,
    context: *mut c_void,
) -> *mut c_char {
    CANCELLED.store(false, Ordering::SeqCst);
    let progress = Progress { callback: progress, context };
    run(request, |request: Request| async move { install(&request, progress).await })
}

/// Connects and reports what the system has installed for `bundle_id`.
///
/// # Safety
/// `request` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iPadnNativeLookup(request: *const c_char) -> *mut c_char {
    run(request, |request: Request| async move {
        let mut session = connect(&request).await?;
        let app = checked_lookup(&mut session, &request.bundle_id).await;
        session.close().await;
        session.finish(app.map(|app| json!({ "ok": true, "app": app })))
    })
}

/// Connects and reports every app the user installed.
///
/// # Safety
/// `request` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iPadnNativeList(request: *const c_char) -> *mut c_char {
    run(request, |request: Request| async move {
        let mut session = connect(&request).await?;
        let apps = checked_list(&mut session).await;
        session.close().await;
        session.finish(apps.map(|apps| json!({ "ok": true, "apps": apps })))
    })
}

/// Lets the device pair with this app as if it were a computer (iOS 27 and
/// later). Blocks until pairing completes, fails, times out or is cancelled.
///
/// `events` receives, in order: ready (JSON with the port, the service
/// identifier and the TXT records to advertise), connected, and the PIN the
/// user types on the device. The reply carries the pairing file as base64.
///
/// # Safety
/// `request` must be a valid NUL-terminated string. `context` must stay valid
/// for the whole call; `events` may be invoked from another thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iPadnNativePair(
    request: *const c_char,
    events: Option<pairing::EventCallback>,
    context: *mut c_void,
) -> *mut c_char {
    let events = pairing::Events { callback: events, context };
    run(request, |request: pairing::PairRequest| async move { pairing::pair(request, events).await })
}

/// Stops a pairing that is waiting for the device.
#[unsafe(no_mangle)]
pub extern "C" fn iPadnNativePairCancel() {
    pairing::cancel();
}

/// Stops an upload in progress. A started system install cannot be stopped.
#[unsafe(no_mangle)]
pub extern "C" fn iPadnNativeCancel() {
    CANCELLED.store(true, Ordering::SeqCst);
}

/// Frees a reply returned by this library.
///
/// # Safety
/// `reply` must come from this library and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iPadnNativeFree(reply: *mut c_char) {
    if !reply.is_null() {
        drop(unsafe { CString::from_raw(reply) });
    }
}
