//! Certificate-based lockdown over the caller's existing VPN mapping.
//!
//! API references, pinned idevice 0.1.68 (MIT):
//! - https://docs.rs/idevice/0.1.68/src/idevice/provider.rs.html
//!   `TcpProvider`, `IdeviceProvider::{connect,get_pairing_file}`.
//! - https://docs.rs/idevice/0.1.68/src/idevice/pairing_file.rs.html
//!   `PairingFile::from_value` (not RpPairingFile).
//! - https://docs.rs/idevice/0.1.68/src/idevice/services/lockdown.rs.html
//!   `start_session`, `start_service`, `stop_session`.
//! - https://docs.rs/idevice/0.1.68/src/idevice/lib.rs.html
//!   `Idevice::start_session`, `IdeviceService::{service_name,from_stream}`.
//!
//! The VPN must forward *both* 62078 and dynamically allocated service ports
//! to the same device. This code neither creates a VPN nor pairs a new host.
//! "legacy_lockdown" means pre-RSD transport, NOT the crate's `legacy` TLS
//! flag, which means iOS < 5. iOS 16 uses ordinary TLS 1.2 here.
//!
//! Security limitation of the pinned crate: sni.rs disables server certificate
//! and handshake signature verification. Preflight below validates local client
//! credentials, not the VPN peer's identity. Use only a trusted local mapping;
//! do not expose this transport on an untrusted network.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use idevice::lockdown::LockdownClient;
use idevice::pairing_file::PairingFile;
use idevice::provider::{IdeviceProvider, TcpProvider};
use idevice::{Idevice, IdeviceError, IdeviceService};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use tokio::io::AsyncReadExt;

use crate::{CONNECT_TIMEOUT, Failure, HANDSHAKE_TIMEOUT, Request, failure};
use crate::legacy_transport::{self, BoundRoute};
use crate::legacy_heartbeat::LegacyHeartbeat;

const MAX_PAIRING_BYTES: usize = 64 * 1024;

/// TcpProvider derives Debug and exposes PairingFile's private keys. Never
/// delegate Debug to it, even when an upstream trait requires Debug.
struct RedactedProvider {
    inner: TcpProvider,
    route: Option<BoundRoute>,
    diagnostics: Arc<Mutex<Vec<String>>>,
}

impl RedactedProvider {
    fn diagnostics(&self) -> Vec<String> {
        self.diagnostics.lock().map(|v| v.clone()).unwrap_or_default()
    }

    fn annotate(&self, mut error: Failure) -> Failure {
        error.diagnostics.extend(self.diagnostics());
        error
    }
}

impl fmt::Debug for RedactedProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyProvider { credentials: [REDACTED] }")
    }
}

impl IdeviceProvider for RedactedProvider {
    fn connect(&self, port: u16)
        -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>>
    {
        let ip = self.inner.addr;
        let label = self.inner.label.clone();
        let route = self.route.clone();
        let diagnostics = self.diagnostics.clone();
        Box::pin(async move {
            let (stream, diagnostic) = legacy_transport::recorded_connect(ip, port, route.as_ref()).await;
            if let Ok(mut entries) = diagnostics.lock() { entries.push(diagnostic); }
            Ok(Idevice::new(Box::new(stream?), label))
        })
    }

    fn label(&self) -> &str { self.inner.label() }

    fn get_pairing_file(&self)
        -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>>
    {
        self.inner.get_pairing_file()
    }
}

/// Do not include upstream Debug/Display: errors can contain a raw peer plist
/// or user-provided bytes. Keep a useful category, not a secret-bearing body.
pub(crate) fn safe_error(stage: &'static str, error: IdeviceError) -> Failure {
    if let IdeviceError::Socket(error) = &error {
        return failure(stage, crate::io_diagnostics::io_detail(error));
    }
    if let IdeviceError::Rustls(_) = &error {
        return failure(stage, format!("TLS session failed; {}", crate::io_diagnostics::idevice_detail(&error)));
    }
    let message = match error {
        IdeviceError::InvalidHostID => "pairing record rejected; import a trusted record for this device",
        IdeviceError::DeviceLocked => "device is locked; unlock it and retry",
        IdeviceError::SessionInactive => "lockdown session is inactive",
        IdeviceError::ServiceNotFound => "required device service is unavailable",
        IdeviceError::Socket(_) => "device connection failed; check VPN and service-port forwarding",
        IdeviceError::Timeout => "timed out",
        IdeviceError::Rustls(_) | IdeviceError::TlsBuilderFailed(_) | IdeviceError::PemParseFailed(_) =>
            "TLS session failed; check the pairing record and device TLS support",
        _ => "device request failed (details redacted)",
    };
    failure(stage, message)
}

/// Pure, offline parsing. No paths, network, pairing databases or logging of
/// plist values. Requiring expected field types before from_value also avoids
/// serde diagnostics containing arbitrary malformed field contents.
pub(crate) fn parse_pairing(bytes: &[u8]) -> Result<PairingFile, Failure> {
    if bytes.is_empty() || bytes.len() > MAX_PAIRING_BYTES {
        return Err(failure("pairing_file", "empty or oversized legacy pairing record"));
    }
    let value: plist::Value = plist::from_bytes(bytes)
        .map_err(|_| failure("pairing_file", "legacy pairing record is not a valid plist"))?;
    let dictionary = value.as_dictionary()
        .ok_or_else(|| failure("pairing_file", "legacy pairing record must be a plist dictionary"))?;
    // Match Swift's format classifier: never accept a record carrying keys
    // from both transports, even if all legacy credentials are otherwise valid.
    if ["public_key", "private_key", "identifier"].iter().any(|key| dictionary.contains_key(*key)) {
        return Err(failure("pairing_file", "mixed remote and legacy pairing record"));
    }
    for field in ["HostID", "SystemBUID"] {
        if !dictionary.get(field).and_then(plist::Value::as_string)
            .is_some_and(|s| !s.trim().is_empty())
        {
            return Err(failure("pairing_file", format!("missing or invalid {field} in legacy record")));
        }
    }
    for field in ["DeviceCertificate", "HostCertificate", "RootCertificate", "HostPrivateKey", "RootPrivateKey"] {
        if !dictionary.get(field).and_then(plist::Value::as_data).is_some_and(|d| !d.is_empty()) {
            return Err(failure("pairing_file", format!("missing or invalid {field} in legacy record")));
        }
    }
    // RawPairingFile requires this String, but the connection never uses it.
    if dictionary.get("WiFiMACAddress").and_then(plist::Value::as_string).is_none() {
        return Err(failure("pairing_file", "missing or invalid WiFiMACAddress in legacy record"));
    }
    if dictionary.get("EscrowBag").is_some_and(|v| v.as_data().is_none())
        || dictionary.get("UDID").is_some_and(|v|
            !v.as_string().is_some_and(|s| !s.trim().is_empty()))
    {
        return Err(failure("pairing_file", "invalid optional field in legacy record"));
    }
    let pairing = PairingFile::from_value(&value)
        .map_err(|_| failure("pairing_file", "invalid legacy pairing certificates"))?;
    preflight_tls(&pairing)?;
    Ok(pairing)
}

/// idevice 0.1.68 sni.rs calls with_client_auth_cert(...).unwrap(). Validate
/// the same inputs first with a fallible builder so a mismatched key does not
/// abort the release app. Select the same process provider idevice will use.
fn preflight_tls(pairing: &PairingFile) -> Result<(), Failure> {
    let invalid = || failure("pairing_file", "invalid or mismatched legacy TLS credentials");
    let provider = rustls::crypto::CryptoProvider::get_default().cloned()
        .unwrap_or_else(|| Arc::new(rustls_rustcrypto::provider()));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pairing.root_certificate.clone()).map_err(|_| invalid())?;
    // Parse the device certificate as X.509 too (PairingFile only decodes PEM).
    let mut device = rustls::RootCertStore::empty();
    device.add(pairing.device_certificate.clone()).map_err(|_| invalid())?;
    let key = PrivateKeyDer::from_pem_slice(&pairing.host_private_key).map_err(|_| invalid())?;
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions().map_err(|_| invalid())?
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![pairing.host_certificate.clone()], key)
        .map_err(|_| invalid())?;
    Ok(())
}

fn verify_identity(expected: &str, observed: &plist::Value) -> Result<(), Failure> {
    if !expected.trim().is_empty() && observed.as_string()
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
    {
        Ok(())
    } else {
        // Neither the imported nor observed identifier belongs in an error.
        Err(failure("device_identity", "VPN target does not match the imported pairing record"))
    }
}

pub(crate) struct LegacySession {
    // Drop heartbeat before the session/provider on cancellation or failure.
    heartbeat: Option<LegacyHeartbeat>,
    provider: RedactedProvider,
    lockdown: LockdownClient,
    /// Only means SSL3/TLS1 for iOS < 5. Not the transport selector.
    old_tls: bool,
}

impl LegacySession {
    pub(crate) async fn connect(request: &Request, ip: IpAddr) -> Result<Self, Failure> {
        if request.port != LockdownClient::LOCKDOWND_PORT {
            return Err(failure("request", "legacy_lockdown requires port 62078"));
        }
        // Only the explicitly supplied imported record is opened. Never search
        // lockdown databases, generate keys, pair, unpair or rewrite the file.
        let file = tokio::fs::File::open(&request.pairing_file).await
            .map_err(|_| failure("pairing_file", "cannot open imported legacy pairing record"))?;
        if !file.metadata().await
            .map_err(|_| failure("pairing_file", "cannot inspect imported legacy pairing record"))?
            .is_file()
        {
            return Err(failure("pairing_file", "legacy pairing record must be a regular file"));
        }
        let mut bytes = Vec::new();
        file.take((MAX_PAIRING_BYTES + 1) as u64).read_to_end(&mut bytes).await
            .map_err(|_| failure("pairing_file", "cannot read imported legacy pairing record"))?;
        let pairing_file = parse_pairing(&bytes)?;
        let (route, stream, diagnostics) = legacy_transport::open_lockdown(ip, request.port).await?;
        let provider = RedactedProvider { inner: TcpProvider {
            addr: ip,
            scope_id: None,
            pairing_file,
            label: "iPadn".into(),
        }, route, diagnostics: Arc::new(Mutex::new(diagnostics)) };
        // Reuse the selected bound socket; all subsequent service sockets use
        // the same provider and fail if that interface disappears.
        let mut lockdown = LockdownClient::new(Idevice::new(Box::new(stream), "iPadn"));
        // StartSession authenticates an EXISTING record. No Pair/ValidatePair
        // fallback: a rejected HostID is an actionable failure, not re-pairing.
        let old_tls = tokio::time::timeout(HANDSHAKE_TIMEOUT,
            lockdown.start_session(&provider.inner.pairing_file))
            .await.map_err(|_| provider.annotate(failure("lockdown_session", "timed out")))?
            .map_err(|e| provider.annotate(safe_error("lockdown_session", e)))?;
        if let Some(expected) = provider.inner.pairing_file.udid.as_deref() {
            // A protocol query within the caller-requested connection, not an
            // independent read from system identity or pairing databases.
            let checked = async {
                let observed = tokio::time::timeout(HANDSHAKE_TIMEOUT,
                    lockdown.get_value(Some("UniqueDeviceID"), None)).await
                    .map_err(|_| failure("device_identity", "timed out"))?
                    .map_err(|e| safe_error("device_identity", e))?;
                verify_identity(expected, &observed)
            }.await;
            if let Err(error) = checked {
                let _ = tokio::time::timeout(CONNECT_TIMEOUT, lockdown.stop_session()).await;
                return Err(provider.annotate(error));
            }
        }
        // UDID is optional in the pinned format. Its absence is not a reason
        // to read another identity source or silently create a pairing record.
        let mut session = Self { heartbeat: None, provider, lockdown, old_tls };
        let startup = session.start_heartbeat().await;
        match startup {
            Ok(heartbeat) => { session.heartbeat = Some(heartbeat); Ok(session) }
            Err(error) => {
                session.close().await;
                Err(session.provider.annotate(error))
            }
        }
    }

    async fn start_heartbeat(&mut self) -> Result<LegacyHeartbeat, Failure> {
        // This factory uses the original authenticated lockdown and provider.
        // HeartbeatClient::connect would authenticate another lockdown session.
        let client = self.open_service::<idevice::heartbeat::HeartbeatClient>().await
            .map_err(|error| {
                self.record_query(format!("phase=heartbeat result=failed code={}", error.stage));
                failure("heartbeat_setup", "cannot start legacy heartbeat service")
            })?;
        LegacyHeartbeat::start(client, self.provider.diagnostics.clone()).await
    }

    pub(crate) fn diagnostics(&self) -> Vec<String> { self.provider.diagnostics() }

    pub(crate) fn record_query(&self, entry: String) {
        if let Ok(mut entries) = self.provider.diagnostics.lock() { entries.push(entry); }
    }


    pub(crate) async fn guard<T>(&self, work: impl Future<Output = Result<T, Failure>>)
        -> Result<T, Failure>
    {
        self.heartbeat.as_ref().ok_or_else(|| failure("heartbeat_lost", "legacy heartbeat unavailable"))?
            .guard(work).await
    }

    pub(crate) async fn service<T: IdeviceService>(&mut self) -> Result<T, Failure> {
        self.heartbeat.as_ref().ok_or_else(|| failure("heartbeat_lost", "legacy heartbeat unavailable"))?.check()?;
        let service = self.open_service::<T>().await?;
        self.heartbeat.as_ref().ok_or_else(|| failure("heartbeat_lost", "legacy heartbeat unavailable"))?.check()?;
        Ok(service)
    }

    async fn open_service<T: IdeviceService>(&mut self) -> Result<T, Failure> {
        // Log a fixed local label, never an arbitrary service/peer value.
        let name = match T::service_name().as_ref() {
            "com.apple.mobile.installation_proxy" => "installation_proxy",
            "com.apple.afc" => "afc",
            "com.apple.mobile.heartbeat" => "heartbeat",
            _ => "other",
        };
        self.record_query(format!("phase=service name={name} step=start"));
        let (port, ssl) = tokio::time::timeout(HANDSHAKE_TIMEOUT,
            self.lockdown.start_service(T::service_name().into_owned()))
            .await.map_err(|_| failure("lockdown_service", "timed out"))?
            .map_err(|e| safe_error("lockdown_service", e))?;
        if port == 0 {
            return Err(failure("lockdown_service", "device returned an invalid service port"));
        }
        self.record_query(format!("phase=service name={name} step=selected port={port} ssl={ssl}"));
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, self.provider.connect(port))
            .await.map_err(|_| failure("service_connect", "timed out"))?
            .map_err(|e| safe_error("service_connect", e))?;
        if ssl {
            self.record_query(format!("phase=service name={name} step=tls_start"));
            tokio::time::timeout(HANDSHAKE_TIMEOUT,
                stream.start_session(&self.provider.inner.pairing_file, self.old_tls))
                .await.map_err(|_| {
                    self.record_query(format!("phase=service name={name} step=tls_failed io=timed_out errno=0 tls=none"));
                    failure("service_tls", "timed out")
                })?
                .map_err(|e| {
                    self.record_query(format!("phase=service name={name} step=tls_failed {}", crate::io_diagnostics::idevice_detail(&e)));
                    safe_error("service_tls", e)
                })?;
            self.record_query(format!("phase=service name={name} step=tls_ready"));
        } else {
            self.record_query(format!("phase=service name={name} step=tls_not_requested"));
        }
        tokio::time::timeout(HANDSHAKE_TIMEOUT,
            <T as IdeviceService>::from_stream(stream))
            .await.map_err(|_| failure("service_connect", "timed out"))?
            .map_err(|e| safe_error("service_connect", e))
    }

    pub(crate) async fn close(&mut self) {
        // Cleanup must never turn a completed install into a retryable failure.
        let _ = tokio::time::timeout(CONNECT_TIMEOUT, self.lockdown.stop_session()).await;
        if let Some(heartbeat) = self.heartbeat.take() { heartbeat.stop().await; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(dictionary: plist::Dictionary) -> Vec<u8> {
        let mut bytes = Vec::new();
        plist::Value::Dictionary(dictionary).to_writer_xml(&mut bytes).unwrap();
        bytes
    }

    fn invalid_record() -> plist::Dictionary {
        let mut d = plist::Dictionary::new();
        for key in ["HostID", "SystemBUID", "WiFiMACAddress"] {
            d.insert(key.into(), "test-identity".into());
        }
        for key in ["DeviceCertificate", "HostCertificate", "RootCertificate", "HostPrivateKey", "RootPrivateKey"] {
            d.insert(key.into(), plist::Value::Data(b"not-a-certificate-or-key".to_vec()));
        }
        d
    }

    #[test]
    fn rejects_remote_json_and_non_dictionary_plist() {
        for bytes in [br#"{"private_key":"SENSITIVE"}"#.as_slice(), b"not plist".as_slice(),
            b"<?xml version=\"1.0\"?><plist version=\"1.0\"><string>SENSITIVE</string></plist>".as_slice()]
        {
            let e = parse_pairing(bytes).err().expect("must reject");
            assert_eq!(e.stage, "pairing_file");
            assert!(!e.message.contains("SENSITIVE"));
        }
    }

    #[test]
    fn rejects_missing_wrong_empty_and_invalid_credentials() {
        let mut missing = invalid_record();
        missing.remove("HostID");
        let mut wrong = invalid_record();
        wrong.insert("HostPrivateKey".into(), "SENSITIVE".into());
        let mut empty = invalid_record();
        empty.insert("SystemBUID".into(), " ".into());
        let mut optional = invalid_record();
        optional.insert("EscrowBag".into(), "SENSITIVE".into());
        for record in [missing, wrong, empty, optional, invalid_record()] {
            let e = parse_pairing(&encoded(record)).err().expect("must reject");
            assert_eq!(e.stage, "pairing_file");
            assert!(!e.message.contains("SENSITIVE"));
            assert!(!e.message.contains("not-a-certificate-or-key"));
        }
        assert!(parse_pairing(&[]).is_err());
        assert!(parse_pairing(&vec![0; MAX_PAIRING_BYTES + 1]).is_err());
    }

    #[test]
    fn rejects_mixed_transport_keys_before_certificate_parsing() {
        for key in ["public_key", "private_key", "identifier"] {
            let mut record = invalid_record();
            record.insert(key.into(), "SENSITIVE".into());
            let error = parse_pairing(&encoded(record)).err().expect("must reject mixed record");
            assert_eq!(error.stage, "pairing_file");
            assert_eq!(error.message, "mixed remote and legacy pairing record");
        }
    }

    #[test]
    fn binary_plist_reaches_certificate_validation() {
        let mut bytes = Vec::new();
        plist::Value::Dictionary(invalid_record()).to_writer_binary(&mut bytes).unwrap();
        assert!(bytes.starts_with(b"bplist"));
        let e = parse_pairing(&bytes).err().expect("invalid certificates");
        assert_eq!(e.stage, "pairing_file");
        assert!(!e.message.contains("not a valid plist"));
    }

    #[test]
    fn identity_match_is_case_insensitive_and_failures_are_redacted() {
        assert!(verify_identity("ABC-123", &plist::Value::String("abc-123".into())).is_ok());
        for observed in [plist::Value::String("OTHER_SENSITIVE_DEVICE".into()),
            plist::Value::Data(b"SENSITIVE_BYTES".to_vec())]
        {
            let error = verify_identity("SENSITIVE_EXPECTED_DEVICE", &observed)
                .err().expect("must reject mismatched or invalid identity");
            assert_eq!(error.stage, "device_identity");
            assert!(!error.message.contains("SENSITIVE"));
        }
        assert!(verify_identity("", &plist::Value::String(String::new())).is_err());
    }

    #[test]
    fn provider_debug_never_exposes_pairing_credentials() {
        // Deliberately synthetic, not a real record; no certificates are used.
        let provider = RedactedProvider { inner: TcpProvider {
            addr: "10.7.0.1".parse().unwrap(),
            scope_id: None,
            label: "SENSITIVE_LABEL".into(),
            pairing_file: PairingFile {
                device_certificate: Vec::new().into(),
                host_certificate: Vec::new().into(),
                root_certificate: Vec::new().into(),
                host_private_key: b"SENSITIVE_HOST_KEY".to_vec(),
                root_private_key: b"SENSITIVE_ROOT_KEY".to_vec(),
                system_buid: "SENSITIVE_BUID".into(),
                host_id: "SENSITIVE_HOST_ID".into(),
                escrow_bag: Some(b"SENSITIVE_ESCROW".to_vec()),
                wifi_mac_address: "SENSITIVE_MAC".into(),
                udid: Some("SENSITIVE_UDID".into()),
            },
        }, route: None, diagnostics: Arc::new(Mutex::new(Vec::new())) };
        let debug = format!("{provider:?}");
        assert!(!debug.contains("SENSITIVE"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn errors_never_echo_peer_data_or_private_keys() {
        for error in [
            IdeviceError::UnexpectedResponse("HostPrivateKey=SENSITIVE".into()),
            IdeviceError::UnknownErrorType("<plist>SENSITIVE</plist>".into()),
            IdeviceError::InternalError("SENSITIVE".into()),
            IdeviceError::Socket(std::io::Error::other("SENSITIVE")),
            IdeviceError::InvalidHostID,
        ] {
            let e = safe_error("lockdown_session", error);
            assert_eq!(e.stage, "lockdown_session");
            assert!(!e.message.contains("SENSITIVE"));
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn actual_provider_preserves_route_for_each_dynamic_port() {
        let pairing_file = PairingFile {
            device_certificate: Vec::new().into(), host_certificate: Vec::new().into(),
            root_certificate: Vec::new().into(), host_private_key: Vec::new(), root_private_key: Vec::new(),
            system_buid: String::new(), host_id: String::new(), escrow_bag: None,
            wifi_mac_address: String::new(), udid: None,
        };
        let route = legacy_transport::loopback_test_route();
        let provider = RedactedProvider {
            inner: TcpProvider { addr: "127.0.0.1".parse().unwrap(), scope_id: None, pairing_file, label: "test".into() },
            route: Some(route.clone()), diagnostics: Arc::new(Mutex::new(Vec::new())),
        };
        for _ in 0..2 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut device = provider.connect(port).await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            device.send_raw(b"local-transport-test").await.unwrap();
            let mut data = [0; 20];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"local-transport-test");
            let entry = provider.diagnostics().pop().unwrap();
            assert!(entry.contains(&route.description()));
            assert!(entry.contains(&format!("port={port}")));
            assert!(entry.contains("tcp=connected"));
        }
        assert_eq!(provider.diagnostics().len(), 2);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod heartbeat_tests;
