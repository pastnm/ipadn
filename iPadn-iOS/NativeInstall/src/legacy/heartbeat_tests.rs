//! Simulated device services over actual route-bound localhost TCP + mTLS.
//! Requires first and later Polo before answering the installation query.
use super::*;
use crate::test_wire::{message, Wire};
use rustls::pki_types::CertificateDer;
use tokio::{net::TcpListener, sync::oneshot, time::{timeout, Duration}};

const ROOT: &[u8] = include_bytes!("../../tests/fixtures/root.pem");
const HOST: &[u8] = include_bytes!("../../tests/fixtures/host.pem");
const HOST_KEY: &[u8] = include_bytes!("../../tests/fixtures/host.key");
const DEVICE: &[u8] = include_bytes!("../../tests/fixtures/device.pem");
const DEVICE_KEY: &[u8] = include_bytes!("../../tests/fixtures/device.key");
fn cert(bytes: &[u8]) -> CertificateDer<'static> { CertificateDer::from_pem_slice(bytes).unwrap() }
fn pairing() -> PairingFile {
    PairingFile { device_certificate: cert(DEVICE), host_certificate: cert(HOST),
        root_certificate: cert(ROOT), host_private_key: HOST_KEY.to_vec(), root_private_key: Vec::new(),
        host_id: "TEST_PUBLIC_HOST".into(), system_buid: "TEST_PUBLIC_BUID".into(),
        wifi_mac_address: String::new(), escrow_bag: None, udid: None }
}
fn acceptor(version: &'static rustls::SupportedProtocolVersion) -> tokio_rustls::TlsAcceptor {
    let crypto = Arc::new(rustls_rustcrypto::provider());
    let mut roots = rustls::RootCertStore::empty(); roots.add(cert(ROOT)).unwrap();
    let verify = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crypto.clone()).build().unwrap();
    let config = rustls::ServerConfig::builder_with_provider(crypto).with_protocol_versions(&[version]).unwrap()
        .with_client_cert_verifier(verify)
        .with_single_cert(vec![cert(DEVICE)], PrivateKeyDer::from_pem_slice(DEVICE_KEY).unwrap()).unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}
async fn accept(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor) -> Idevice {
    let (tcp, _) = listener.accept().await.unwrap();
    let tls = acceptor.accept(tcp).await.unwrap();
    assert_eq!(tls.get_ref().1.peer_certificates().unwrap()[0], cert(HOST));
    Idevice::new(Box::new(tls), "test-device")
}
async fn polo(device: &mut Idevice) {
    device.send_message(message!({"Command": "Marco", "Interval": 15})).await.unwrap();
    assert_eq!(device.read_message().await.unwrap()["Command"].as_string(), Some("Polo"));
}

// The duplex stream represents the caller's already-authenticated lockdown;
// all StartService/StopSession commands must remain on this exact stream.
fn session() -> (LegacySession, Idevice) {
    let (client, peer) = tokio::io::duplex(4096);
    (LegacySession { heartbeat: None, old_tls: false,
        provider: RedactedProvider { inner: TcpProvider { addr: "127.0.0.1".parse().unwrap(),
            scope_id: None, pairing_file: pairing(), label: "test".into() },
            route: Some(legacy_transport::loopback_test_route()), diagnostics: Arc::new(Mutex::new(Vec::new())) },
        lockdown: LockdownClient::new(Idevice::new(Box::new(client), "test")) },
        Idevice::new(Box::new(peer), "test-lockdown"))
}

#[derive(Clone, Copy)]
enum Scenario { Success, ServiceFailure, Lost }

async fn lifecycle(version: &'static rustls::SupportedProtocolVersion, scenario: Scenario) {
    let heartbeat = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let installation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let heartbeat_port = heartbeat.local_addr().unwrap().port();
    let target_port = if matches!(scenario, Scenario::ServiceFailure) { 0 } else { installation.local_addr().unwrap().port() };
    let (mut session, mut lockdown) = session();
    let (first_tx, first_rx) = oneshot::channel();
    let (query_tx, query_rx) = oneshot::channel();
    let (second_tx, second_rx) = oneshot::channel();
    let heartbeat_job = tokio::spawn({ let acceptor = acceptor(version); async move {
        let mut peer = accept(heartbeat, acceptor).await;
        polo(&mut peer).await;
        first_tx.send(()).unwrap();
        if !matches!(scenario, Scenario::ServiceFailure) {
            query_rx.await.unwrap();
            if matches!(scenario, Scenario::Lost) { return; }
            polo(&mut peer).await;
            second_tx.send(()).unwrap();
        }
        // Task/socket ownership must end on successful close or setup failure.
        let end = peer.read_any(1).await;
        assert!(matches!(end, Ok(ref bytes) if bytes.is_empty()) || end.is_err());
    }});
    let lockdown_job = tokio::spawn(async move {
        let req = lockdown.read_message().await.unwrap();
        assert_eq!(req["Request"].as_string(), Some("StartService"));
        assert_eq!(req["Service"].as_string(), Some("com.apple.mobile.heartbeat"));
        lockdown.send_message(message!({"Port": heartbeat_port, "EnableServiceSSL": true})).await.unwrap();
        let req = lockdown.read_message().await.unwrap();
        first_rx.await.unwrap();
        assert_eq!(req["Request"].as_string(), Some("StartService"));
        assert_eq!(req["Service"].as_string(), Some("com.apple.mobile.installation_proxy"));
        lockdown.send_message(message!({"Port": target_port, "EnableServiceSSL": true})).await.unwrap();
        let next = lockdown.read_message().await;
        if matches!(scenario, Scenario::ServiceFailure) { assert!(next.is_err()); }
        else {
            assert_eq!(next.unwrap()["Request"].as_string(), Some("StopSession"), "no extra StartService or StartSession");
            lockdown.send_message(message!({"Request": "StopSession"})).await.unwrap();
        }
    });
    let query_job = if !matches!(scenario, Scenario::ServiceFailure) { Some(tokio::spawn({
        let acceptor = acceptor(version); async move {
            let mut peer = accept(installation, acceptor).await;
            assert_eq!(peer.read_message().await.unwrap()["Command"].as_string(), Some("Lookup"));
            query_tx.send(()).unwrap();
            if matches!(scenario, Scenario::Lost) {
                assert!(peer.read_message().await.is_err(), "heartbeat loss cancels the blocked query");
            } else {
                second_rx.await.unwrap();
                peer.send_message(message!({"Status": "Complete", "LookupResult": plist::Dictionary::new()})).await.unwrap();
            }
        }
    })) } else { None };
    session.heartbeat = Some(session.start_heartbeat().await.unwrap_or_else(|e| panic!("{} {}", e.stage, e.message)));
    if matches!(scenario, Scenario::ServiceFailure) {
        assert_eq!(session.service::<idevice::installation_proxy::InstallationProxyClient>().await.err().unwrap().stage, "lockdown_service");
        drop(session); // No explicit close: failed initialization must abort too.
    } else {
        let mut native = crate::Session::Legacy(session);
        let outcome = crate::checked_lookup(&mut native, "test.app").await;
        if matches!(scenario, Scenario::Lost) { assert_eq!(outcome.err().unwrap().stage, "heartbeat_lost"); }
        else { assert_eq!(outcome.unwrap_or_else(|e| panic!("{} {}", e.stage, e.message))["installed"], serde_json::json!(false)); }
        native.close().await;
        let crate::Session::Legacy(session) = native else { unreachable!() };
        let logs = session.diagnostics();
        let ready = logs.iter().position(|s| s == "phase=heartbeat step=ready polo=1").unwrap();
        let service = logs.iter().position(|s| s == "phase=service name=installation_proxy step=start").unwrap();
        assert!(ready < service);
        assert_eq!(logs.iter().filter(|s| s.contains("tcp=connected")).count(), 2);
        assert!(logs.iter().filter(|s| s.contains("tcp=connected")).all(|s| s.contains("route=lo0#")));
        assert!(!logs.join("\n").contains("TEST_PUBLIC_HOST"));
    }
    lockdown_job.await.unwrap(); heartbeat_job.await.unwrap();
    if let Some(job) = query_job { job.await.unwrap(); }
}

#[tokio::test]
async fn same_session_bound_mtls_services_wait_for_first_and_later_polo() {
    timeout(Duration::from_secs(20), async {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] { lifecycle(version, Scenario::Success).await; }
    }).await.unwrap();
}
#[tokio::test]
async fn failed_target_service_setup_drops_heartbeat_socket() {
    timeout(Duration::from_secs(10), lifecycle(&rustls::version::TLS12, Scenario::ServiceFailure)).await.unwrap();
}
#[tokio::test]
async fn lost_heartbeat_aborts_query_without_compatibility_retry() {
    timeout(Duration::from_secs(10), lifecycle(&rustls::version::TLS12, Scenario::Lost)).await.unwrap();
}
