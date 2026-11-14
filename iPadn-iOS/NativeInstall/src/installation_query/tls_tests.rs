//! Real localhost mTLS, using the existing B29 idevice client and RustCrypto.
//! The public synthetic identities are never compiled into the device library.
use super::*;
use super::tests::{app, detailed_request, read_request, response, write};
use idevice::{Idevice, pairing_file::PairingFile};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::cell::RefCell;
use std::sync::Arc;

const ROOT: &[u8] = include_bytes!("../../tests/fixtures/root.pem");
const HOST: &[u8] = include_bytes!("../../tests/fixtures/host.pem");
const HOST_KEY: &[u8] = include_bytes!("../../tests/fixtures/host.key");
const DEVICE: &[u8] = include_bytes!("../../tests/fixtures/device.pem");
const DEVICE_KEY: &[u8] = include_bytes!("../../tests/fixtures/device.key");

fn certificate(pem: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem).unwrap()
}
fn pairing() -> PairingFile {
    PairingFile {
        device_certificate: certificate(DEVICE), host_certificate: certificate(HOST),
        root_certificate: certificate(ROOT), host_private_key: HOST_KEY.to_vec(),
        root_private_key: Vec::new(), host_id: "TEST_PUBLIC_HOST".into(),
        system_buid: "TEST_PUBLIC_BUID".into(), wifi_mac_address: String::new(),
        escrow_bag: None, udid: None,
    }
}

struct TlsService {
    version: &'static rustls::SupportedProtocolVersion,
    close_first: bool,
    opened: usize,
    jobs: Vec<tokio::task::JoinHandle<()>>,
    logs: RefCell<Vec<String>>,
}

impl Service for TlsService {
    async fn open(&mut self) -> Result<InstallationProxyClient, Failure> {
        self.opened += 1;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let provider = Arc::new(rustls_rustcrypto::provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate(ROOT)).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build().unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[self.version]).unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![certificate(DEVICE)], PrivateKeyDer::from_pem_slice(DEVICE_KEY).unwrap()).unwrap();
        let close = self.close_first && self.opened == 1;
        let expected_attributes = self.opened == 1;
        let expected_version = self.version.version;
        self.jobs.push(tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(server).await.unwrap();
            assert_eq!(stream.get_ref().1.protocol_version(), Some(expected_version));
            assert_eq!(stream.get_ref().1.peer_certificates().unwrap()[0], certificate(HOST));
            let request = read_request(&mut stream).await;
            let options = request["ClientOptions"].as_dictionary().unwrap();
            assert_eq!(options.contains_key("ReturnAttributes"), expected_attributes);
            assert_eq!(options["ApplicationType"].as_string(), Some("Any"));
            if close {
                stream.shutdown().await.unwrap();
            } else {
                write(&mut stream, response(Some("Complete"), Some(app("test.app")))).await;
                stream.flush().await.unwrap();
            }
        }));
        let mut client = Idevice::new(Box::new(client), "test");
        client.start_session(&pairing(), false).await.map_err(io_failure)?;
        Ok(InstallationProxyClient::new(client))
    }
    fn record(&self, entry: String) { self.logs.borrow_mut().push(entry); }
    fn allows_legacy_retry(&self) -> bool { true }
}

#[tokio::test]
async fn b29_rustcrypto_tls12_and_tls13_query_and_reconnect_after_clean_tls_eof() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            for close_first in [false, true] {
                let mut service = TlsService { version, close_first, opened: 0,
                    jobs: Vec::new(), logs: RefCell::new(Vec::new()) };
                let result = run_with_retry(&mut service, &detailed_request()).await
                    .unwrap_or_else(|e| panic!("{} {}", e.stage, e.message));
                assert!(result["test.app"].as_dictionary().unwrap().contains_key("iTunesMetadata"));
                assert_eq!(service.opened, if close_first { 2 } else { 1 });
                for job in service.jobs { job.await.unwrap(); }
            }
        }
    }).await.expect("localhost TLS exchange must finish");
}
