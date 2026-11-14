use super::*;
use idevice::Idevice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) fn response(status: Option<&str>, result: Option<plist::Dictionary>) -> plist::Dictionary {
    let mut d = plist::Dictionary::new();
    if let Some(s) = status { d.insert("Status".into(), s.into()); }
    if let Some(r) = result { d.insert("LookupResult".into(), r.into()); }
    d
}
pub(super) fn app(id: &str) -> plist::Dictionary {
    let mut record = plist::Dictionary::new();
    record.insert("CFBundleIdentifier".into(), id.into());
    record.insert("iTunesMetadata".into(), plist::Value::Data(b"SENSITIVE_PURCHASE_RECORD".to_vec()));
    let mut result = plist::Dictionary::new(); result.insert(id.into(), record.into()); result
}
pub(super) async fn write(stream: &mut (impl tokio::io::AsyncWrite + Unpin), d: plist::Dictionary) {
    let mut body=Vec::new(); plist::to_writer_xml(&mut body,&d).unwrap();
    stream.write_u32(body.len() as u32).await.unwrap();
    // Deliberate fragmentation across reads, not one synthetic whole buffer.
    for part in body.chunks(7) { stream.write_all(part).await.unwrap(); tokio::task::yield_now().await; }
}
pub(super) async fn read_request(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> plist::Dictionary {
    let length=stream.read_u32().await.unwrap();
    let mut body=vec![0;length as usize]; stream.read_exact(&mut body).await.unwrap();
    let request: plist::Dictionary=plist::from_bytes(&body).unwrap();
    assert_eq!(request["Command"].as_string(),Some("Lookup"));
    request
}
fn request() -> plist::Value {
    let mut d=plist::Dictionary::new(); d.insert("Command".into(),"Lookup".into()); d.into()
}
async fn query(responses: Vec<plist::Dictionary>) -> (Result<plist::Dictionary,Failure>,Vec<String>) {
    let (client,mut peer)=tokio::io::duplex(4096);
    let peer=tokio::spawn(async move {
        read_request(&mut peer).await;
        for d in responses { write(&mut peer,d).await; }
    });
    let mut client=InstallationProxyClient::new(Idevice::new(Box::new(client),"test"));
    let mut logs=Vec::new();
    let result=run(&mut client,&request(),|line| logs.push(line)).await;
    peer.await.unwrap(); (result,logs)
}

#[tokio::test]
async fn status_before_result_is_not_mistaken_for_missing_inventory() {
    let (result,logs)=query(vec![response(Some("LookingUp"),None),
        response(Some("Complete"),Some(app("SENSITIVE_APP_ID")))]).await;
    assert!(result.unwrap_or_else(|e|panic!("{}",e.message)).contains_key("SENSITIVE_APP_ID"));
    assert!(logs.iter().any(|l|l.contains("frame=2 status=complete")));
    assert!(!logs.join(" ").contains("SENSITIVE"));
}

#[tokio::test]
async fn partial_results_are_collected_until_completion() {
    let (result,_)=query(vec![response(Some("LookingUp"),Some(app("first.app"))),
        response(Some("LookingUp"),Some(app("second.app"))),response(Some("Complete"),None)]).await;
    assert_eq!(result.unwrap_or_else(|e|panic!("{}",e.message)).len(),2);
}

#[tokio::test]
async fn existing_single_response_and_empty_inventory_remain_valid() {
    for status in [None,Some("Complete")] {
        for entries in [plist::Dictionary::new(),app("test.app")] {
            let count=entries.len(); let (result,_)=query(vec![response(status,Some(entries))]).await;
            assert_eq!(result.unwrap_or_else(|e|panic!("{}",e.message)).len(),count);
        }
    }
}

#[tokio::test]
async fn completed_without_result_is_an_error_and_not_not_installed() {
    let (result,logs)=query(vec![response(Some("Complete"),None)]).await;
    let e=result.err().expect("must reject");
    assert_eq!(e.message,"code=query_missing_result");
    assert!(logs.last().unwrap().contains("query_missing_result"));
}

#[tokio::test]
async fn device_error_after_partial_inventory_never_returns_success_or_private_text() {
    for (error,code) in [("PasswordProtected","query_device_locked"),
        ("LookupFailed","query_device_lookup_failed"),("SENSITIVE_ERROR","query_device_rejected")]
    {
        let mut d=response(Some("Complete"),None);
        d.insert("Error".into(),error.into());
        d.insert("ErrorDescription".into(),"SENSITIVE_DESCRIPTION".into());
        let (result,logs)=query(vec![response(Some("LookingUp"),Some(app("SENSITIVE_ID"))),d]).await;
        let e=result.err().expect("must fail"); assert_eq!(e.message,format!("code={code}"));
        assert!(!logs.join(" ").contains("SENSITIVE"));
    }
}

#[tokio::test]
async fn malformed_result_and_status_are_rejected() {
    for (field,code) in [("LookupResult","query_invalid_result"),("Status","query_invalid_status")] {
        let mut d=response(Some("Complete"),None);d.insert(field.into(),123u64.into());
        let (result,_)=query(vec![d]).await;
        assert_eq!(result.err().expect("must reject").message,format!("code={code}"));
    }
}

#[tokio::test]
async fn invalid_sizes_and_early_eof_are_classified() {
    for size in [0,MAX_REPLY+1,100] {
        let (client,mut peer)=tokio::io::duplex(4096);
        let task=tokio::spawn(async move {
            read_request(&mut peer).await;peer.write_u32(size).await.unwrap();
            if size==100 { peer.write_all(b"short").await.unwrap(); }
        });
        let mut client=InstallationProxyClient::new(Idevice::new(Box::new(client),"test"));
        let mut logs=Vec::new();
        let e=run(&mut client,&request(),|line|logs.push(line)).await.err().expect("must reject");
        assert!(e.message.contains(if size==100 { "query_socket" } else { "query_invalid_size" }));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn endless_progress_is_bounded_by_frame_limit() {
    let (result,_)=query((0..MAX_FRAMES).map(|_|response(Some("LookingUp"),None)).collect()).await;
    assert_eq!(result.err().expect("must reject").message,"code=query_frame_limit");
}

#[test]
fn socket_payload_is_redacted() {
    let e=io_failure(IdeviceError::Socket(std::io::Error::other("SENSITIVE")));
    assert!(e.message.contains("query_socket")); assert!(!e.message.contains("SENSITIVE"));
}

#[tokio::test]
async fn peer_close_before_or_during_first_header_is_an_eof_not_a_device_rejection() {
    for prefix in [vec![], vec![0, 0]] {
        let (client, mut peer) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            read_request(&mut peer).await;
            peer.write_all(&prefix).await.unwrap();
        });
        let mut client = InstallationProxyClient::new(Idevice::new(Box::new(client), "test"));
        let mut logs = Vec::new();
        let error = run(&mut client, &request(), |line| logs.push(line)).await.err().unwrap();
        task.await.unwrap();
        assert_eq!(error.message, "code=query_socket io=unexpected_eof errno=0 tls=none");
        assert_eq!(logs[1], "phase=app_query step=read_header frame=1");
        assert!(!logs.iter().any(|line| line.contains("step=read_body")));
    }
}

#[test]
fn wrapped_tls_alert_is_preserved_as_a_fixed_category() {
    let alert = rustls::Error::AlertReceived(rustls::AlertDescription::UnknownCA);
    let error = io_failure(IdeviceError::Socket(std::io::Error::new(std::io::ErrorKind::InvalidData, alert)));
    assert_eq!(error.message, "code=query_socket io=invalid_data errno=0 tls=alert_48");
    let error = io_failure(IdeviceError::Rustls(rustls::Error::General("SENSITIVE_TLS_TEXT".into())));
    assert_eq!(error.message, "code=query_tls io=none errno=0 tls=general_error");
}

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

enum Peer {
    Eof(Vec<u8>),
    Replies(Vec<plist::Dictionary>),
    BodyEof,
    OpenFailure,
}

struct FakeService {
    peers: VecDeque<Peer>,
    legacy: bool,
    opened: usize,
    logs: RefCell<Vec<String>>,
    requests: Arc<Mutex<Vec<plist::Dictionary>>>,
    jobs: Vec<tokio::task::JoinHandle<()>>,
}

impl FakeService {
    fn new(legacy: bool, peers: Vec<Peer>) -> Self {
        Self { peers: peers.into(), legacy, opened: 0, logs: RefCell::new(Vec::new()),
            requests: Arc::new(Mutex::new(Vec::new())), jobs: Vec::new() }
    }
    async fn finish(&mut self) {
        for job in self.jobs.drain(..) { job.await.unwrap(); }
    }
}

impl Service for FakeService {
    async fn open(&mut self) -> Result<InstallationProxyClient, Failure> {
        self.opened += 1;
        let action = self.peers.pop_front().expect("unexpected extra service connection");
        if matches!(action, Peer::OpenFailure) { return Err(failure("service_connect", "test connect failed")); }
        let (client, mut peer) = tokio::io::duplex(4096);
        let requests = self.requests.clone();
        self.jobs.push(tokio::spawn(async move {
            let request = read_request(&mut peer).await;
            requests.lock().unwrap().push(request);
            match action {
                Peer::Eof(prefix) => { peer.write_all(&prefix).await.unwrap(); }
                Peer::Replies(replies) => { for reply in replies { write(&mut peer, reply).await; } }
                Peer::BodyEof => { peer.write_u32(100).await.unwrap(); peer.write_all(b"partial").await.unwrap(); }
                Peer::OpenFailure => unreachable!(),
            }
        }));
        Ok(InstallationProxyClient::new(Idevice::new(Box::new(client), "test")))
    }
    fn record(&self, entry: String) { self.logs.borrow_mut().push(entry); }
    fn allows_legacy_retry(&self) -> bool { self.legacy }
}

pub(super) fn detailed_request() -> plist::Value {
    let mut options = plist::Dictionary::new();
    options.insert("ApplicationType".into(), "Any".into());
    options.insert("BundleIDs".into(), vec![plist::Value::from("SENSITIVE_TARGET_APP")].into());
    options.insert("ReturnAttributes".into(), vec![plist::Value::from("iTunesMetadata")].into());
    let mut message = request().into_dictionary().unwrap();
    message.insert("ClientOptions".into(), options.into());
    message.into()
}

#[tokio::test]
async fn initial_eof_reopens_once_and_preserves_target_filters_and_purchase_metadata() {
    let mut service = FakeService::new(true, vec![Peer::Eof(vec![]),
        Peer::Replies(vec![response(Some("Complete"), Some(app("SENSITIVE_TARGET_APP")))])]);
    let original = detailed_request();
    let result = run_with_retry(&mut service, &original).await.unwrap_or_else(|e| panic!("{}", e.message));
    service.finish().await;
    assert_eq!(service.opened, 2);
    assert_eq!(result["SENSITIVE_TARGET_APP"].as_dictionary().unwrap()["iTunesMetadata"].as_data(),
        Some(b"SENSITIVE_PURCHASE_RECORD".as_slice()));
    let requests = service.requests.lock().unwrap();
    assert_eq!(requests[0], *original.as_dictionary().unwrap());
    let expected = without_attributes(&original).unwrap();
    assert_eq!(requests[1], *expected.as_dictionary().unwrap());
    assert!(original.as_dictionary().unwrap()["ClientOptions"].as_dictionary().unwrap().contains_key("ReturnAttributes"));
    let logs = service.logs.borrow().join(" ");
    assert!(logs.contains("attempt=2 result=succeeded"));
    assert!(!logs.contains("SENSITIVE"));
}

#[tokio::test]
async fn repeated_eof_or_retry_connect_failure_stays_an_error_and_never_opens_a_third_service() {
    for second in [Peer::Eof(vec![]), Peer::OpenFailure] {
        let mut service = FakeService::new(true, vec![Peer::Eof(vec![]), second]);
        assert!(run_with_retry(&mut service, &detailed_request()).await.is_err());
        service.finish().await;
        assert_eq!(service.opened, 2);
    }
}

#[tokio::test]
async fn partial_header_body_later_eof_and_device_errors_never_retry_or_return_partial_inventory() {
    let mut denied = response(Some("Complete"), None);
    denied.insert("Error".into(), "NotEntitled".into());
    let cases = vec![Peer::Eof(vec![0, 0]), Peer::BodyEof,
        Peer::Replies(vec![response(Some("LookingUp"), Some(app("partial.app")))]),
        Peer::Replies(vec![response(Some("Complete"), None)]), Peer::Replies(vec![denied])];
    for action in cases {
        let mut service = FakeService::new(true, vec![action]);
        assert!(run_with_retry(&mut service, &detailed_request()).await.is_err());
        service.finish().await;
        assert_eq!(service.opened, 1);
        assert!(!service.logs.borrow().join(" ").contains("step=retry "));
    }
}

#[tokio::test]
async fn modern_transport_and_already_unrestricted_lookup_do_not_retry() {
    for (legacy, message) in [(false, detailed_request()), (true, request())] {
        let mut service = FakeService::new(legacy, vec![Peer::Eof(vec![])]);
        assert!(run_with_retry(&mut service, &message).await.is_err());
        service.finish().await;
        assert_eq!(service.opened, 1);
    }
    let mut install = detailed_request().into_dictionary().unwrap();
    install.insert("Command".into(), "Install".into());
    assert!(without_attributes(&install.into()).is_none());
}
