use super::*;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::timeout};

fn route(name: &str, index: u32, source: [u8; 4]) -> BoundRoute {
    BoundRoute { name: name.into(), index, address: source.into() }
}

#[test]
fn diagnostics_explain_rejections_and_keep_b36_policy() {
    let target = Ipv4Addr::new(10, 7, 0, 1);
    let cases = [
        (route("utun9", 33, [10, 7, 1, 1]), "accepted", true),
        (route("utun8", 32, [198, 18, 0, 1]), "source_not_private", false),
        (route("utun7", 31, [172, 19, 0, 1]), "source_prefix_mismatch", false),
        (route("utun6", 30, [10, 7, 0, 1]), "source_equals_target", false),
        (route("utun5", 0, [10, 7, 1, 1]), "invalid_index", false),
    ];
    let routes: Vec<_> = cases.iter().map(|(route, _, _)| route.clone()).collect();
    let logs = snapshot(target, &routes);
    let logs: Vec<_> = logs.into_iter().filter(|line| line.contains("step=interface route=") && routes.iter().any(|route| line.contains(&route.description()))).collect();
    for ((route, expected, accepted), log) in cases.iter().zip(&logs) {
        assert_eq!(eligible(route, target), *accepted);
        assert_eq!(reason(route, target), *expected);
        assert!(log.contains(&format!("eligible={accepted} reason={expected}")));
    }
    assert!(interface_lines(target, &routes, &BTreeMap::new()).last().unwrap().contains("eligible=1"));
}

#[tokio::test]
async fn observed_loon_is_logged_accepted_and_skips_unauthenticated_rejected_probe() {
    let route = route("utun9", 33, [198,19,0,1]);
    let logs = interface_lines(Ipv4Addr::new(10,7,0,1), &[route.clone()], &BTreeMap::new());
    assert!(logs[0].contains("eligible=true reason=accepted policy=loon_reflect"));
    let skipped = probe_rejected(ENDPOINT.ip(), ENDPOINT.port(), &[route]).await;
    assert!(skipped[0].contains("reason=eligible_route_exists"));
}

#[test]
fn down_and_ipv6_only_tunnels_are_visible_and_logs_are_bounded_and_redacted() {
    let mut states = BTreeMap::new();
    states.insert("utun1".into(), TunnelState { up: false, ipv4: true, ipv6: false, index: 1 });
    states.insert("utun2".into(), TunnelState { up: true, ipv4: false, ipv6: true, index: 2 });
    states.insert("SENSITIVE\nINJECTED".into(), TunnelState::default());
    let routes = vec![route("en0", 3, [192, 168, 30, 77]), route("utun9", 9, [10, 7, 1, 1])];
    let logs = interface_lines(Ipv4Addr::new(10, 7, 0, 1), &routes, &states);
    assert!(logs.iter().any(|s| s.contains("reason=interface_down")));
    assert!(logs.iter().any(|s| s.contains("ipv6=true eligible=false reason=no_ipv4")));
    assert!(!logs.join("\n").contains("SENSITIVE"));
    assert!(!logs.join("\n").contains("192.168.30.77"));
    let routes: Vec<_> = (1..=100).map(|i| route(&format!("utun{i}"), i, [10, 8, 0, 1])).collect();
    let logs = interface_lines(Ipv4Addr::new(10, 7, 0, 1), &routes, &BTreeMap::new());
    assert_eq!(logs.len(), MAX_INTERFACE_LINES + 1);
    assert!(logs.last().unwrap().contains("omitted=76"));
    assert!(logs.iter().all(|line| line.len() < 300));
}

#[test]
fn source_hint_is_labeled_as_a_hint_and_hides_non_tunnel_addresses() {
    let routes = vec![route("en0", 1, [192, 168, 30, 77]), route("utun9", 9, [198, 18, 0, 1])];
    let physical = hint_line("192.168.30.77:1234".parse().unwrap(), &routes);
    assert!(physical.contains("source_hint=non_utun_or_unknown"));
    assert!(!physical.contains("192.168.30.77"));
    let tunnel = hint_line("198.18.0.1:1234".parse().unwrap(), &routes);
    assert!(tunnel.contains("utun9#9 source=198.18.0.1"));
    assert!(tunnel.contains("sent_bytes=0") && tunnel.contains("proof=source_only"));
}

#[tokio::test]
async fn probes_are_capped_deduplicated_fixed_target_and_skipped_for_valid_route() {
    let mut routes = vec![route("en0", 1, [192, 168, 30, 77]), route("utun1", 2, [198, 18, 0, 1]),
        route("utun1", 2, [198, 18, 0, 2]), route("utun2", 3, [127, 0, 0, 1]),
        route("utun3", 4, [10, 7, 0, 1]), route("utun4", 0, [198, 18, 0, 1])];
    routes.extend((10..30).map(|i| route(&format!("utun{i}"), i, [172, 19, 0, 1])));
    let candidates = probe_candidates(&routes, Ipv4Addr::new(10, 7, 0, 1));
    assert_eq!(candidates.len(), MAX_PROBES);
    assert_eq!(candidates[0].index, 2);
    assert_eq!(candidates[1].index, 10);
    let skipped = probe_rejected("127.0.0.1".parse().unwrap(), 62078, &routes).await;
    assert!(skipped[0].contains("unexpected_endpoint"));
    let skipped = source_hint(ENDPOINT.ip(), 62079, &routes).await;
    assert!(skipped.contains("unexpected_endpoint"));
    routes.push(route("utun99", 99, [10, 7, 1, 1]));
    let skipped = probe_rejected(ENDPOINT.ip(), 62078, &routes).await;
    assert!(skipped[0].contains("eligible_route_exists"));
}

#[tokio::test]
async fn real_bound_probe_connects_closes_and_sends_zero_bytes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = super::super::loopback_test_route();
    let (entry, peer) = tokio::join!(probe_one(listener.local_addr().unwrap(), &route), listener.accept());
    let (mut peer, _) = peer.unwrap();
    let count = timeout(Duration::from_secs(1), peer.read(&mut [0; 16])).await.unwrap().unwrap();
    assert_eq!(count, 0, "diagnostic connection must close without plist/TLS/credentials");
    assert!(entry.contains("tcp=connected errno=0") && entry.contains("auth=not_sent"));
    assert!(entry.contains(&format!("route={}", route.description())));
}

#[tokio::test]
async fn unavailable_probe_never_connects_unbound_and_diagnostic_error_keeps_original_stage() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad = route("utun999", u32::MAX, [198, 18, 0, 1]);
    let entry = probe_one(listener.local_addr().unwrap(), &bad).await;
    assert!(entry.contains("tcp=interface_unavailable"));
    assert!(timeout(Duration::from_millis(30), listener.accept()).await.is_err());
    let original = select_route(ENDPOINT.ip(), ENDPOINT.port(), vec![]).await;
    let error = prepend_diagnostics(original, vec![entry.clone()]).err().expect("expected failure");
    assert_eq!(error.stage, "lockdown_route");
    assert_eq!(error.diagnostics[0], entry);
    assert!(error.diagnostics[1].contains("route=none"));
}

#[tokio::test]
async fn extra_diagnostics_keep_selected_bound_socket_usable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let route = super::super::loopback_test_route();
    let result = select_route(endpoint.ip(), endpoint.port(), vec![route.clone()]).await;
    let (selected, mut stream, entries) = prepend_diagnostics(result, vec!["diagnostic".into()])
        .unwrap_or_else(|e| panic!("{}", e.stage));
    assert_eq!(selected, Some(route));
    assert_eq!(entries[0], "diagnostic");
    assert!(entries[1].contains("tcp=connected"));
    let (mut peer, _) = listener.accept().await.unwrap();
    stream.write_all(b"same authenticated connector socket").await.unwrap();
    let mut received = [0; 35]; peer.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"same authenticated connector socket");
}
