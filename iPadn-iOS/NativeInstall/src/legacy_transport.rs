//! IPv4 interface-scoped transport for this device's existing loopback VPN.
//! No device discovery, pairing, credentials, VPN changes or remote fallbacks.
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;
use tokio::net::TcpStream;
use crate::{Failure, CONNECT_TIMEOUT, failure};

#[cfg(any(target_os = "ios", all(test, target_os = "macos")))]
mod diagnostics;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundRoute {
    name: String,
    index: u32,
    address: Ipv4Addr,
}

impl BoundRoute {
    pub(crate) fn description(&self) -> String {
        format!("{}#{} source={}", self.name, self.index, self.address)
    }
}

/// Keep numeric errno and an allowlisted category, never io::Error's payload.
pub(crate) fn socket_detail(error: &io::Error) -> String {
    let kind = match error.kind() {
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::NetworkDown => "network_down",
        io::ErrorKind::NotConnected => "interface_unavailable",
        io::ErrorKind::ConnectionReset => "connection_reset",
        _ => "socket_error",
    };
    format!("tcp={kind} errno={}", error.raw_os_error().unwrap_or(0))
}

#[cfg(any(target_os = "ios", test))]
fn eligible(route: &BoundRoute, target: Ipv4Addr) -> bool {
    policy(route, target).is_some()
}

#[cfg(any(target_os = "ios", test))]
fn policy(route: &BoundRoute, target: Ipv4Addr) -> Option<&'static str> {
    // LocalDevVPN may use /32 addresses in different /24s (e.g. source
    // 10.7.1.1 and peer 10.7.0.1). Do not assume matching /24 masks.
    let suffix = route.name.strip_prefix("utun").unwrap_or("");
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit())
        || route.index == 0 || !target.is_private() || route.address == target
    { return None; }
    if route.address.is_private() && route.address.octets()[..2] == target.octets()[..2] {
        return Some("b36");
    }
    // B37 device evidence: Loon's active utun source198.19.0.1 can reach
    // the existing reflector10.7.0.1:62078. This benchmark-range address is
    // not RFC1918 private; do not generalize to198.18/15 or arbitrary utuns.
    if target == Ipv4Addr::new(10, 7, 0, 1) && route.address == Ipv4Addr::new(198, 19, 0, 1) {
        return Some("loon_reflect");
    }
    None
}

#[cfg(any(target_os = "ios", test))]
fn candidate_routes(discovered: &[BoundRoute], target: Ipv4Addr) -> Vec<BoundRoute> {
    let mut routes: Vec<_> = discovered.iter().filter(|route| eligible(route, target)).cloned().collect();
    // Stable priority keeps the exact B36 order among its existing routes.
    // Try the observed Loon mapping after all previously eligible routes.
    routes.sort_by_key(|route| policy(route, target) != Some("b36"));
    routes
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn interfaces() -> io::Result<Vec<BoundRoute>> {
    use std::ffi::CStr;
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct List(*mut libc::ifaddrs);
    impl Drop for List {
        fn drop(&mut self) { unsafe { libc::freeifaddrs(self.0) }; }
    }
    let _list = List(head);
    let mut result = Vec::new();
    let mut next = head;
    while !next.is_null() {
        let interface = unsafe { &*next };
        next = interface.ifa_next;
        if interface.ifa_name.is_null() || interface.ifa_addr.is_null()
            || interface.ifa_flags & libc::IFF_UP as u32 == 0
            || unsafe { (*interface.ifa_addr).sa_family } as i32 != libc::AF_INET
        { continue; }
        let name = unsafe { CStr::from_ptr(interface.ifa_name) }.to_string_lossy().into_owned();
        let index = unsafe { libc::if_nametoindex(interface.ifa_name) };
        let address = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in>() };
        let route = BoundRoute { name, index, address: Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()) };
        if index != 0 && !result.contains(&route) { result.push(route); }
    }
    result.sort_by_key(|route| route.index);
    Ok(result)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub(crate) async fn connect_bound(target: SocketAddr, route: &BoundRoute) -> io::Result<TcpStream> {
    use std::os::fd::AsRawFd;
    if !target.is_ipv4() || !interfaces()?.contains(route) {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "selected interface unavailable"));
    }
    let socket = tokio::net::TcpSocket::new_v4()?;
    let status = unsafe {
        libc::setsockopt(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_BOUND_IF,
            (&route.index as *const u32).cast(), std::mem::size_of::<u32>() as libc::socklen_t)
    };
    if status != 0 { return Err(io::Error::last_os_error()); }
    // Scope the real socket, not just a preflight. Never retry it unbound.
    socket.connect(target).await
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
pub(crate) async fn connect_bound(_target: SocketAddr, _route: &BoundRoute) -> io::Result<TcpStream> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "interface binding requires Darwin"))
}

pub(crate) async fn connect_port(ip: IpAddr, port: u16, route: Option<&BoundRoute>) -> io::Result<TcpStream> {
    let target = SocketAddr::new(ip, port);
    match route {
        Some(route) => connect_bound(target, route).await,
        None => TcpStream::connect(target).await,
    }
}

fn attempt(route: Option<&BoundRoute>, port: u16, start: Instant, error: Option<&io::Error>) -> String {
    format!("route={} port={port} elapsed_ms={} {}",
        route.map(BoundRoute::description).unwrap_or_else(|| "explicit-host".into()),
        start.elapsed().as_millis(),
        error.map(socket_detail).unwrap_or_else(|| "tcp=connected errno=0".into()))
}

pub(crate) async fn recorded_connect(ip: IpAddr, port: u16, route: Option<&BoundRoute>)
    -> (io::Result<TcpStream>, String)
{
    let start = Instant::now();
    // Leave time for the enclosing service timeout to receive the diagnostic.
    let timeout = CONNECT_TIMEOUT.saturating_sub(std::time::Duration::from_secs(2));
    let result = tokio::time::timeout(timeout, connect_port(ip, port, route)).await
        .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)));
    let diagnostic = attempt(route, port, start, result.as_ref().err());
    (result, diagnostic)
}

#[cfg(any(target_os = "ios", all(test, target_os = "macos")))]
async fn select_route(ip: IpAddr, port: u16, routes: Vec<BoundRoute>)
    -> Result<(Option<BoundRoute>, TcpStream, Vec<String>), Failure>
{
    let mut diagnostics = Vec::new();
    if routes.is_empty() {
        let mut error = failure("lockdown_route", "no matching active IPv4 VPN interface");
        error.diagnostics.push(format!("route=none port={port} tcp=interface_unavailable errno=0"));
        return Err(error);
    }
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    for route in routes {
        let start = Instant::now();
        let until = deadline.min(tokio::time::Instant::now() + std::time::Duration::from_secs(3));
        let result = tokio::time::timeout_at(until, connect_port(ip, port, Some(&route))).await
            .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)));
        diagnostics.push(attempt(Some(&route), port, start, result.as_ref().err()));
        if let Ok(stream) = result { return Ok((Some(route), stream, diagnostics)); }
        if tokio::time::Instant::now() >= deadline { break; }
    }
    let mut error = failure("lockdown_connect", diagnostics.last().cloned().unwrap_or_default());
    error.diagnostics = diagnostics;
    Err(error)
}

pub(crate) async fn open_lockdown(ip: IpAddr, port: u16)
    -> Result<(Option<BoundRoute>, TcpStream, Vec<String>), Failure>
{
    #[cfg(target_os = "ios")]
    {
        // The app's documented local endpoint only. No LAN scan or alternate
        // target may receive pairing credentials as an automatic fallback.
        let IpAddr::V4(target) = ip else {
            return Err(failure("lockdown_route", "local VPN transport requires IPv4"));
        };
        if target != Ipv4Addr::new(10, 7, 0, 1) {
            return Err(failure("lockdown_route", "unexpected local VPN endpoint"));
        }
        let discovered = interfaces().map_err(|e| {
            let mut error = failure("lockdown_route", socket_detail(&e));
            error.diagnostics.push(format!("interface enumeration: {}", socket_detail(&e)));
            error
        })?;
        let mut diagnostics = diagnostics::snapshot(target, &discovered);
        let routes = candidate_routes(&discovered, target);
        // The hint performs no send and cannot select an authenticated route.
        diagnostics.push(diagnostics::source_hint(ip, port, &discovered).await);
        if routes.is_empty() {
            diagnostics.extend(diagnostics::probe_rejected(ip, port, &discovered).await);
        }
        let selected = select_route(ip, port, routes).await;
        if let Ok((Some(route), _, _)) = &selected {
            diagnostics.push(format!("phase=route_diag step=selection policy={}", policy(route, target).unwrap_or("unknown")));
        }
        prepend_diagnostics(selected, diagnostics)
    }
    #[cfg(not(target_os = "ios"))]
    {
        // Preserve the standalone, explicitly addressed host CLI.
        let (result, diagnostic) = recorded_connect(ip, port, None).await;
        let stream = result.map_err(|e| {
            let mut error = failure("lockdown_connect", socket_detail(&e));
            error.diagnostics.push(diagnostic.clone());
            error
        })?;
        Ok((None, stream, vec![diagnostic]))
    }
}

#[cfg(any(target_os = "ios", all(test, target_os = "macos")))]
fn prepend_diagnostics(
    result: Result<(Option<BoundRoute>, TcpStream, Vec<String>), Failure>,
    mut diagnostics: Vec<String>,
) -> Result<(Option<BoundRoute>, TcpStream, Vec<String>), Failure> {
    match result {
        Ok((route, stream, entries)) => {
            diagnostics.extend(entries);
            Ok((route, stream, diagnostics))
        }
        Err(mut error) => {
            diagnostics.append(&mut error.diagnostics);
            error.diagnostics = diagnostics;
            Err(error)
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) fn loopback_test_route() -> BoundRoute {
    interfaces().unwrap().into_iter().find(|r| r.name == "lo0" && r.address.is_loopback()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_loon_source_is_allowed_only_for_exact_reflector_and_valid_utun() {
        let target = Ipv4Addr::new(10, 7, 0, 1);
        let route = BoundRoute { name: "utun9".into(), index: 33, address: Ipv4Addr::new(198, 19, 0, 1) };
        assert!(!route.address.is_private());
        assert_eq!(policy(&route, target), Some("loon_reflect"));
        for source in [[198,18,0,1], [198,19,0,2], [198,19,1,1], [198,20,0,1],
            [172,19,0,1], [192,168,0,1], [8,8,8,8]]
        {
            assert!(!eligible(&BoundRoute { address: source.into(), ..route.clone() }, target));
        }
        for target in [[10,7,0,2], [10,8,0,1], [127,0,0,1], [198,19,0,1], [8,8,8,8]] {
            assert!(!eligible(&route, target.into()));
        }
        for invalid in [BoundRoute { name: "en0".into(), ..route.clone() },
            BoundRoute { name: "utun".into(), ..route.clone() },
            BoundRoute { name: "utun9x".into(), ..route.clone() },
            BoundRoute { index: 0, ..route.clone() }]
        { assert!(!eligible(&invalid, target)); }
    }

    #[test]
    fn original_b36_eligibility_is_preserved_and_only_observed_mapping_is_added() {
        fn b36(route: &BoundRoute, target: Ipv4Addr) -> bool {
            let suffix = route.name.strip_prefix("utun").unwrap_or("");
            !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                && route.index != 0 && route.address.is_private() && target.is_private()
                && route.address.octets()[..2] == target.octets()[..2] && route.address != target
        }
        for name in ["utun0", "utun9", "utun", "utun1x", "en0", "lo0"] {
            for index in [0, 9, 33] {
                for source in [[10,7,1,1], [10,7,0,1], [10,8,0,1], [172,19,0,1],
                    [198,18,0,1], [198,19,0,1], [198,19,0,2], [127,0,0,1], [8,8,8,8]]
                {
                    let route = BoundRoute { name: name.into(), index, address: source.into() };
                    for target in [[10,7,0,1], [10,8,0,1], [172,19,0,2], [127,0,0,1], [8,8,8,8]] {
                        let target = Ipv4Addr::from(target);
                        if b36(&route, target) { assert_eq!(policy(&route, target), Some("b36")); }
                        else if eligible(&route, target) {
                            assert_eq!(policy(&route, target), Some("loon_reflect"));
                            assert_eq!(route.address, Ipv4Addr::new(198,19,0,1));
                            assert_eq!(target, Ipv4Addr::new(10,7,0,1));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn candidate_routes_keep_b36_order_and_priority_before_loon() {
        let loon = BoundRoute { name: "utun1".into(), index: 1, address: Ipv4Addr::new(198,19,0,1) };
        let first = BoundRoute { name: "utun9".into(), index: 9, address: Ipv4Addr::new(10,7,1,1) };
        let second = BoundRoute { name: "utun10".into(), index: 10, address: Ipv4Addr::new(10,7,2,1) };
        let unsupported = BoundRoute { name: "utun8".into(), index: 8, address: Ipv4Addr::new(172,19,0,1) };
        let target = Ipv4Addr::new(10,7,0,1);
        assert_eq!(candidate_routes(&[loon.clone(), unsupported, first.clone(), second.clone()], target),
            vec![first, second, loon.clone()]);
        assert_eq!(candidate_routes(&[loon.clone()], target), vec![loon]);
    }

    #[test]
    fn accepts_split_32_tunnel_but_rejects_unrelated_interfaces() {
        let target = Ipv4Addr::new(10, 7, 0, 1);
        let route = BoundRoute { name: "utun12".into(), index: 31, address: Ipv4Addr::new(10, 7, 1, 1) };
        assert!(eligible(&route, target));
        for bad in [
            BoundRoute { name: "en0".into(), ..route.clone() },
            BoundRoute { name: "utun".into(), ..route.clone() },
            BoundRoute { index: 0, ..route.clone() },
            BoundRoute { address: target, ..route.clone() },
            BoundRoute { address: Ipv4Addr::new(10, 8, 0, 1), ..route.clone() },
        ] { assert!(!eligible(&bad, target)); }
    }

    #[test]
    fn diagnostics_never_echo_socket_error_payloads() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "PRIVATE_KEY_SENSITIVE");
        assert_eq!(socket_detail(&error), "tcp=permission_denied errno=0");
        assert!(!socket_detail(&error).contains("SENSITIVE"));
        let error = io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert!(socket_detail(&error).contains("connection_refused"));
        assert!(socket_detail(&error).contains(&format!("errno={}", libc::ECONNREFUSED)));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn real_sockets_keep_bound_interface_on_multiple_service_ports() {
        use std::os::fd::AsRawFd;
        let route = interfaces().unwrap().into_iter().find(|r| r.name == "lo0" && r.address.is_loopback()).unwrap();
        for _ in 0..2 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let stream = connect_bound(listener.local_addr().unwrap(), &route).await.unwrap();
            let _peer = listener.accept().await.unwrap();
            let mut index: u32 = 0;
            let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
            assert_eq!(unsafe { libc::getsockopt(stream.as_raw_fd(), libc::IPPROTO_IP, libc::IP_BOUND_IF,
                (&mut index as *mut u32).cast(), &mut len) }, 0);
            assert_eq!(index, route.index);
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn vanished_interface_fails_even_when_unbound_target_is_reachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let route = BoundRoute { name: "utun999999".into(), index: u32::MAX, address: Ipv4Addr::LOCALHOST };
        let error = connect_bound(listener.local_addr().unwrap(), &route).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(80), listener.accept()).await.is_err());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn candidate_selection_returns_the_selected_socket_and_never_falls_back_unbound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let route = interfaces().unwrap().into_iter().find(|r| r.name == "lo0" && r.address.is_loopback()).unwrap();
        let bad = BoundRoute { index: u32::MAX, ..route.clone() };
        let (selected, _stream, diagnostics) = select_route(target.ip(), target.port(), vec![bad.clone(), route.clone()]).await.unwrap_or_else(|e| panic!("{}", e.message));
        assert_eq!(selected, Some(route));
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics[0].contains("interface_unavailable"));
        assert!(diagnostics[1].contains("tcp=connected"));
        let _peer = listener.accept().await.unwrap();
        let error = select_route(target.ip(), target.port(), vec![bad]).await.err().unwrap();
        assert_eq!(error.stage, "lockdown_connect");
        assert!(tokio::time::timeout(std::time::Duration::from_millis(80), listener.accept()).await.is_err());
    }
}
