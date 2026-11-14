//! Bounded diagnostics for the B36 and observed Loon authenticated policies.
//! Only fixed endpoint TCP handshakes and zero-payload UDP source selection.
//! Never authenticate a rejected route or expose physical interface addresses.
use super::*;
use std::{collections::BTreeMap, time::Duration};

const MAX_INTERFACE_LINES: usize = 24;
const MAX_PROBES: usize = 4;
const PROBE_TIMEOUT: Duration = Duration::from_millis(1200);
const SOURCE_HINT_TIMEOUT: Duration = Duration::from_millis(300);
const ENDPOINT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1)), 62078);

fn is_tunnel(name: &str) -> bool {
    name.strip_prefix("utun").is_some_and(|suffix|
        !suffix.is_empty() && suffix.len() <= 10 && suffix.bytes().all(|b| b.is_ascii_digit()))
}

fn reason(route: &BoundRoute, target: Ipv4Addr) -> &'static str {
    if eligible(route, target) { return "accepted"; }
    if !is_tunnel(&route.name) { "not_utun" }
    else if route.index == 0 { "invalid_index" }
    else if !route.address.is_private() { "source_not_private" }
    else if !target.is_private() { "target_not_private" }
    else if route.address.octets()[..2] != target.octets()[..2] { "source_prefix_mismatch" }
    else if route.address == target { "source_equals_target" }
    else { "policy_rejected" }
}

#[derive(Default)]
struct TunnelState {
    up: bool,
    ipv4: bool,
    ipv6: bool,
    index: u32,
}

fn tunnel_states() -> io::Result<BTreeMap<String, TunnelState>> {
    use std::ffi::CStr;
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 { return Err(io::Error::last_os_error()); }
    struct List(*mut libc::ifaddrs);
    impl Drop for List {
        fn drop(&mut self) { unsafe { libc::freeifaddrs(self.0) }; }
    }
    let _list = List(head);
    let mut states = BTreeMap::<String, TunnelState>::new();
    let mut next = head;
    while !next.is_null() {
        let item = unsafe { &*next }; next = item.ifa_next;
        if item.ifa_name.is_null() { continue; }
        let name = unsafe { CStr::from_ptr(item.ifa_name) }.to_string_lossy();
        if !is_tunnel(&name) { continue; }
        let state = states.entry(name.into_owned()).or_default();
        state.up |= item.ifa_flags & libc::IFF_UP as u32 != 0;
        state.index = unsafe { libc::if_nametoindex(item.ifa_name) };
        if !item.ifa_addr.is_null() {
            let family = unsafe { (*item.ifa_addr).sa_family } as i32;
            state.ipv4 |= family == libc::AF_INET;
            state.ipv6 |= family == libc::AF_INET6;
        }
    }
    Ok(states)
}

fn interface_lines(target: Ipv4Addr, routes: &[BoundRoute], states: &BTreeMap<String, TunnelState>) -> Vec<String> {
    let mut lines = Vec::new();
    for route in routes.iter().filter(|route| is_tunnel(&route.name)) {
        lines.push(format!("phase=route_diag step=interface route={} up=true eligible={} reason={} policy={}",
            route.description(), eligible(route, target), reason(route, target), policy(route, target).unwrap_or("none")));
    }
    // State sampling includes down/IPv6-only tunnels absent from the actual
    // IPv4 candidate enumeration. Do not print IPv6 addresses or non-utun IPs.
    for (name, state) in states.iter().filter(|(name, _)| is_tunnel(name)) {
        if routes.iter().any(|route| &route.name == name) { continue; }
        let reason = if !state.up { "interface_down" }
            else if state.index == 0 { "invalid_index" }
            else if !state.ipv4 { "no_ipv4" }
            else { "not_in_ipv4_snapshot" };
        lines.push(format!("phase=route_diag step=interface route={name}#{} up={} ipv4={} ipv6={} eligible=false reason={reason}",
            state.index, state.up, state.ipv4, state.ipv6));
    }
    let omitted = lines.len().saturating_sub(MAX_INTERFACE_LINES);
    lines.truncate(MAX_INTERFACE_LINES);
    lines.push(format!("phase=route_diag step=summary ipv4_utun={} eligible={} omitted={omitted}",
        routes.iter().filter(|r| is_tunnel(&r.name)).count(), routes.iter().filter(|r| eligible(r, target)).count()));
    lines
}

pub(super) fn snapshot(target: Ipv4Addr, routes: &[BoundRoute]) -> Vec<String> {
    let mut entries = vec![format!("phase=route_diag step=policy target={target} source_prefix=10.7 extra_source=198.19.0.1 rule=b38")];
    match tunnel_states() {
        Ok(states) => entries.extend(interface_lines(target, routes, &states)),
        Err(error) => {
            // Auxiliary state inspection is best effort. Actual candidate
            // enumeration and the authenticated path must remain usable.
            entries.push(format!("phase=route_diag step=state_error {}", socket_detail(&error)));
            entries.extend(interface_lines(target, routes, &BTreeMap::new()));
        }
    }
    entries
}

fn hint_line(local: SocketAddr, routes: &[BoundRoute]) -> String {
    let found = routes.iter().find(|route| is_tunnel(&route.name) && IpAddr::V4(route.address) == local.ip());
    let source = found.map(BoundRoute::description).unwrap_or_else(|| "non_utun_or_unknown".into());
    format!("phase=route_diag step=source_hint method=udp_connect sent_bytes=0 source_hint={source} proof=source_only")
}

pub(super) async fn source_hint(ip: IpAddr, port: u16, routes: &[BoundRoute]) -> String {
    if SocketAddr::new(ip, port) != ENDPOINT {
        return "phase=route_diag step=source_hint result=skipped reason=unexpected_endpoint".into();
    }
    let hint = tokio::time::timeout(SOURCE_HINT_TIMEOUT, async {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        // UDP connect chooses a local source without sending any payload.
        // This is a hint, not a routing-table lookup or TCP reachability proof.
        socket.connect(ENDPOINT).await?;
        socket.local_addr()
    }).await.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
    match hint {
        Ok(local) => hint_line(local, routes),
        Err(error) => format!("phase=route_diag step=source_hint sent_bytes=0 result=failed {}", socket_detail(&error)),
    }
}

fn probe_candidates(routes: &[BoundRoute], target: Ipv4Addr) -> Vec<BoundRoute> {
    let mut candidates: Vec<BoundRoute> = Vec::new();
    for route in routes {
        if !is_tunnel(&route.name) || route.index == 0 || route.address == target
            || route.address.is_unspecified() || route.address.is_multicast() || route.address.is_loopback()
            || eligible(route, target)
            || candidates.iter().any(|chosen| chosen.index == route.index)
        { continue; }
        candidates.push(route.clone());
        if candidates.len() == MAX_PROBES { break; }
    }
    candidates
}

async fn probe_one(endpoint: SocketAddr, route: &BoundRoute) -> String {
    let start = Instant::now();
    let result = tokio::time::timeout(PROBE_TIMEOUT, connect_bound(endpoint, route)).await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
    let detail = result.as_ref().err().map(socket_detail).unwrap_or_else(|| "tcp=connected errno=0".into());
    // No reads, TLS, plist, StartSession or credentials. The diagnostic socket
    // is dropped here even when it connects; it can never be used by legacy.rs.
    drop(result);
    format!("phase=route_diag step=probe route={} target={} port={} elapsed_ms={} {detail} auth=not_sent",
        route.description(), endpoint.ip(), endpoint.port(), start.elapsed().as_millis())
}

pub(super) async fn probe_rejected(ip: IpAddr, port: u16, routes: &[BoundRoute]) -> Vec<String> {
    if SocketAddr::new(ip, port) != ENDPOINT {
        return vec!["phase=route_diag step=probe_summary result=skipped reason=unexpected_endpoint".into()];
    }
    let IpAddr::V4(target) = ip else { unreachable!() };
    // Defense in depth: do not probe when a supported route exists.
    if routes.iter().any(|route| eligible(route, target)) {
        return vec!["phase=route_diag step=probe_summary result=skipped reason=eligible_route_exists".into()];
    }
    let candidates = probe_candidates(routes, target);
    let mut entries = vec![format!("phase=route_diag step=probe_summary candidates={} max={MAX_PROBES} timeout_ms={} auth=not_sent",
        candidates.len(), PROBE_TIMEOUT.as_millis())];
    for route in &candidates { entries.push(probe_one(ENDPOINT, route).await); }
    entries
}

#[cfg(test)]
mod tests;
