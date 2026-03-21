//! Connection collector — full pipeline from /proc parsing to enriched Connection structs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::data::*;
use crate::data::procfs;
use crate::data::geoip;
use crate::data::threat;

/// Full collection pipeline:
/// 1. Parse /proc/net/tcp, tcp6, udp, udp6
/// 2. Build inode→pid map
/// 3. Resolve process names
/// 4. Construct enriched Connection structs
pub fn collect_connections() -> Vec<Connection> {
    // Gather raw sockets from all four files
    let mut raw_sockets: Vec<(procfs::RawSocket, Protocol, bool)> = Vec::new();

    for s in procfs::parse_proc_net_tcp(false) { // IPv4
        raw_sockets.push((s, Protocol::Tcp, false));
    }
    for s in procfs::parse_proc_net_tcp(true) { // IPv6 TCP
        raw_sockets.push((s, Protocol::Tcp, true));
    }
    for s in procfs::parse_proc_net_udp(false) { // IPv4 UDP
        raw_sockets.push((s, Protocol::Udp, false));
    }
    for s in procfs::parse_proc_net_udp(true) { // IPv6 UDP
        raw_sockets.push((s, Protocol::Udp, true));
    }

    // Build inode → PID mapping
    let inode_map = procfs::build_inode_pid_map();

    let mut connections = Vec::with_capacity(raw_sockets.len());

    for (raw, protocol, is_v6) in raw_sockets {
        let local_ip = u128_to_ip(raw.local_addr, is_v6);
        let remote_ip = u128_to_ip(raw.remote_addr, is_v6);

        let local_addr = SocketAddr::new(local_ip, raw.local_port);
        let remote_addr = SocketAddr::new(remote_ip, raw.remote_port);

        let state = TcpState::from_u8(raw.state);

        let pid = inode_map.get(&raw.inode).copied();
        let process_name = pid.and_then(procfs::get_process_name).or_else(|| {
            // Sockets with inode=0 are kernel-owned (TIME_WAIT/CLOSE)
            // No process owns them — label based on TCP state
            match state {
                TcpState::TimeWait => Some("[time-wait]".to_string()),
                TcpState::Close => Some("[closed]".to_string()),
                TcpState::CloseWait => Some("[close-wait]".to_string()),
                _ => Some("[kernel]".to_string()),
            }
        });
        let user = pid
            .and_then(procfs::get_process_uid)
            .and_then(uid_to_username);

        let geo = if !geoip::is_private_ip(remote_ip) {
            geoip::lookup(remote_ip)
        } else {
            None
        };

        let is_threat = threat::is_threat_ip(&remote_ip);
        let direction = classify_direction(local_addr, remote_addr, state);

        connections.push(Connection {
            local_addr,
            remote_addr,
            state,
            protocol,
            inode: raw.inode,
            pid,
            process_name,
            user,
            geo,
            is_threat,
            direction,
            rx_bps: 0.0,
            tx_bps: 0.0,
            tx_queue: raw.tx_queue,
            rx_queue: raw.rx_queue,
            retransmits: raw.retransmits,
        });
    }

    connections
}

/// Aggregate connections by TCP state. Returns a sorted vec of (state, count).
pub fn aggregate_by_state(conns: &[Connection]) -> Vec<(TcpState, u32)> {
    let mut counts = std::collections::HashMap::new();
    for c in conns {
        *counts.entry(c.state).or_insert(0u32) += 1;
    }
    let mut result: Vec<_> = counts.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

/// Aggregate connections by country code. Returns sorted vec of (country_code, count).
pub fn aggregate_by_country(conns: &[Connection]) -> Vec<(String, u32)> {
    let mut counts = std::collections::HashMap::new();
    for c in conns {
        let cc = c
            .geo
            .as_ref()
            .map(|g| g.country_code.clone())
            .unwrap_or_else(|| "??".to_string());
        *counts.entry(cc).or_insert(0u32) += 1;
    }
    let mut result: Vec<_> = counts.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

/// Aggregate connections by process name. Returns sorted vec of (process, count).
pub fn aggregate_by_process(conns: &[Connection]) -> Vec<(String, u32)> {
    let mut counts = std::collections::HashMap::new();
    for c in conns {
        let name = c.process_name.clone().unwrap_or_else(|| "[kernel]".to_string());
        if name.starts_with("[") { continue; } // Skip kernel-owned sockets from top apps
        *counts.entry(name).or_insert(0u32) += 1;
    }
    let mut result: Vec<_> = counts.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Convert a u128 (as stored by procfs parser) into an IpAddr.
/// Values ≤ 0xFFFFFFFF are treated as IPv4, otherwise IPv6.
fn u128_to_ip(addr: u128, is_ipv6: bool) -> IpAddr {
    if !is_ipv6 && addr <= u32::MAX as u128 {
        IpAddr::V4(Ipv4Addr::from(addr as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(addr))
    }
}

/// Classify direction based on address characteristics and state.
fn classify_direction(local: SocketAddr, remote: SocketAddr, state: TcpState) -> Direction {
    let remote_ip = remote.ip();

    // Only true loopback is Local — NOT private-to-private, which may be
    // LAN, VPN, Docker, or CGNAT traffic that the user wants to see.
    if remote_ip.is_loopback() || remote_ip.is_unspecified() {
        return Direction::Local;
    }

    // Also local if remote is the exact same IP as local (process talking to itself)
    if remote_ip == local.ip() && !remote_ip.is_unspecified() {
        return Direction::Local;
    }

    match state {
        TcpState::Listen => Direction::Inbound,
        TcpState::SynSent => Direction::Outbound,
        TcpState::SynRecv => Direction::Inbound,
        TcpState::Established | TcpState::CloseWait | TcpState::FinWait1
        | TcpState::FinWait2 | TcpState::LastAck | TcpState::Closing => {
            classify_by_ports(local, remote)
        }
        TcpState::TimeWait | TcpState::Close => {
            // For UDP, state 07 (Close) is the normal active state — still classify.
            // For TCP TIME_WAIT / CLOSE, port heuristics are the best we have.
            classify_by_ports(local, remote)
        }
        TcpState::Unknown => classify_by_ports(local, remote),
    }
}

/// Determine direction from port numbers alone.
fn classify_by_ports(local: SocketAddr, remote: SocketAddr) -> Direction {
    let lp = local.port();
    let rp = remote.port();

    // Well-known port (< 1024) on one side is definitive
    if lp < 1024 && rp >= 1024 {
        return Direction::Inbound;
    }
    if rp < 1024 && lp >= 1024 {
        return Direction::Outbound;
    }

    // Common service ports on remote → Outbound
    if is_common_service_port(rp) && !is_common_service_port(lp) {
        return Direction::Outbound;
    }
    if is_common_service_port(lp) && !is_common_service_port(rp) {
        return Direction::Inbound;
    }

    // Ephemeral local port (>= 32768) connecting to any remote → Outbound.
    // This works for both public and private IPs (LAN, VPN, containers).
    if lp >= 32768 && rp < 32768 {
        return Direction::Outbound;
    }
    if rp >= 32768 && lp < 32768 {
        return Direction::Inbound;
    }

    // Both in ephemeral range — the lower port is more likely the "server"
    if lp >= 32768 && rp >= 32768 {
        return if rp < lp { Direction::Outbound } else { Direction::Inbound };
    }

    Direction::Unknown
}

/// Common service ports that indicate the remote side is a server.
fn is_common_service_port(port: u16) -> bool {
    matches!(
        port,
        // Web
        80 | 443 | 8080 | 8443 | 8000 | 8888 | 3000 | 4000 | 5000 | 9000 |
        // Databases
        3306 | 5432 | 6379 | 27017 | 11211 | 9042 | 26257 | 5984 | 8529 |
        // Messaging / XMPP / GCM
        5222 | 5223 | 5228 | 5229 | 5230 | 5672 | 15672 | 9092 | 4222 |
        // Monitoring
        9090 | 9093 | 9100 | 9200 | 9300 | 3100 | 8086 | 8125 | 9411 |
        // MQTT
        1883 | 8883 |
        // IRC
        6667 | 6697 |
        // STUN/TURN
        3478 | 5349 |
        // Streaming
        1935 | 554 |
        // Container / orchestration
        2375 | 2376 | 6443 | 10250 | 2379 | 2380 |
        // Other
        8081 | 8082 | 8880
    )
}

/// Map a UID to a username by reading /etc/passwd.
/// Returns None on failure (e.g. Windows or if UID not found).
fn uid_to_username(uid: u32) -> Option<String> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 {
            if let Ok(line_uid) = fields[2].parse::<u32>() {
                if line_uid == uid {
                    return Some(fields[0].to_string());
                }
            }
        }
    }
    // Fallback: just return the numeric UID
    Some(format!("uid:{}", uid))
}
