//! Connection collector — full pipeline from /proc parsing to enriched Connection structs.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::data::*;
use crate::data::procfs;
use crate::data::geoip;
use crate::data::threat;

/// Full collection pipeline:
/// 1. Parse /proc/net/tcp, tcp6, udp, udp6
/// 2. Build inode→pid map
/// 3. Collect listening ports (ground truth for direction)
/// 4. Classify direction using listening set — no guessing
/// 5. Construct enriched Connection structs
pub fn collect_connections() -> Vec<Connection> {
    // Gather raw sockets from all four files
    let mut raw_sockets: Vec<(procfs::RawSocket, Protocol, bool)> = Vec::new();

    for s in procfs::parse_proc_net_tcp(false) {
        raw_sockets.push((s, Protocol::Tcp, false));
    }
    for s in procfs::parse_proc_net_tcp(true) {
        raw_sockets.push((s, Protocol::Tcp, true));
    }
    for s in procfs::parse_proc_net_udp(false) {
        raw_sockets.push((s, Protocol::Udp, false));
    }
    for s in procfs::parse_proc_net_udp(true) {
        raw_sockets.push((s, Protocol::Udp, true));
    }

    // Build inode → PID mapping
    let inode_map = procfs::build_inode_pid_map();

    // ── Pass 1: collect every port that has a LISTEN socket ──────────
    // For TCP: state 0x0A = LISTEN.
    // For UDP: bound sockets with remote 0.0.0.0:0 (state 07) are "listening".
    // This set is the ground truth: if our local port is in here, someone
    // connected TO us.  If not, WE initiated it.
    let mut listening_ports: HashSet<u16> = HashSet::new();
    for (raw, protocol, _) in &raw_sockets {
        match protocol {
            Protocol::Tcp => {
                if raw.state == 0x0A {
                    // TCP LISTEN
                    listening_ports.insert(raw.local_port);
                }
            }
            Protocol::Udp => {
                if raw.remote_addr == 0 && raw.remote_port == 0 {
                    // UDP bound socket (the equivalent of "listening")
                    listening_ports.insert(raw.local_port);
                }
            }
        }
    }

    // ── Pass 2: build enriched connections ───────────────────────────
    let mut connections = Vec::with_capacity(raw_sockets.len());

    for (raw, protocol, is_v6) in raw_sockets {
        let local_ip = u128_to_ip(raw.local_addr, is_v6);
        let remote_ip = u128_to_ip(raw.remote_addr, is_v6);

        let local_addr = SocketAddr::new(local_ip, raw.local_port);
        let remote_addr = SocketAddr::new(remote_ip, raw.remote_port);

        let state = TcpState::from_u8(raw.state);

        let pid = inode_map.get(&raw.inode).copied();
        let process_name = pid.and_then(procfs::get_process_name).or_else(|| {
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
        let direction = classify_direction(
            local_addr,
            remote_addr,
            state,
            protocol,
            &listening_ports,
        );

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

// ─── Helpers ────────────────────────────────────────────────────────

/// Convert a u128 (as stored by procfs parser) into an IpAddr.
fn u128_to_ip(addr: u128, is_ipv6: bool) -> IpAddr {
    if !is_ipv6 && addr <= u32::MAX as u128 {
        IpAddr::V4(Ipv4Addr::from(addr as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(addr))
    }
}

/// Classify connection direction using the listening port set as ground truth.
///
/// Logic:
///   1. Remote is loopback/unspecified/self → Local
///   2. TCP LISTEN or UDP bound (remote 0:0) → Inbound (server socket)
///   3. SYN_SENT → Outbound (we sent the SYN, definitive)
///   4. SYN_RECV → Inbound (we received a SYN, definitive)
///   5. Everything else: if our local port is a listening port → Inbound
///      (someone connected to our server), otherwise → Outbound
///      (we initiated it — our local port is ephemeral)
///
/// This catches ALL outbound connections regardless of port numbers,
/// protocols, or whether the remote is public/private/LAN/VPN/container.
fn classify_direction(
    local: SocketAddr,
    remote: SocketAddr,
    state: TcpState,
    protocol: Protocol,
    listening_ports: &HashSet<u16>,
) -> Direction {
    let remote_ip = remote.ip();

    // ── Local: loopback, unspecified, or talking to self ─────────
    if remote_ip.is_loopback() || remote_ip.is_unspecified() {
        return Direction::Local;
    }
    if remote_ip == local.ip() {
        return Direction::Local;
    }

    // ── TCP LISTEN → Inbound server socket ──────────────────────
    if state == TcpState::Listen {
        return Direction::Inbound;
    }

    // ── UDP bound socket (remote 0.0.0.0:0) → Inbound/listening ─
    if protocol == Protocol::Udp
        && remote.port() == 0
        && (remote_ip.is_unspecified() || remote_ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    {
        return Direction::Inbound;
    }

    // ── SYN_SENT/SYN_RECV are definitive ────────────────────────
    if state == TcpState::SynSent {
        return Direction::Outbound;
    }
    if state == TcpState::SynRecv {
        return Direction::Inbound;
    }

    // ── For everything else: check if our local port is listening ─
    // If we have a server on this port, someone connected to us.
    // If not, we opened this connection ourselves.
    if listening_ports.contains(&local.port()) {
        Direction::Inbound
    } else {
        Direction::Outbound
    }
}

/// Map a UID to a username by reading /etc/passwd.
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
    Some(format!("uid:{}", uid))
}
