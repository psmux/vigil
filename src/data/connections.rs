//! Connection collector — full pipeline from /proc parsing to enriched Connection structs.
//!
//! Auto-discovers ALL socket files in /proc/net/ — tcp, udp, icmp, raw,
//! udplite, and any future protocol the kernel exposes.  Nothing escapes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::data::*;
use crate::data::procfs;
use crate::data::geoip;
use crate::data::threat;

/// Full collection pipeline:
/// 1. Auto-discover and parse ALL /proc/net/ socket files
/// 2. Build inode→pid map
/// 3. Construct enriched Connection structs
pub fn collect_connections() -> Vec<Connection> {
    let raw_sockets = procfs::parse_all_proc_net_sockets();
    let inode_map = procfs::build_inode_pid_map();
    let mut connections = Vec::with_capacity(raw_sockets.len());

    for (raw, proto_name) in raw_sockets {
        let is_v6 = raw.local_addr > u32::MAX as u128 || raw.remote_addr > u32::MAX as u128;
        let local_ip = u128_to_ip(raw.local_addr, is_v6);
        let remote_ip = u128_to_ip(raw.remote_addr, is_v6);

        let local_addr = SocketAddr::new(local_ip, raw.local_port);
        let remote_addr = SocketAddr::new(remote_ip, raw.remote_port);

        let state = TcpState::from_u8(raw.state);
        let protocol = protocol_from_name(&proto_name);

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
        let direction = classify_direction(remote_addr, state);

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
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            packet_count: 0,
            capture_source: CaptureSource::ProcFs,
        });
    }

    connections
}

// ─── Helpers ────────────────────────────────────────────────────────

fn u128_to_ip(addr: u128, is_ipv6: bool) -> IpAddr {
    if !is_ipv6 && addr <= u32::MAX as u128 {
        IpAddr::V4(Ipv4Addr::from(addr as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(addr))
    }
}

/// Map /proc/net/ filename to Protocol enum.
fn protocol_from_name(name: &str) -> Protocol {
    match name {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        _ => Protocol::Raw, // raw, udplite, sctp, anything else
    }
}

/// Direction: is the remote a different machine? Then outbound.
fn classify_direction(remote: SocketAddr, state: TcpState) -> Direction {
    let remote_ip = remote.ip();

    if remote_ip.is_unspecified() {
        return Direction::Local;
    }
    if remote_ip.is_loopback() {
        return Direction::Local;
    }
    if state == TcpState::Listen {
        return Direction::Inbound;
    }

    Direction::Outbound
}

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
