//! /proc filesystem parsing (Linux-specific).
//!
//! All functions return empty/default data when /proc is unavailable (e.g. on
//! Windows or macOS), so the project compiles and runs everywhere while only
//! producing real data on Linux.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ─── RawSocket ──────────────────────────────────────────────────────
/// A single row from /proc/net/tcp{,6} or /proc/net/udp{,6}.
#[derive(Clone, Debug)]
pub struct RawSocket {
    pub local_addr: u128,
    pub local_port: u16,
    pub remote_addr: u128,
    pub remote_port: u16,
    pub state: u8,
    pub inode: u64,
    /// Transmit queue size in bytes (from tx_queue:rx_queue field).
    pub tx_queue: u32,
    /// Receive queue size in bytes.
    pub rx_queue: u32,
    /// Retransmit count.
    pub retransmits: u32,
    /// UID of socket owner.
    pub uid: u32,
}

// ─── Auto-discovery of ALL socket files in /proc/net/ ────────────────

/// Scan `/proc/net/` and parse EVERY file that has the kernel socket table
/// format (header starting with "sl").  Returns `(RawSocket, protocol_name)`
/// pairs — no hardcoded file list, nothing escapes.
///
/// Covers: tcp, tcp6, udp, udp6, icmp, icmp6, raw, raw6, udplite, udplite6,
/// and any future protocol the kernel adds.
pub fn parse_all_proc_net_sockets() -> Vec<(RawSocket, String)> {
    let net_dir = Path::new("/proc/net");
    if !net_dir.exists() {
        return Vec::new();
    }

    let entries = match fs::read_dir(net_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let name = fname.to_string_lossy().to_string();

        // Skip non-socket files (dev, route, arp, snmp, netstat, etc.)
        // Socket files have a header line starting with "sl" or "  sl"
        let path = entry.path();
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Check if first line looks like a socket table header
        let first_line = match content.lines().next() {
            Some(l) => l.trim(),
            None => continue,
        };
        if !first_line.starts_with("sl") {
            continue;
        }

        // Determine if IPv6 from filename (ends with "6")
        let is_v6 = name.ends_with('6');

        // Derive the base protocol name (strip trailing "6")
        let proto_name = if is_v6 {
            name[..name.len() - 1].to_string()
        } else {
            name.clone()
        };

        // Parse all socket rows
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let (local_addr, local_port) = match parse_addr_port(fields[1], is_v6) {
                Some(v) => v,
                None => continue,
            };
            let (remote_addr, remote_port) = match parse_addr_port(fields[2], is_v6) {
                Some(v) => v,
                None => continue,
            };
            let state = u8::from_str_radix(fields[3], 16).unwrap_or(0);
            let inode = fields[9].parse::<u64>().unwrap_or(0);
            let (tx_queue, rx_queue) = parse_queue_pair(fields[4]);
            let retransmits = fields[6].parse::<u32>().unwrap_or(0);
            let uid = fields[7].parse::<u32>().unwrap_or(0);

            results.push((
                RawSocket {
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    state,
                    inode,
                    tx_queue,
                    rx_queue,
                    retransmits,
                    uid,
                },
                proto_name.clone(),
            ));
        }
    }

    results
}

/// Parse "HEX:HEX" tx_queue:rx_queue pair.
fn parse_queue_pair(s: &str) -> (u32, u32) {
    let mut parts = s.split(':');
    let tx = parts
        .next()
        .and_then(|h| u32::from_str_radix(h, 16).ok())
        .unwrap_or(0);
    let rx = parts
        .next()
        .and_then(|h| u32::from_str_radix(h, 16).ok())
        .unwrap_or(0);
    (tx, rx)
}

/// Parse "HEXADDR:HEXPORT" into (u128, u16).
/// For IPv4, the hex is 8 chars (little-endian u32 stored in u128).
/// For IPv6, the hex is 32 chars (four little-endian u32 groups).
fn parse_addr_port(s: &str, ipv6: bool) -> Option<(u128, u16)> {
    let mut parts = s.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    let addr: u128 = if ipv6 {
        // 32 hex chars = 4 groups of 8 hex chars, each little-endian u32
        if addr_hex.len() != 32 {
            return None;
        }
        let a = u32::from_str_radix(&addr_hex[0..8], 16).ok()?.swap_bytes();
        let b = u32::from_str_radix(&addr_hex[8..16], 16).ok()?.swap_bytes();
        let c = u32::from_str_radix(&addr_hex[16..24], 16).ok()?.swap_bytes();
        let d = u32::from_str_radix(&addr_hex[24..32], 16).ok()?.swap_bytes();
        ((a as u128) << 96) | ((b as u128) << 64) | ((c as u128) << 32) | (d as u128)
    } else {
        // 8 hex chars, little-endian u32
        if addr_hex.len() != 8 {
            return None;
        }
        let v = u32::from_str_radix(addr_hex, 16).ok()?.swap_bytes();
        v as u128
    };

    Some((addr, port))
}

// ─── /proc/net/dev ──────────────────────────────────────────────────

/// Parse `/proc/net/dev` and return `(iface_name, rx_bytes, tx_bytes)` tuples.
pub fn parse_proc_net_dev() -> Vec<(String, u64, u64)> {
    let content = match fs::read_to_string("/proc/net/dev") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    // First two lines are headers
    for line in content.lines().skip(2) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // "eth0: 123456 ... 789012 ..."
        let mut parts = line.splitn(2, ':');
        let iface = match parts.next() {
            Some(s) => s.trim().to_string(),
            None => continue,
        };
        let rest = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        let nums: Vec<&str> = rest.split_whitespace().collect();
        // nums[0] = rx_bytes, nums[8] = tx_bytes
        if nums.len() < 10 {
            continue;
        }
        let rx = nums[0].parse::<u64>().unwrap_or(0);
        let tx = nums[8].parse::<u64>().unwrap_or(0);
        results.push((iface, rx, tx));
    }
    results
}

// ─── Process info from /proc/{pid}/ ─────────────────────────────────

/// Read `/proc/{pid}/comm` to get the process name (trimmed).
pub fn get_process_name(pid: u32) -> Option<String> {
    // Try /proc/comm first
    let comm_path = format!("/proc/{}/comm", pid);
    let comm = fs::read_to_string(comm_path).ok().map(|s| s.trim().to_string());
    
    // If comm is a single char, digit, or empty — fall back to cmdline
    if let Some(ref name) = comm {
        if name.len() <= 1 || name.chars().all(|c| c.is_ascii_digit()) || name == "exe" {
            // comm is useless (e.g., "1" from memfd processes), try cmdline
            if let Some(cmdline) = get_process_cmdline(pid) {
                // Extract binary name from first arg
                let first_arg = cmdline.split_whitespace().next().unwrap_or("");
                let binary = first_arg.rsplit('/').next().unwrap_or(first_arg);
                if !binary.is_empty() && binary.len() > 1 {
                    return Some(binary.to_string());
                }
            }
            // Try exe symlink as last resort
            let exe_path = format!("/proc/{}/exe", pid);
            if let Ok(target) = fs::read_link(exe_path) {
                let exe_name = target.to_string_lossy();
                // Handle memfd: (deleted) executables
                if exe_name.contains("memfd:") || exe_name.contains("(deleted)") {
                    let name = exe_name.replace(" (deleted)", "").replace("memfd:", "");
                    if !name.is_empty() {
                        return Some(format!("[memfd:{}]", name.trim_start_matches('/')));
                    }
                }
                let binary = exe_name.rsplit('/').next().unwrap_or("").to_string();
                if !binary.is_empty() {
                    return Some(binary);
                }
            }
        }
    }
    comm
}

/// Read `/proc/{pid}/cmdline` (null-separated) and return as a space-separated string.
pub fn get_process_cmdline(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let raw = fs::read(path).ok()?;
    if raw.is_empty() {
        return None;
    }
    let cmdline = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect::<Vec<_>>()
        .join(" ");
    if cmdline.is_empty() {
        None
    } else {
        Some(cmdline)
    }
}

/// Read `/proc/{pid}/status` and extract the real UID from the `Uid:` line.
pub fn get_process_uid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if line.starts_with("Uid:") {
            // "Uid:\treal\teffective\tsaved\tfs"
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                return fields[1].parse::<u32>().ok();
            }
        }
    }
    None
}

// ─── Inode → PID map ────────────────────────────────────────────────

/// Scan `/proc/*/fd/*` symlinks to build a map from socket inode → PID.
///
/// Each fd symlink target for a socket looks like `socket:[12345]`.
/// This is an expensive operation; call it once per collection cycle.
pub fn build_inode_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();

    let proc_dir = Path::new("/proc");
    if !proc_dir.exists() {
        return map;
    }

    let entries = match fs::read_dir(proc_dir) {
        Ok(e) => e,
        Err(_) => return map,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Only numeric directory names (PIDs)
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = entry.path().join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(f) => f,
            Err(_) => continue, // permission denied is common
        };

        for fd_entry in fds.flatten() {
            let link = match fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let link_str = link.to_string_lossy().to_string();
            // socket:[12345]
            if let Some(rest) = link_str.strip_prefix("socket:[") {
                if let Some(inode_str) = rest.strip_suffix(']') {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        map.insert(inode, pid);
                    }
                }
            }
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_addr_port_v4() {
        // 127.0.0.1:22 → hex little-endian = 0100007F:0016
        let result = parse_addr_port("0100007F:0016", false);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        assert_eq!(port, 22);
        // 0x0100007F byte-swapped = 0x7F000001 = 127.0.0.1
        assert_eq!(addr, 0x7F000001);
    }

    #[test]
    fn test_empty_on_missing_proc() {
        // On Windows (or any non-Linux), these should return empty
        if !Path::new("/proc/net/tcp").exists() {
            assert!(parse_proc_net_tcp(false).is_empty());
            assert!(parse_proc_net_udp(false).is_empty());
            assert!(parse_proc_net_dev().is_empty());
            assert!(build_inode_pid_map().is_empty());
        }
    }
}
