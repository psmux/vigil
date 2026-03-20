//! LAN device discovery via ARP cache and neighbor table.
//!
//! Reads /proc/net/arp and `ip neigh show` output to discover devices
//! on the local network. Also reads gateway and DNS server info.

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;

use chrono::{DateTime, Utc};

// ─── LAN device ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct LanDevice {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub is_online: bool,
    pub last_seen: DateTime<Utc>,
}

// ─── Neighbor discovery ────────────────────────────────────────────

/// Discover LAN neighbors by merging ARP cache and `ip neigh` output.
pub fn discover_neighbors() -> Vec<LanDevice> {
    let mut devices: HashMap<IpAddr, LanDevice> = HashMap::new();

    // Method 1: Read /proc/net/arp
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            // Format: IP address  HW type  Flags  HW address  Mask  Device
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                if let Ok(ip) = parts[0].parse::<IpAddr>() {
                    let mac = parts[3].to_string();
                    // Skip incomplete entries (00:00:00:00:00:00)
                    let mac_opt = if mac == "00:00:00:00:00:00" {
                        None
                    } else {
                        Some(mac)
                    };
                    // Flags field: 0x2 means complete/reachable
                    let flags = parts[2];
                    let is_online = flags != "0x0";

                    devices.entry(ip).or_insert_with(|| LanDevice {
                        ip,
                        mac: mac_opt,
                        hostname: None,
                        vendor: None,
                        is_online,
                        last_seen: Utc::now(),
                    });
                }
            }
        }
    }

    // Method 2: `ip neigh show` for more complete neighbor table
    if let Ok(output) = Command::new("ip").args(["neigh", "show"]).output() {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            for line in stdout.lines() {
                // Format: "IP dev IFACE lladdr MAC STATE"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }
                if let Ok(ip) = parts[0].parse::<IpAddr>() {
                    // Find lladdr if present
                    let mac_opt = parts.iter()
                        .position(|&p| p == "lladdr")
                        .and_then(|i| parts.get(i + 1))
                        .map(|s| s.to_string());

                    // Last token is the state
                    let state = parts.last().copied().unwrap_or("");
                    let is_online = matches!(state, "REACHABLE" | "STALE" | "DELAY" | "PROBE");

                    let entry = devices.entry(ip).or_insert_with(|| LanDevice {
                        ip,
                        mac: None,
                        hostname: None,
                        vendor: None,
                        is_online,
                        last_seen: Utc::now(),
                    });

                    // Prefer non-None MAC from ip neigh
                    if entry.mac.is_none() && mac_opt.is_some() {
                        entry.mac = mac_opt;
                    }
                    // Update online status -- ip neigh is more authoritative
                    entry.is_online = is_online;
                }
            }
        }
    }

    // Attempt reverse DNS for each device
    for device in devices.values_mut() {
        device.hostname = reverse_dns(device.ip);
        device.vendor = device.mac.as_ref().and_then(|m| oui_vendor(m));
    }

    let mut result: Vec<LanDevice> = devices.into_values().collect();
    result.sort_by(|a, b| {
        a.ip.to_string().cmp(&b.ip.to_string())
    });
    result
}

/// Try a reverse DNS lookup for an IP address.
fn reverse_dns(ip: IpAddr) -> Option<String> {
    let output = Command::new("host")
        .arg(ip.to_string())
        .output()
        .ok()?;

    let stdout = String::from_utf8(output.stdout).ok()?;
    // Output format: "X.X.X.X.in-addr.arpa domain name pointer hostname."
    if let Some(line) = stdout.lines().next() {
        if line.contains("domain name pointer") {
            let hostname = line.split("domain name pointer")
                .nth(1)?
                .trim()
                .trim_end_matches('.');
            if !hostname.is_empty() {
                return Some(hostname.to_string());
            }
        }
    }
    None
}

/// Look up a vendor prefix from a MAC address OUI (first 3 octets).
fn oui_vendor(mac: &str) -> Option<String> {
    let upper = mac.to_uppercase();
    if upper.len() < 8 { return None; }
    let prefix = &upper[..8];

    let vendor = match prefix {
        "00:50:56" | "00:0C:29" | "00:05:69" => "VMware",
        "08:00:27" => "VirtualBox",
        "52:54:00" | "FA:16:3E" => "KVM/QEMU",
        "02:42:AC" | "02:42:0A" => "Docker",
        "00:15:5D" => "Hyper-V",
        "00:16:3E" => "Xen",
        "B8:27:EB" | "DC:A6:32" | "E4:5F:01" => "Raspberry Pi",
        "00:1A:79" | "00:1E:67" | "00:23:AB" => "Cisco",
        "00:1B:44" | "18:E7:28" | "A0:36:9F" => "Cisco",
        "00:0E:C6" | "30:B5:C2" | "4C:5E:0C" => "MikroTik",
        "00:1F:33" | "24:A4:3C" | "80:2A:A8" => "Ubiquiti",
        "00:17:88" => "Philips Hue",
        "B0:BE:76" | "18:B4:30" => "Nest",
        "F0:B4:29" | "38:F7:3D" => "Amazon",
        "68:A3:78" | "70:EF:00" | "B0:34:95" => "Apple",
        "00:25:00" | "AC:9E:17" | "FC:F5:28" => "Apple",
        "98:D6:F7" | "00:A0:C9" | "3C:D9:2B" => "Intel",
        "00:26:B9" | "04:7D:7B" | "34:17:EB" => "Dell",
        "00:1C:C4" | "00:04:AC" | "00:1A:4B" => "HP",
        "00:E0:4C" | "52:54:AB" | "74:D0:2B" => "Realtek",
        "00:0F:00" | "D0:67:E5" | "2C:56:DC" => "TP-Link",
        "44:D9:E7" | "00:24:B2" | "FC:75:16" => "Netgear",
        "00:1D:7E" | "CC:B2:55" | "8C:3B:AD" => "Linksys",
        "C8:3A:35" | "BC:EE:7B" | "20:CF:30" => "ASUS",
        "00:24:D7" | "34:68:95" | "E4:F0:42" => "DigitalOcean",
        _ => return None,
    };
    Some(vendor.to_string())
}

// ─── Gateway detection ─────────────────────────────────────────────

/// Read the default gateway from /proc/net/route.
pub fn get_gateway() -> Option<IpAddr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        // Destination == 00000000 means default route
        if parts[1] == "00000000" {
            if let Ok(hex) = u32::from_str_radix(parts[2], 16) {
                let bytes = hex.to_le_bytes();
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ));
                return Some(ip);
            }
        }
    }
    None
}

// ─── DNS server detection ──────────────────────────────────────────

/// Read DNS servers from /etc/resolv.conf.
pub fn get_dns_servers() -> Vec<IpAddr> {
    let mut servers = Vec::new();

    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                if let Some(ip_str) = trimmed.split_whitespace().nth(1) {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        servers.push(ip);
                    }
                }
            }
        }
    }

    servers
}
