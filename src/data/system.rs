//! System info collector — CPU, memory, disk, services, and network interfaces.
//!
//! Uses the `sysinfo` crate for cross-platform CPU/memory/disk data.
//! Service status and network interfaces use Linux-specific paths with fallbacks.

use crate::data::*;

/// System data collector backed by the sysinfo crate.
pub struct SystemCollector {
    sys: sysinfo::System,
}

impl SystemCollector {
    pub fn new() -> Self {
        let mut sys = sysinfo::System::new();
        sys.refresh_all();
        Self { sys }
    }

    /// Refresh system data and return (CpuInfo, MemoryInfo, Vec<DiskInfo>).
    pub fn refresh(&mut self) -> (CpuInfo, MemoryInfo, Vec<DiskInfo>) {
        self.sys.refresh_all();

        let cpu_info = self.collect_cpu();
        let mem_info = self.collect_memory();
        let disk_info = self.collect_disks();

        (cpu_info, mem_info, disk_info)
    }

    fn collect_cpu(&self) -> CpuInfo {
        let cores: Vec<CpuCore> = self
            .sys
            .cpus()
            .iter()
            .enumerate()
            .map(|(id, cpu)| CpuCore {
                id,
                usage_percent: cpu.cpu_usage(),
            })
            .collect();

        // Load averages (Linux only; returns (0,0,0) on other platforms)
        let load_avg = sysinfo::System::load_average();

        CpuInfo {
            cores,
            load_avg: (load_avg.one, load_avg.five, load_avg.fifteen),
        }
    }

    fn collect_memory(&self) -> MemoryInfo {
        MemoryInfo {
            total: self.sys.total_memory(),
            used: self.sys.used_memory(),
            swap_total: self.sys.total_swap(),
            swap_used: self.sys.used_swap(),
        }
    }

    fn collect_disks(&self) -> Vec<DiskInfo> {
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();
        disks
            .iter()
            .map(|d| DiskInfo {
                mount: d.mount_point().to_string_lossy().to_string(),
                total: d.total_space(),
                used: d.total_space().saturating_sub(d.available_space()),
            })
            .collect()
    }
}

impl Default for SystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if specific services are active via `systemctl is-active`.
///
/// Returns a ServiceStatus for each of the well-known services.
/// On non-Linux, all services report as inactive.
pub fn collect_services() -> Vec<ServiceStatus> {
    // (display_name, systemd_unit_candidates)
    // SSH is "ssh" on Debian/Ubuntu, "sshd" on RHEL/Fedora/Arch.
    const SERVICES: &[(&str, &[&str])] = &[
        ("postgresql", &["postgresql"]),
        ("ssh", &["ssh", "sshd"]),
        ("cloudflared", &["cloudflared"]),
        ("caddy", &["caddy"]),
        ("fail2ban", &["fail2ban"]),
        ("nginx", &["nginx"]),
    ];

    SERVICES
        .iter()
        .map(|&(display_name, candidates)| ServiceStatus {
            name: display_name.to_string(),
            active: candidates.iter().any(|&c| is_service_active(c)),
        })
        .collect()
}

/// Check if a single systemd service is active.
fn is_service_active(name: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        Command::new("systemctl")
            .args(["is-active", "--quiet", name])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        false
    }
}

/// Collect network interface information from /sys/class/net/.
///
/// Returns an empty vec on non-Linux platforms.
pub fn collect_interfaces() -> Vec<NetworkInterface> {
    #[cfg(target_os = "linux")]
    {
        collect_interfaces_linux()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Linux implementation: reads /sys/class/net/ for interface details.
#[cfg(target_os = "linux")]
fn collect_interfaces_linux() -> Vec<NetworkInterface> {
    use std::fs;
    use std::path::Path;

    let net_dir = Path::new("/sys/class/net");
    let entries = match fs::read_dir(net_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut interfaces = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let iface_path = entry.path();

        // Read operstate: "up", "down", or "unknown" (loopback uses "unknown")
        let operstate_path = iface_path.join("operstate");
        let operstate = fs::read_to_string(&operstate_path).unwrap_or_default();
        let state = operstate.trim();
        // "unknown" is returned by loopback (lo) — treat it as up
        let up = state == "up" || state == "unknown";

        // Read speed (Mbps) — may fail for virtual interfaces
        let speed_path = iface_path.join("speed");
        let speed_mbps = fs::read_to_string(&speed_path)
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .and_then(|s| if s > 0 { Some(s as u64) } else { None });

        // Get IP address via ip command (simpler than parsing /proc)
        let ip = get_interface_ip(&name).unwrap_or_default();

        interfaces.push(NetworkInterface {
            name,
            ip,
            speed_mbps,
            up,
        });
    }

    // Sort: physical interfaces first, then virtual
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

/// Get the primary IPv4 address for an interface using `ip addr show`.
#[cfg(target_os = "linux")]
fn get_interface_ip(iface: &str) -> Option<String> {
    use std::process::Command;

    let output = Command::new("ip")
        .args(["-4", "addr", "show", iface])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("inet ") {
            // "inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // Return IP without the CIDR prefix
                return Some(
                    parts[1]
                        .split('/')
                        .next()
                        .unwrap_or(parts[1])
                        .to_string(),
                );
            }
        }
    }

    None
}
