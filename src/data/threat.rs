//! Threat IP checker — embeds the IPsum level-3 threat list at compile time.
//!
//! The threat_ips.txt file contains one IP per line sourced from
//! https://github.com/stamparm/ipsum (IPs reported by 3+ blacklists).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

/// Raw embedded threat-IP data (one IP per line, blank lines ignored).
static THREAT_DATA: &str = include_str!("../../assets/threat_ips.txt");

/// Lazily-initialized set of known-bad IPs.
static THREAT_SET: OnceLock<HashSet<IpAddr>> = OnceLock::new();

/// Initialize (or return) the threat IP set from embedded data.
fn init_threat_set() -> &'static HashSet<IpAddr> {
    THREAT_SET.get_or_init(|| {
        THREAT_DATA
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter_map(|l| l.trim().parse::<IpAddr>().ok())
            .collect()
    })
}

/// Check if an IP is in the known-threat set.
pub fn is_threat_ip(ip: &IpAddr) -> bool {
    init_threat_set().contains(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_set_loads() {
        let set = init_threat_set();
        // Should have thousands of entries from the IPsum list
        assert!(set.len() > 1000, "Expected >1000 threat IPs, got {}", set.len());
    }

    #[test]
    fn test_private_ip_not_threat() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!is_threat_ip(&ip));
    }
}
