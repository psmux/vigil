//! Threat IP checker — stub for IP reputation lookups.
//!
//! TODO: Embed a threat IP list at compile time:
//!   static THREAT_IPS_RAW: &str = include_str!("../../assets/threat_ips.txt");
//!
//! The threat_ips.txt file should contain one IP per line (comments with #).
//! Sources: abuse.ch, emerging threats, firehol blocklists.

use std::collections::HashSet;
use std::net::IpAddr;

/// Check if an IP is in the known-threat set.
///
/// Currently a stub that always returns false.
/// Will be replaced with a lookup into `init_threat_set()` once the
/// threat IP list is embedded.
pub fn is_threat_ip(_ip: &IpAddr) -> bool {
    // TODO: use a lazy_static or OnceLock with init_threat_set()
    false
}

/// Initialize the threat IP set from embedded data.
///
/// Currently returns an empty set (placeholder).
/// Future implementation will parse include_str!("../../assets/threat_ips.txt")
/// and populate the set.
pub fn init_threat_set() -> HashSet<IpAddr> {
    // TODO: parse threat_ips.txt lines into IpAddr
    //
    // Example future implementation:
    //
    //   THREAT_IPS_RAW
    //       .lines()
    //       .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    //       .filter_map(|l| l.trim().parse::<IpAddr>().ok())
    //       .collect()
    //
    HashSet::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_stub_returns_false() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(!is_threat_ip(&ip));
    }

    #[test]
    fn test_init_empty() {
        let set = init_threat_set();
        assert!(set.is_empty());
    }
}
