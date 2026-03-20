//! Firewall rule parser — reads ufw or iptables output and builds FirewallRule structs.

use crate::data::*;

/// Collect firewall information.
///
/// Returns `(rules, default_deny, is_active)`.
///
/// Tries `ufw status verbose` first, falls back to `iptables -L -n -v`.
/// On Windows / when neither is available, returns empty defaults.
pub fn collect_firewall_info() -> (Vec<FirewallRule>, bool, bool) {
    #[cfg(target_os = "linux")]
    {
        // Try ufw first
        if let Some(result) = try_parse_ufw() {
            return result;
        }

        // Fallback to iptables
        if let Some(result) = try_parse_iptables() {
            return result;
        }
    }

    // Non-Linux or both commands failed
    (Vec::new(), false, false)
}

/// Try to parse `ufw status verbose` output.
#[cfg(target_os = "linux")]
fn try_parse_ufw() -> Option<(Vec<FirewallRule>, bool, bool)> {
    use std::process::Command;

    let output = Command::new("ufw")
        .args(["status", "verbose"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("inactive") {
        return Some((Vec::new(), false, false));
    }

    let mut rules = Vec::new();
    let mut default_deny = false;
    let mut in_rules = false;
    let mut index = 0;

    for line in text.lines() {
        let line = line.trim();

        // Check default policy
        if line.starts_with("Default:") {
            if line.contains("deny (incoming)") || line.contains("reject (incoming)") {
                default_deny = true;
            }
        }

        // Rule header line
        if line.starts_with("--") {
            in_rules = true;
            continue;
        }

        if !in_rules || line.is_empty() {
            continue;
        }

        // Parse rule lines like:
        // "22/tcp                     ALLOW IN    Anywhere"
        // "80,443/tcp                 ALLOW IN    Anywhere"
        if let Some(rule) = parse_ufw_rule_line(line, index) {
            rules.push(rule);
            index += 1;
        }
    }

    Some((rules, default_deny, true))
}

/// Parse a single ufw rule line.
#[cfg(target_os = "linux")]
fn parse_ufw_rule_line(line: &str, index: usize) -> Option<FirewallRule> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // parts[0] = port/proto (e.g. "22/tcp", "80,443/tcp", "Anywhere")
    // parts[1] = action (ALLOW, DENY, REJECT)
    // parts[2] = direction (IN, OUT) — optional

    let action = match parts[1].to_uppercase().as_str() {
        "ALLOW" => FirewallAction::Allow,
        "DENY" => FirewallAction::Deny,
        "REJECT" => FirewallAction::Reject,
        _ => return None,
    };

    let direction = if parts.len() > 2 {
        match parts[2].to_uppercase().as_str() {
            "IN" => FirewallDirection::In,
            "OUT" => FirewallDirection::Out,
            _ => FirewallDirection::Both,
        }
    } else {
        FirewallDirection::Both
    };

    // Parse port/protocol
    let port_spec = parts[0];
    let (port, protocol) = if port_spec.contains('/') {
        let mut sp = port_spec.split('/');
        let port_str = sp.next().unwrap_or("0");
        let proto_str = sp.next().unwrap_or("");
        let port = port_str.split(',').next().and_then(|p| p.parse::<u16>().ok());
        let protocol = match proto_str {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            _ => None,
        };
        (port, protocol)
    } else {
        (None, None)
    };

    // Source: everything after the direction keyword
    let source = if parts.len() > 3 {
        Some(parts[3..].join(" "))
    } else {
        None
    };

    Some(FirewallRule {
        index,
        action,
        direction,
        port,
        protocol,
        source,
        comment: String::new(),
        hits: 0,
    })
}

/// Try to parse `iptables -L -n -v` output.
#[cfg(target_os = "linux")]
fn try_parse_iptables() -> Option<(Vec<FirewallRule>, bool, bool)> {
    use std::process::Command;

    let output = Command::new("iptables")
        .args(["-L", "-n", "-v"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut rules = Vec::new();
    let mut default_deny = false;
    let mut index = 0;

    for line in text.lines() {
        let line = line.trim();

        // Chain INPUT (policy DROP) → default deny
        if line.starts_with("Chain INPUT") && line.contains("DROP") {
            default_deny = true;
        }

        // Skip headers
        if line.starts_with("Chain") || line.starts_with("pkts") || line.is_empty() {
            continue;
        }

        // Parse iptables rule lines:
        // "pkts bytes target prot opt in out source destination [extra]"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let hits = parts[0].parse::<u64>().unwrap_or(0);
        let target = parts[2]; // ACCEPT, DROP, REJECT
        let prot = parts[3]; // tcp, udp, all
        let source = parts[7];

        let action = match target {
            "ACCEPT" => FirewallAction::Allow,
            "DROP" => FirewallAction::Deny,
            "REJECT" => FirewallAction::Reject,
            _ => continue,
        };

        let protocol = match prot {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            _ => None,
        };

        // Try to extract dpt: (destination port) from the extra info
        let port = parts[8..]
            .iter()
            .find_map(|p| {
                p.strip_prefix("dpt:").and_then(|s| s.parse::<u16>().ok())
            });

        let source = if source != "0.0.0.0/0" {
            Some(source.to_string())
        } else {
            None
        };

        rules.push(FirewallRule {
            index,
            action,
            direction: FirewallDirection::In,
            port,
            protocol,
            source,
            comment: String::new(),
            hits,
        });
        index += 1;
    }

    Some((rules, default_deny, true))
}

/// Calculate the percentage of listening ports that have at least one explicit
/// firewall rule (allow or deny).
pub fn firewall_coverage(rules: &[FirewallRule], ports: &[ListeningPort]) -> u8 {
    if ports.is_empty() {
        return 100; // no ports, nothing to protect
    }

    let covered = ports
        .iter()
        .filter(|p| rules.iter().any(|r| r.port == Some(p.port)))
        .count();

    ((covered as f64 / ports.len() as f64) * 100.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_firewall_coverage_empty() {
        assert_eq!(firewall_coverage(&[], &[]), 100);
    }

    #[test]
    fn test_firewall_coverage_partial() {
        let rules = vec![FirewallRule {
            index: 0,
            action: FirewallAction::Allow,
            direction: FirewallDirection::In,
            port: Some(22),
            protocol: Some(Protocol::Tcp),
            source: None,
            comment: String::new(),
            hits: 0,
        }];

        let ports = vec![
            ListeningPort {
                port: 22,
                bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                protocol: Protocol::Tcp,
                pid: 1,
                process_name: "sshd".to_string(),
                user: "root".to_string(),
                conn_count: 0,
                bandwidth_bps: 0.0,
                risk: PortRisk::Safe,
                auth: AuthMethod::KeyAuth,
            },
            ListeningPort {
                port: 80,
                bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                protocol: Protocol::Tcp,
                pid: 2,
                process_name: "nginx".to_string(),
                user: "www-data".to_string(),
                conn_count: 0,
                bandwidth_bps: 0.0,
                risk: PortRisk::Exposed,
                auth: AuthMethod::Unknown,
            },
        ];

        assert_eq!(firewall_coverage(&rules, &ports), 50);
    }
}
