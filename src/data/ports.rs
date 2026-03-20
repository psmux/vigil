//! Listening port analysis — discovery, risk classification, and auth detection.

use std::net::IpAddr;

use crate::data::*;

/// Filter connections in LISTEN state and build ListeningPort entries.
/// `connections` should come from `connections::collect_connections()`.
pub fn collect_listening_ports(connections: &[Connection]) -> Vec<ListeningPort> {
    use std::collections::HashMap;

    // First pass: find all listening sockets
    // Use (port, proto_discriminant) as key since Protocol doesn't derive Hash
    let proto_disc = |p: Protocol| -> u8 {
        match p {
            Protocol::Tcp => 0,
            Protocol::Udp => 1,
        }
    };
    let mut listeners: HashMap<(u16, u8), &Connection> = HashMap::new();
    for c in connections {
        if c.state == TcpState::Listen {
            listeners
                .entry((c.local_addr.port(), proto_disc(c.protocol)))
                .or_insert(c);
        }
    }

    // Second pass: count established connections per port
    let mut conn_counts: HashMap<u16, u32> = HashMap::new();
    for c in connections {
        if c.state == TcpState::Established {
            *conn_counts.entry(c.local_addr.port()).or_insert(0) += 1;
        }
    }

    let mut ports: Vec<ListeningPort> = Vec::new();

    for (&(port, protocol), listener) in &listeners {
        let bind_addr = listener.local_addr.ip();
        let process = listener
            .process_name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        let user = listener
            .user
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());

        let risk = classify_risk(port, bind_addr, &process, &[]);
        let auth = detect_auth(port, &process);
        let conn_count = conn_counts.get(&port).copied().unwrap_or(0);

        ports.push(ListeningPort {
            port,
            bind_addr,
            protocol,
            pid: listener.pid.unwrap_or(0),
            process_name: process,
            user,
            conn_count,
            bandwidth_bps: 0.0, // TODO: per-port bandwidth tracking
            risk,
            auth,
        });
    }

    // Sort by port number
    ports.sort_by_key(|p| p.port);
    ports
}

/// Classify the risk level of a listening port.
///
/// - **Critical**: dangerous service exposed on 0.0.0.0 with no firewall rule
/// - **Exposed**: bound to 0.0.0.0 (all interfaces)
/// - **Safe**: bound to 127.0.0.1, or has an explicit firewall rule
pub fn classify_risk(
    port: u16,
    bind_addr: IpAddr,
    process: &str,
    firewall_rules: &[FirewallRule],
) -> PortRisk {
    let is_wildcard = match bind_addr {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    };

    // Bound to localhost only → safe
    if !is_wildcard {
        return PortRisk::Safe;
    }

    // Check if there's an explicit firewall rule for this port
    let has_rule = firewall_rules.iter().any(|r| r.port == Some(port));

    if is_dangerous_service(process) && !has_rule {
        return PortRisk::Critical;
    }

    if is_wildcard && !has_rule {
        return PortRisk::Exposed;
    }

    PortRisk::Safe
}

/// Heuristic auth detection based on port number and process name.
pub fn detect_auth(port: u16, process: &str) -> AuthMethod {
    let proc_lower = process.to_lowercase();

    // SSH daemon → key auth (typical for hardened servers)
    if proc_lower.contains("sshd") || port == 22 {
        return AuthMethod::KeyAuth;
    }

    // Database services → password auth
    if proc_lower.contains("postgres")
        || proc_lower.contains("mysql")
        || proc_lower.contains("mariadbd")
        || port == 5432
        || port == 3306
    {
        return AuthMethod::PasswordAuth;
    }

    // Redis on wildcard → likely no auth
    if proc_lower.contains("redis") {
        return AuthMethod::NoAuth;
    }

    // Memcached → typically no auth
    if proc_lower.contains("memcached") {
        return AuthMethod::NoAuth;
    }

    // MongoDB → mixed, but often no auth by default
    if proc_lower.contains("mongod") || port == 27017 {
        return AuthMethod::NoAuth;
    }

    // Elasticsearch
    if proc_lower.contains("elasticsearch") || proc_lower.contains("java") && port == 9200 {
        return AuthMethod::NoAuth;
    }

    // Node.js / Python / common web frameworks → unknown
    if proc_lower.contains("node")
        || proc_lower.contains("python")
        || proc_lower.contains("nginx")
        || proc_lower.contains("caddy")
    {
        return AuthMethod::Unknown;
    }

    // HTTPS ports → likely JWT or token auth
    if port == 443 || port == 8443 {
        return AuthMethod::JwtAuth;
    }

    AuthMethod::Unknown
}

/// Returns true if the process is a known-dangerous service that should
/// not be exposed on all interfaces without a firewall rule.
pub fn is_dangerous_service(process: &str) -> bool {
    let proc_lower = process.to_lowercase();
    const DANGEROUS: &[&str] = &[
        "redis-server",
        "redis",
        "mongod",
        "mongos",
        "memcached",
        "elasticsearch",
        "couchdb",
        "cassandra",
        "rethinkdb",
    ];
    DANGEROUS.iter().any(|d| proc_lower.contains(d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_classify_risk_localhost() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(classify_risk(6379, addr, "redis-server", &[]), PortRisk::Safe);
    }

    #[test]
    fn test_classify_risk_exposed_redis() {
        let addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            classify_risk(6379, addr, "redis-server", &[]),
            PortRisk::Critical
        );
    }

    #[test]
    fn test_detect_auth_sshd() {
        assert_eq!(detect_auth(22, "sshd"), AuthMethod::KeyAuth);
    }

    #[test]
    fn test_dangerous_services() {
        assert!(is_dangerous_service("redis-server"));
        assert!(is_dangerous_service("mongod"));
        assert!(!is_dangerous_service("nginx"));
    }
}
