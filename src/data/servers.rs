//! Basic server fingerprinting — detect services on listening ports via
//! process names, banner probing, and version extraction.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::data::ListeningPort;

// ─── Data types ─────────────────────────────────────────────────────

/// Category of detected server/service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServerCategory {
    WebServer,
    Database,
    AppRuntime,
    Infrastructure,
    System,
    Other,
}

impl ServerCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::WebServer => "Web Server",
            Self::Database => "Database",
            Self::AppRuntime => "App Runtime",
            Self::Infrastructure => "Infrastructure",
            Self::System => "System",
            Self::Other => "Other",
        }
    }
}

/// Information about a detected server/service on a listening port.
#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub port: u16,
    pub service_name: String,
    pub technology: String,
    pub version: Option<String>,
    pub category: ServerCategory,
}

// ─── Known process -> service mapping ───────────────────────────────

struct ProcessSignature {
    /// Substring to match against the process name (lowercase).
    pattern: &'static str,
    /// Human-readable service name.
    service: &'static str,
    /// Technology / runtime.
    technology: &'static str,
    category: ServerCategory,
}

const KNOWN_PROCESSES: &[ProcessSignature] = &[
    ProcessSignature { pattern: "nginx",          service: "Nginx",       technology: "Nginx",       category: ServerCategory::WebServer },
    ProcessSignature { pattern: "caddy",          service: "Caddy",       technology: "Caddy",       category: ServerCategory::WebServer },
    ProcessSignature { pattern: "apache2",        service: "Apache",      technology: "Apache",      category: ServerCategory::WebServer },
    ProcessSignature { pattern: "httpd",          service: "Apache",      technology: "Apache",      category: ServerCategory::WebServer },
    ProcessSignature { pattern: "lighttpd",       service: "Lighttpd",    technology: "Lighttpd",    category: ServerCategory::WebServer },
    ProcessSignature { pattern: "haproxy",        service: "HAProxy",     technology: "HAProxy",     category: ServerCategory::WebServer },
    ProcessSignature { pattern: "traefik",        service: "Traefik",     technology: "Traefik",     category: ServerCategory::WebServer },
    ProcessSignature { pattern: "postgres",       service: "PostgreSQL",  technology: "PostgreSQL",  category: ServerCategory::Database },
    ProcessSignature { pattern: "mysqld",         service: "MySQL",       technology: "MySQL",       category: ServerCategory::Database },
    ProcessSignature { pattern: "mariadbd",       service: "MariaDB",     technology: "MariaDB",     category: ServerCategory::Database },
    ProcessSignature { pattern: "redis-server",   service: "Redis",       technology: "Redis",       category: ServerCategory::Database },
    ProcessSignature { pattern: "mongod",         service: "MongoDB",     technology: "MongoDB",     category: ServerCategory::Database },
    ProcessSignature { pattern: "mongos",         service: "MongoDB",     technology: "MongoDB",     category: ServerCategory::Database },
    ProcessSignature { pattern: "memcached",      service: "Memcached",   technology: "Memcached",   category: ServerCategory::Database },
    ProcessSignature { pattern: "cockroach",      service: "CockroachDB", technology: "CockroachDB", category: ServerCategory::Database },
    ProcessSignature { pattern: "clickhouse",     service: "ClickHouse",  technology: "ClickHouse",  category: ServerCategory::Database },
    ProcessSignature { pattern: "node",           service: "Node.js",     technology: "Node.js",     category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "deno",           service: "Deno",        technology: "Deno",        category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "bun",            service: "Bun",         technology: "Bun",         category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "python",         service: "Python",      technology: "Python",      category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "uvicorn",        service: "Uvicorn",     technology: "Python",      category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "gunicorn",       service: "Gunicorn",    technology: "Python",      category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "java",           service: "Java",        technology: "Java/JVM",    category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "dotnet",         service: ".NET",        technology: ".NET",        category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "php-fpm",        service: "PHP-FPM",     technology: "PHP",         category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "ruby",           service: "Ruby",        technology: "Ruby",        category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "puma",           service: "Puma",        technology: "Ruby",        category: ServerCategory::AppRuntime },
    ProcessSignature { pattern: "sshd",           service: "OpenSSH",     technology: "OpenSSH",     category: ServerCategory::System },
    ProcessSignature { pattern: "systemd-resolve",service: "systemd-resolved", technology: "systemd", category: ServerCategory::System },
    ProcessSignature { pattern: "named",          service: "BIND",        technology: "BIND",        category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "unbound",        service: "Unbound",     technology: "Unbound",     category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "dnsmasq",        service: "dnsmasq",     technology: "dnsmasq",     category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "dockerd",        service: "Docker",      technology: "Docker",      category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "containerd",     service: "containerd",  technology: "containerd",  category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "etcd",           service: "etcd",        technology: "etcd",        category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "consul",         service: "Consul",      technology: "HashiCorp",   category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "vault",          service: "Vault",       technology: "HashiCorp",   category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "prometheus",     service: "Prometheus",  technology: "Prometheus",   category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "grafana",        service: "Grafana",     technology: "Grafana",     category: ServerCategory::Infrastructure },
    ProcessSignature { pattern: "cloudflared",    service: "cloudflared", technology: "Cloudflare",  category: ServerCategory::Infrastructure },
];

// ─── Main detection entry point ─────────────────────────────────────

/// Detect servers/services on all listening ports.
/// Uses a three-stage approach:
/// 1. Process name matching against known signatures
/// 2. Banner probing on localhost (TCP connect + read)
/// 3. Version extraction from /proc/{pid}/cmdline
pub fn detect_servers(ports: &[ListeningPort]) -> Vec<ServerInfo> {
    let mut results: Vec<ServerInfo> = Vec::with_capacity(ports.len());
    // Deduplicate by port number (in case TCP+UDP both listen)
    let mut seen_ports = std::collections::HashSet::new();

    for lp in ports {
        if !seen_ports.insert(lp.port) {
            continue;
        }

        let proc_lower = lp.process_name.to_lowercase();

        // Stage 1: Process name matching
        if let Some(sig) = KNOWN_PROCESSES.iter().find(|s| proc_lower.contains(s.pattern)) {
            let version = extract_version_from_cmdline(lp.pid)
                .or_else(|| probe_version(lp.port, sig.pattern));

            let service_name = match &version {
                Some(v) => format!("{} {}", sig.service, v),
                None => sig.service.to_string(),
            };

            results.push(ServerInfo {
                port: lp.port,
                service_name,
                technology: sig.technology.to_string(),
                version,
                category: sig.category,
            });
            continue;
        }

        // Stage 2: Banner probing for unrecognized processes
        if let Some(info) = probe_banner(lp.port) {
            results.push(info);
            continue;
        }

        // Stage 3: Fallback -- use process name as-is
        if proc_lower != "<unknown>" {
            results.push(ServerInfo {
                port: lp.port,
                service_name: lp.process_name.clone(),
                technology: lp.process_name.clone(),
                version: None,
                category: ServerCategory::Other,
            });
        }
    }

    results.sort_by_key(|s| s.port);
    results
}

// ─── Version extraction from /proc/{pid}/cmdline ────────────────────

fn extract_version_from_cmdline(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let path = format!("/proc/{}/cmdline", pid);
    let data = std::fs::read(&path).ok()?;
    // cmdline is NUL-separated
    let cmdline = String::from_utf8_lossy(&data);
    let args: Vec<&str> = cmdline.split('\0').collect();

    // Look for --version= flags with version-like values
    for arg in &args {
        if let Some(ver) = arg.strip_prefix("--version=") {
            return Some(ver.to_string());
        }
    }

    // Try to extract version from binary path (e.g., /usr/lib/postgresql/16/bin/postgres)
    for arg in &args {
        if let Some(captures) = extract_version_pattern(arg) {
            return Some(captures);
        }
    }

    None
}

/// Extract a version-like pattern (e.g., "16", "1.24.0", "9.6p1") from a string.
fn extract_version_pattern(s: &str) -> Option<String> {
    // Match patterns like /16/ or /1.24/ in paths
    let parts: Vec<&str> = s.split('/').collect();
    for part in &parts {
        if part.is_empty() {
            continue;
        }
        let first_char = part.chars().next()?;
        if first_char.is_ascii_digit() {
            // Looks like a version segment in a path
            let trimmed = part.trim();
            if trimmed.len() <= 20
                && trimmed
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == 'p')
            {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

// ─── Banner probing ─────────────────────────────────────────────────

/// Attempt banner probing on localhost for a specific port.
fn probe_banner(port: u16) -> Option<ServerInfo> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let timeout = Duration::from_millis(500);

    // Try reading a banner first (SSH, SMTP, etc. send data immediately)
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) {
        stream.set_read_timeout(Some(timeout)).ok()?;
        let mut buf = [0u8; 4096];
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                let banner = String::from_utf8_lossy(&buf[..n]);
                if let Some(info) = parse_banner(&banner, port) {
                    return Some(info);
                }
            }
        }
    }

    // If no immediate banner, try an HTTP probe
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) {
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;
        let request = format!(
            "GET / HTTP/1.0\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            port
        );
        if stream.write_all(request.as_bytes()).is_ok() {
            let mut response = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                response.extend_from_slice(&chunk[..n]);
                if response.len() > 8192 {
                    break;
                }
            }
            let resp_str = String::from_utf8_lossy(&response);
            if let Some(info) = parse_http_server_header(&resp_str, port) {
                return Some(info);
            }
        }
    }

    // Try Redis PING
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) {
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;
        if stream.write_all(b"PING\r\n").is_ok() {
            let mut buf = [0u8; 256];
            if let Ok(n) = stream.read(&mut buf) {
                let resp = String::from_utf8_lossy(&buf[..n]);
                if resp.contains("+PONG") {
                    return Some(ServerInfo {
                        port,
                        service_name: "Redis".to_string(),
                        technology: "Redis".to_string(),
                        version: None,
                        category: ServerCategory::Database,
                    });
                }
            }
        }
    }

    None
}

/// Probe for version using banner methods, given a known service type.
fn probe_version(port: u16, service_hint: &str) -> Option<String> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let timeout = Duration::from_millis(500);

    match service_hint {
        "sshd" => {
            // SSH servers send banner immediately
            let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
            stream.set_read_timeout(Some(timeout)).ok()?;
            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf).ok()?;
            let banner = String::from_utf8_lossy(&buf[..n]);
            // Parse "SSH-2.0-OpenSSH_9.6p1 ..."
            if let Some(rest) = banner.strip_prefix("SSH-2.0-OpenSSH_") {
                let version = rest.split_whitespace().next()?;
                return Some(version.to_string());
            }
            None
        }
        "nginx" | "caddy" | "apache2" | "httpd" | "lighttpd" | "haproxy" | "traefik" => {
            // HTTP Server header
            let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
            stream.set_read_timeout(Some(timeout)).ok()?;
            stream.set_write_timeout(Some(timeout)).ok()?;
            let req = format!(
                "HEAD / HTTP/1.0\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                port
            );
            stream.write_all(req.as_bytes()).ok()?;
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).ok()?;
            let resp = String::from_utf8_lossy(&buf[..n]);
            // Find Server: header
            for line in resp.lines() {
                let lower = line.to_lowercase();
                if lower.starts_with("server:") {
                    let value = line[7..].trim();
                    // Extract version: "nginx/1.24.0" -> "1.24.0"
                    if let Some(pos) = value.find('/') {
                        return Some(value[pos + 1..].trim().to_string());
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Parse an immediate TCP banner (SSH, SMTP, FTP, etc.)
fn parse_banner(banner: &str, port: u16) -> Option<ServerInfo> {
    let trimmed = banner.trim();

    // SSH banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    if trimmed.starts_with("SSH-") {
        let version = trimmed
            .strip_prefix("SSH-2.0-OpenSSH_")
            .and_then(|rest| rest.split_whitespace().next())
            .map(|v| v.to_string());
        let service_name = match &version {
            Some(v) => format!("OpenSSH {}", v),
            None => "OpenSSH".to_string(),
        };
        return Some(ServerInfo {
            port,
            service_name,
            technology: "OpenSSH".to_string(),
            version,
            category: ServerCategory::System,
        });
    }

    // SMTP banner: "220 hostname ESMTP Postfix"
    if trimmed.starts_with("220 ") {
        let tech = if trimmed.contains("Postfix") {
            "Postfix"
        } else if trimmed.contains("Exim") {
            "Exim"
        } else {
            "SMTP"
        };
        return Some(ServerInfo {
            port,
            service_name: format!("{} SMTP", tech),
            technology: tech.to_string(),
            version: None,
            category: ServerCategory::Infrastructure,
        });
    }

    // FTP banner: "220 ProFTPD ..."
    if trimmed.contains("FTP") || trimmed.contains("ftp") {
        return Some(ServerInfo {
            port,
            service_name: "FTP Server".to_string(),
            technology: "FTP".to_string(),
            version: None,
            category: ServerCategory::Infrastructure,
        });
    }

    // MySQL greeting (binary, but starts with a version string after length prefix)
    // The greeting packet contains version as a null-terminated string starting at byte 5
    if banner.len() > 5 && banner.as_bytes().get(4) == Some(&0x0a) {
        // Likely MySQL greeting protocol v10
        let version_bytes = &banner.as_bytes()[5..];
        if let Some(null_pos) = version_bytes.iter().position(|&b| b == 0) {
            let version = String::from_utf8_lossy(&version_bytes[..null_pos]).to_string();
            if version
                .chars()
                .next()
                .map_or(false, |c| c.is_ascii_digit())
            {
                return Some(ServerInfo {
                    port,
                    service_name: format!("MySQL {}", version),
                    technology: "MySQL".to_string(),
                    version: Some(version),
                    category: ServerCategory::Database,
                });
            }
        }
    }

    None
}

/// Extract Server header from HTTP response.
fn parse_http_server_header(response: &str, port: u16) -> Option<ServerInfo> {
    if !response.starts_with("HTTP/") {
        return None;
    }

    for line in response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            let value = line[7..].trim().to_string();
            let (technology, version) = parse_server_value(&value);
            let service_name = value.clone();
            return Some(ServerInfo {
                port,
                service_name,
                technology,
                version,
                category: ServerCategory::WebServer,
            });
        }
    }

    // HTTP response but no Server header -- still a web server
    Some(ServerInfo {
        port,
        service_name: "HTTP Server".to_string(),
        technology: "HTTP".to_string(),
        version: None,
        category: ServerCategory::WebServer,
    })
}

/// Parse a Server header value like "nginx/1.24.0" or "Caddy" into
/// (technology, optional version).
fn parse_server_value(value: &str) -> (String, Option<String>) {
    if let Some(pos) = value.find('/') {
        let tech = value[..pos].trim().to_string();
        let version = value[pos + 1..]
            .split_whitespace()
            .next()
            .map(|v| v.to_string());
        (tech, version)
    } else {
        (
            value
                .split_whitespace()
                .next()
                .unwrap_or(value)
                .to_string(),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_banner() {
        let info =
            parse_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", 22).unwrap();
        assert_eq!(info.service_name, "OpenSSH 9.6p1");
        assert_eq!(info.version.as_deref(), Some("9.6p1"));
        assert_eq!(info.category, ServerCategory::System);
    }

    #[test]
    fn test_parse_smtp_banner() {
        let info = parse_banner("220 mail.example.com ESMTP Postfix\r\n", 25).unwrap();
        assert!(info.service_name.contains("Postfix"));
        assert_eq!(info.category, ServerCategory::Infrastructure);
    }

    #[test]
    fn test_parse_server_value() {
        let (tech, ver) = parse_server_value("nginx/1.24.0");
        assert_eq!(tech, "nginx");
        assert_eq!(ver.as_deref(), Some("1.24.0"));

        let (tech, ver) = parse_server_value("Caddy");
        assert_eq!(tech, "Caddy");
        assert!(ver.is_none());
    }

    #[test]
    fn test_version_pattern_extraction() {
        assert_eq!(
            extract_version_pattern("/usr/lib/postgresql/16/bin/postgres"),
            Some("16".to_string())
        );
        assert_eq!(extract_version_pattern("/usr/sbin/nginx"), None);
    }
}
