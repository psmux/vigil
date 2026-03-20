//! Attack log parser — tails auth.log or journalctl for SSH brute-force events.

use std::net::IpAddr;
use std::sync::mpsc;

use chrono::Utc;

use crate::data::{AttackEvent, AttackType, DataUpdate};

/// Background thread function that monitors auth logs for attack events.
///
/// Tries (in order):
/// 1. Tail `/var/log/auth.log`
/// 2. Fallback: `journalctl -u sshd -f --no-pager`
///
/// On Windows / when neither source is available, sleeps in a loop (graceful degradation).
pub fn attack_monitor_thread(tx: mpsc::Sender<DataUpdate>) {
    // Try auth.log first, then journalctl
    #[cfg(target_os = "linux")]
    {
        if let Err(_) = tail_auth_log(&tx) {
            let _ = tail_journalctl(&tx);
        }
    }

    // Fallback: graceful degradation — just keep the thread alive
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        if tx.send(DataUpdate::Attack(placeholder_event())).is_err() {
            break; // receiver dropped, main thread exited
        }
    }
}

/// Tail /var/log/auth.log and parse attack events.
#[cfg(target_os = "linux")]
fn tail_auth_log(tx: &mpsc::Sender<DataUpdate>) -> Result<(), ()> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let child = Command::new("tail")
        .args(["-F", "-n", "0", "/var/log/auth.log"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;

    let stdout = child.stdout.ok_or(())?;
    let reader = BufReader::new(stdout);

    for line in reader.lines().flatten() {
        if let Some(event) = parse_auth_line(&line) {
            if tx.send(DataUpdate::Attack(event)).is_err() {
                break;
            }
        }
    }

    Err(()) // stream ended
}

/// Fallback: tail journalctl for sshd events.
#[cfg(target_os = "linux")]
fn tail_journalctl(tx: &mpsc::Sender<DataUpdate>) -> Result<(), ()> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let child = Command::new("journalctl")
        .args(["-u", "sshd", "-f", "--no-pager", "-n", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;

    let stdout = child.stdout.ok_or(())?;
    let reader = BufReader::new(stdout);

    for line in reader.lines().flatten() {
        if let Some(event) = parse_auth_line(&line) {
            if tx.send(DataUpdate::Attack(event)).is_err() {
                break;
            }
        }
    }

    Err(())
}

/// Try to extract a timestamp from the log line.
///
/// Supports two formats:
/// 1. ISO 8601: "2026-03-20T14:51:57.937254+00:00 hostname sshd..."
/// 2. Traditional syslog: "Mar 15 10:23:01 hostname sshd..."
///
/// Falls back to Utc::now() if neither format is found.
fn parse_timestamp(line: &str) -> chrono::DateTime<Utc> {
    // Try ISO 8601 first — the line starts with a timestamp like
    // "2026-03-20T14:51:57.937254+00:00"
    if line.len() > 25 {
        let candidate = line.split_whitespace().next().unwrap_or("");
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(candidate) {
            return dt.with_timezone(&Utc);
        }
        // Some systems emit without the colon in the offset, e.g. +0000
        if let Ok(dt) = chrono::DateTime::parse_from_str(candidate, "%Y-%m-%dT%H:%M:%S%.f%z") {
            return dt.with_timezone(&Utc);
        }
    }

    // Try traditional syslog format: "Mar 15 10:23:01"
    // These don't include year, so we use the current year.
    if line.len() > 15 {
        let prefix = &line[..15];
        let year = Utc::now().format("%Y").to_string();
        let with_year = format!("{} {}", prefix, year);
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&with_year, "%b %e %H:%M:%S %Y") {
            return naive.and_utc();
        }
    }

    Utc::now()
}

/// Parse a single auth.log / journalctl line for attack indicators.
///
/// Patterns detected:
/// - "Failed password for <user> from <ip>"
/// - "Failed password for invalid user <user> from <ip>"
/// - "Invalid user <user> from <ip>"
/// - "Connection closed by authenticating user <user> <ip>"
fn parse_auth_line(line: &str) -> Option<AttackEvent> {
    let ip;
    let username;
    let attack_type;

    if line.contains("Failed password for") {
        // "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
        // "Failed password for root from 1.2.3.4 port 22 ssh2"
        attack_type = AttackType::SshBrute;
        let from_idx = line.find(" from ")?;
        let after_from = &line[from_idx + 6..];
        ip = after_from.split_whitespace().next()?;

        // Extract username
        if line.contains("invalid user") {
            let inv_idx = line.find("invalid user ")?;
            let after = &line[inv_idx + 13..];
            username = after.split_whitespace().next().map(|s| s.to_string());
        } else {
            let for_idx = line.find("for ")?;
            let after = &line[for_idx + 4..];
            username = after.split_whitespace().next().map(|s| s.to_string());
        }
    } else if line.contains("Invalid user") {
        // "Invalid user admin from 1.2.3.4 port 12345"
        attack_type = AttackType::SshBrute;
        let from_idx = line.find(" from ")?;
        let after_from = &line[from_idx + 6..];
        ip = after_from.split_whitespace().next()?;

        let user_idx = line.find("Invalid user ")?;
        let after = &line[user_idx + 13..];
        username = after.split_whitespace().next().map(|s| s.to_string());
    } else if line.contains("Connection closed by authenticating user") {
        // "Connection closed by authenticating user admin 1.2.3.4 port 22"
        attack_type = AttackType::SshBrute;
        let prefix = "Connection closed by authenticating user ";
        let idx = line.find(prefix)?;
        let after = &line[idx + prefix.len()..];
        let parts: Vec<&str> = after.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        username = Some(parts[0].to_string());
        ip = parts[1];
    } else {
        return None;
    }

    let source_ip: IpAddr = ip.parse().ok()?;

    let timestamp = parse_timestamp(line);

    Some(AttackEvent {
        timestamp,
        source_ip,
        attack_type,
        target_port: Some(22),
        username,
        count: 1,
    })
}

/// Create a no-op placeholder event (used only for keepalive on non-Linux).
fn placeholder_event() -> AttackEvent {
    AttackEvent {
        timestamp: Utc::now(),
        source_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        attack_type: AttackType::Other,
        target_port: None,
        username: None,
        count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_failed_password() {
        let line =
            "Mar 15 10:23:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2";
        let event = parse_auth_line(line).unwrap();
        assert_eq!(event.attack_type, AttackType::SshBrute);
        assert_eq!(event.source_ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(event.username.as_deref(), Some("root"));
    }

    #[test]
    fn test_parse_invalid_user() {
        let line =
            "Mar 15 10:23:02 server sshd[1234]: Invalid user admin from 198.51.100.10 port 54321";
        let event = parse_auth_line(line).unwrap();
        assert_eq!(event.attack_type, AttackType::SshBrute);
        assert_eq!(
            event.source_ip,
            "198.51.100.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(event.username.as_deref(), Some("admin"));
    }

    #[test]
    fn test_parse_unrelated_line() {
        let line = "Mar 15 10:23:03 server kernel: something else entirely";
        assert!(parse_auth_line(line).is_none());
    }

    #[test]
    fn test_parse_iso8601_timestamp() {
        let line = "2026-03-20T14:51:57.937254+00:00 vigil sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2";
        let event = parse_auth_line(line).unwrap();
        assert_eq!(event.attack_type, AttackType::SshBrute);
        assert_eq!(event.source_ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        // Verify the timestamp was parsed from the line, not defaulting to now
        assert_eq!(event.timestamp.format("%Y-%m-%d").to_string(), "2026-03-20");
        assert_eq!(event.timestamp.format("%H:%M:%S").to_string(), "14:51:57");
    }

    #[test]
    fn test_parse_iso8601_invalid_user() {
        let line = "2026-03-20T15:00:00.000000+00:00 vigil sshd[5678]: Invalid user admin from 198.51.100.10 port 54321";
        let event = parse_auth_line(line).unwrap();
        assert_eq!(event.attack_type, AttackType::SshBrute);
        assert_eq!(event.source_ip, "198.51.100.10".parse::<IpAddr>().unwrap());
        assert_eq!(event.username.as_deref(), Some("admin"));
        assert_eq!(event.timestamp.format("%Y-%m-%d").to_string(), "2026-03-20");
    }
}
