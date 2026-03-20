//! fail2ban status poller — queries fail2ban-client for banned IPs.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::Duration;

use crate::data::DataUpdate;

/// Background thread that polls `fail2ban-client status sshd` every 30 seconds
/// and sends the current set of banned IPs via the channel.
///
/// On Windows or when fail2ban is not installed, sleeps in a loop (graceful degradation).
pub fn fail2ban_monitor_thread(tx: mpsc::Sender<DataUpdate>) {
    loop {
        let banned = query_fail2ban_sshd();
        if tx.send(DataUpdate::BannedIps(banned)).is_err() {
            break; // receiver dropped
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

/// Run `fail2ban-client status sshd` and parse the banned IP list.
///
/// Returns an empty set on failure.
fn query_fail2ban_sshd() -> HashSet<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        if let Some(ips) = try_query_fail2ban() {
            return ips;
        }
    }

    HashSet::new()
}

/// Attempt to run fail2ban-client and parse its output.
///
/// Expected output contains a line like:
///   `   |- Banned IP list:	1.2.3.4 5.6.7.8 9.10.11.12`
#[cfg(target_os = "linux")]
fn try_query_fail2ban() -> Option<HashSet<IpAddr>> {
    use std::process::Command;

    let output = Command::new("fail2ban-client")
        .args(["status", "sshd"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut ips = HashSet::new();

    for line in text.lines() {
        let line = line.trim();
        // Look for the "Banned IP list:" line
        if let Some(rest) = line.strip_prefix("|- Banned IP list:") {
            let rest = rest.trim();
            for token in rest.split_whitespace() {
                if let Ok(ip) = token.parse::<IpAddr>() {
                    ips.insert(ip);
                }
            }
        }
        // Also check for "Banned IP" without the "list:" (some versions differ)
        if line.contains("Banned IP") && line.contains(':') {
            if let Some(after_colon) = line.split(':').last() {
                for token in after_colon.split_whitespace() {
                    if let Ok(ip) = token.parse::<IpAddr>() {
                        ips.insert(ip);
                    }
                }
            }
        }
    }

    Some(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_on_non_linux() {
        // On Windows this should just return empty
        let result = query_fail2ban_sshd();
        // Can't assert specific content since it depends on platform,
        // but it shouldn't panic
        let _ = result;
    }
}
