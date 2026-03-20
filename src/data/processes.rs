//! Process info enrichment — look up name, user, root status for a set of PIDs.

use std::collections::{HashMap, HashSet};

use crate::data::procfs;

/// Enriched process information.
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub is_root: bool,
}

/// Collect process information for a set of PIDs.
///
/// Uses /proc/{pid}/comm for the name and /proc/{pid}/status for the UID.
/// UIDs are mapped to usernames via /etc/passwd (falls back to `uid:N`).
pub fn collect_process_info(pids: &HashSet<u32>) -> HashMap<u32, ProcessInfo> {
    let passwd_map = load_passwd_map();

    let mut result = HashMap::new();

    for &pid in pids {
        let name = procfs::get_process_name(pid).unwrap_or_else(|| "<unknown>".to_string());
        let uid = procfs::get_process_uid(pid);

        let (user, is_root) = match uid {
            Some(u) => {
                let username = passwd_map
                    .get(&u)
                    .cloned()
                    .unwrap_or_else(|| format!("uid:{}", u));
                (username, u == 0)
            }
            None => ("<unknown>".to_string(), false),
        };

        result.insert(
            pid,
            ProcessInfo {
                pid,
                name,
                user,
                is_root,
            },
        );
    }

    result
}

/// Load /etc/passwd into a UID → username map.
/// Returns empty map on failure (e.g. Windows).
fn load_passwd_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let content = match std::fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(_) => return map,
    };

    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 {
            if let Ok(uid) = fields[2].parse::<u32>() {
                map.insert(uid, fields[0].to_string());
            }
        }
    }

    map
}
