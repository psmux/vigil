//! Alert engine — generates alerts from security events, bandwidth spikes,
//! service state changes, and threat connections.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::data::{AttackEvent, Connection, ListeningPort, PortRisk, ServiceStatus};

// ─── Alert types ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum AlertKind {
    SshBruteForce { source_ip: String, attempts: u32 },
    NewListeningPort { port: u16, process: String, bind: String },
    BandwidthSpike { direction: String, bps: f64, threshold: f64 },
    BandwidthAnomaly { process: String, current_bps: f64, avg_bps: f64 },
    ServiceDown { name: String },
    ServiceUp { name: String },
    NewConnection { process: String, remote: String },
    PortExposed { port: u16, process: String },
    ThreatConnection { ip: String, country: String },
    FirewallChange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Warn,
    Crit,
}

#[derive(Clone, Debug)]
pub struct Alert {
    pub timestamp: DateTime<Utc>,
    pub kind: AlertKind,
    pub severity: AlertSeverity,
    pub message: String,
    pub read: bool,
}

// ─── Alert categories ──────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertCategory {
    Security,
    Network,
    Bandwidth,
    System,
}

impl AlertCategory {
    pub const ALL: [AlertCategory; 4] = [
        AlertCategory::Security,
        AlertCategory::Network,
        AlertCategory::Bandwidth,
        AlertCategory::System,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Security => "Security",
            Self::Network => "Network Activity",
            Self::Bandwidth => "Bandwidth",
            Self::System => "System",
        }
    }
}

impl Alert {
    pub fn category(&self) -> AlertCategory {
        match &self.kind {
            AlertKind::SshBruteForce { .. } => AlertCategory::Security,
            AlertKind::ThreatConnection { .. } => AlertCategory::Security,
            AlertKind::PortExposed { .. } => AlertCategory::Security,
            AlertKind::FirewallChange => AlertCategory::Security,
            AlertKind::NewConnection { .. } => AlertCategory::Network,
            AlertKind::NewListeningPort { .. } => AlertCategory::System,
            AlertKind::BandwidthSpike { .. } => AlertCategory::Bandwidth,
            AlertKind::BandwidthAnomaly { .. } => AlertCategory::Bandwidth,
            AlertKind::ServiceDown { .. } => AlertCategory::System,
            AlertKind::ServiceUp { .. } => AlertCategory::System,
        }
    }
}

// ─── Alert engine ──────────────────────────────────────────────────

pub struct AlertEngine {
    pub alerts: VecDeque<Alert>,
    max_alerts: usize,

    // Tracking state for change detection
    known_ports: HashSet<u16>,
    known_processes: HashSet<String>,
    prev_services: HashMap<String, bool>,
    bandwidth_spike_threshold: f64, // bytes/sec

    // Brute-force tracking: IP -> (count, window_start)
    brute_tracker: HashMap<IpAddr, (u32, DateTime<Utc>)>,
    brute_alerted: HashSet<IpAddr>,

    // Dedup: remember the last N alert messages to avoid exact repeats
    recent_messages: VecDeque<String>,
    dedup_window: usize,

    // New outbound connection tracking
    known_connections: HashSet<String>,

    // Per-app bandwidth anomaly tracking (process -> rolling window of bandwidth samples)
    app_bandwidth_history: HashMap<String, VecDeque<f64>>,

    // Track whether first tick has run (suppress initial noise)
    initialized: bool,
}

impl AlertEngine {
    pub fn new() -> Self {
        Self {
            alerts: VecDeque::with_capacity(200),
            max_alerts: 200,
            known_ports: HashSet::new(),
            known_processes: HashSet::new(),
            prev_services: HashMap::new(),
            bandwidth_spike_threshold: 10.0 * 1024.0 * 1024.0, // 10 MB/s
            brute_tracker: HashMap::new(),
            brute_alerted: HashSet::new(),
            recent_messages: VecDeque::with_capacity(50),
            dedup_window: 50,
            known_connections: HashSet::new(),
            app_bandwidth_history: HashMap::new(),
            initialized: false,
        }
    }

    /// Seed the engine with the initial state so we only alert on *changes*.
    /// Call once after the first data collection.
    pub fn initialize(
        &mut self,
        ports: &[ListeningPort],
        services: &[ServiceStatus],
        connections: &[Connection],
    ) {
        for p in ports {
            self.known_ports.insert(p.port);
            self.known_processes.insert(p.process_name.clone());
        }
        for s in services {
            self.prev_services.insert(s.name.clone(), s.active);
        }
        // Seed known connections so initial outbound connections don't trigger alerts
        for conn in connections {
            if conn.state == crate::data::TcpState::Established
                && conn.direction == crate::data::Direction::Outbound
            {
                let proc_name = conn.process_name.clone().unwrap_or_default();
                if !proc_name.is_empty() {
                    let remote_ip = conn.remote_addr.ip();
                    if !crate::data::geoip::is_private_ip(remote_ip) {
                        let key = format!("{}:{}", proc_name, remote_ip);
                        self.known_connections.insert(key);
                    }
                }
            }
        }
        self.initialized = true;
    }

    // ── Check methods ───────────────────────────────────────────────

    /// Detect SSH brute-force: >10 attempts from the same IP within 60 seconds.
    pub fn check_attacks(&mut self, attacks: &[AttackEvent], banned: &HashSet<IpAddr>) {
        let now = Utc::now();
        let window = chrono::Duration::seconds(60);

        // Collect pending alerts to avoid borrow conflicts with brute_tracker
        let mut pending: Vec<(IpAddr, u32)> = Vec::new();

        for event in attacks {
            if event.count == 0 {
                continue;
            }
            let ip = event.source_ip;

            let entry = self.brute_tracker.entry(ip).or_insert((0, now));

            // Reset window if it has elapsed
            if now.signed_duration_since(entry.1) > window {
                entry.0 = 0;
                entry.1 = now;
            }

            entry.0 += event.count;

            if entry.0 > 10 && !self.brute_alerted.contains(&ip) {
                pending.push((ip, entry.0));
            }
        }

        // Now push the collected alerts (no borrow conflict)
        for (ip, attempts) in pending {
            let status = if banned.contains(&ip) { " (banned)" } else { "" };
            self.push_alert(
                AlertKind::SshBruteForce {
                    source_ip: ip.to_string(),
                    attempts,
                },
                AlertSeverity::Crit,
                format!(
                    "SSH brute-force: {} attempts from {}{}",
                    attempts, ip, status
                ),
            );
            self.brute_alerted.insert(ip);
        }

        // Expire old brute-force tracking entries (older than 5 minutes)
        let cutoff = chrono::Duration::seconds(300);
        self.brute_tracker
            .retain(|_, (_, start)| now.signed_duration_since(*start) < cutoff);
    }

    /// Detect new listening ports that were not present at startup.
    pub fn check_new_ports(&mut self, ports: &[ListeningPort]) {
        if !self.initialized {
            return;
        }

        for p in ports {
            if !self.known_ports.contains(&p.port) {
                self.known_ports.insert(p.port);
                let bind = format!("{}", p.bind_addr);
                self.push_alert(
                    AlertKind::NewListeningPort {
                        port: p.port,
                        process: p.process_name.clone(),
                        bind: bind.clone(),
                    },
                    AlertSeverity::Warn,
                    format!(
                        "New port: {}:{} ({})",
                        bind, p.port, p.process_name
                    ),
                );
            }
        }
    }

    /// Detect bandwidth spikes exceeding the threshold.
    pub fn check_bandwidth(&mut self, rx_bps: f64, tx_bps: f64) {
        if rx_bps > self.bandwidth_spike_threshold {
            self.push_alert(
                AlertKind::BandwidthSpike {
                    direction: "download".into(),
                    bps: rx_bps,
                    threshold: self.bandwidth_spike_threshold,
                },
                AlertSeverity::Warn,
                format!(
                    "Bandwidth spike: download {:.1} MB/s (threshold {:.0} MB/s)",
                    rx_bps / (1024.0 * 1024.0),
                    self.bandwidth_spike_threshold / (1024.0 * 1024.0),
                ),
            );
        }

        if tx_bps > self.bandwidth_spike_threshold {
            self.push_alert(
                AlertKind::BandwidthSpike {
                    direction: "upload".into(),
                    bps: tx_bps,
                    threshold: self.bandwidth_spike_threshold,
                },
                AlertSeverity::Warn,
                format!(
                    "Bandwidth spike: upload {:.1} MB/s (threshold {:.0} MB/s)",
                    tx_bps / (1024.0 * 1024.0),
                    self.bandwidth_spike_threshold / (1024.0 * 1024.0),
                ),
            );
        }
    }

    /// Detect services going down or coming back up.
    pub fn check_services(&mut self, services: &[ServiceStatus]) {
        if !self.initialized {
            return;
        }

        for svc in services {
            let prev_active = self.prev_services.get(&svc.name).copied();

            match prev_active {
                Some(was_active) if was_active && !svc.active => {
                    self.push_alert(
                        AlertKind::ServiceDown { name: svc.name.clone() },
                        AlertSeverity::Crit,
                        format!("Service DOWN: {}", svc.name),
                    );
                }
                Some(was_active) if !was_active && svc.active => {
                    self.push_alert(
                        AlertKind::ServiceUp { name: svc.name.clone() },
                        AlertSeverity::Info,
                        format!("Service UP: {}", svc.name),
                    );
                }
                _ => {}
            }

            self.prev_services.insert(svc.name.clone(), svc.active);
        }
    }

    /// Detect connections flagged as threats.
    pub fn check_threats(&mut self, connections: &[Connection]) {
        for conn in connections {
            if conn.is_threat {
                let ip = conn.remote_addr.ip().to_string();
                let country = conn
                    .geo
                    .as_ref()
                    .map(|g| g.country_code.clone())
                    .unwrap_or_else(|| "??".into());

                self.push_alert(
                    AlertKind::ThreatConnection {
                        ip: ip.clone(),
                        country: country.clone(),
                    },
                    AlertSeverity::Crit,
                    format!("Threat connection: {} ({})", ip, country),
                );
            }
        }
    }

    /// Detect newly exposed critical ports.
    pub fn check_exposed_ports(&mut self, ports: &[ListeningPort]) {
        if !self.initialized {
            return;
        }

        for p in ports {
            if p.risk == PortRisk::Critical {
                // Only alert once per process+port combo
                let key = format!("{}:{}", p.process_name, p.port);
                if !self.known_processes.contains(&key) {
                    self.known_processes.insert(key);
                    self.push_alert(
                        AlertKind::PortExposed {
                            port: p.port,
                            process: p.process_name.clone(),
                        },
                        AlertSeverity::Crit,
                        format!(
                            "CRITICAL port exposed: {} on port {}",
                            p.process_name, p.port
                        ),
                    );
                }
            }
        }
    }

    /// Detect new outbound connections from known processes.
    pub fn check_new_connections(&mut self, connections: &[Connection]) {
        if !self.initialized {
            return;
        }

        for conn in connections {
            if conn.state != crate::data::TcpState::Established {
                continue;
            }
            if conn.direction != crate::data::Direction::Outbound {
                continue;
            }
            let proc_name = conn.process_name.clone().unwrap_or_default();
            if proc_name.is_empty() {
                continue;
            }
            let remote_ip = conn.remote_addr.ip();
            if crate::data::geoip::is_private_ip(remote_ip) {
                continue;
            }
            let key = format!("{}:{}", proc_name, remote_ip);
            if self.known_connections.insert(key) {
                let country = conn
                    .geo
                    .as_ref()
                    .map(|g| g.country_code.clone())
                    .unwrap_or_else(|| "??".into());
                self.push_alert(
                    AlertKind::NewConnection {
                        process: proc_name.clone(),
                        remote: remote_ip.to_string(),
                    },
                    AlertSeverity::Info,
                    format!(
                        "New outbound: {} \u{2192} {} ({})",
                        proc_name, remote_ip, country
                    ),
                );
            }
        }
    }

    /// Detect per-app bandwidth anomalies (current > 5x rolling average).
    pub fn check_bandwidth_anomaly(&mut self, connections: &[Connection]) {
        if !self.initialized {
            return;
        }

        // Aggregate bandwidth by process
        let mut per_proc: HashMap<String, f64> = HashMap::new();
        for conn in connections {
            if conn.state != crate::data::TcpState::Established {
                continue;
            }
            let proc_name = conn.process_name.clone().unwrap_or_default();
            if proc_name.is_empty() {
                continue;
            }
            *per_proc.entry(proc_name).or_insert(0.0) += conn.rx_bps + conn.tx_bps;
        }

        // Collect alerts separately to avoid borrow conflicts
        let mut pending_alerts: Vec<(String, f64, f64)> = Vec::new();

        for (proc_name, current_bps) in &per_proc {
            let history = self
                .app_bandwidth_history
                .entry(proc_name.clone())
                .or_insert_with(|| VecDeque::with_capacity(60));

            // Calculate rolling average
            if history.len() >= 10 {
                let avg: f64 = history.iter().sum::<f64>() / history.len() as f64;
                // Only alert if average is meaningful (> 1 KB/s) and current is 5x
                if avg > 1024.0 && *current_bps > avg * 5.0 {
                    pending_alerts.push((proc_name.clone(), *current_bps, avg));
                }
            }

            // Push current sample
            history.push_back(*current_bps);
            if history.len() > 60 {
                history.pop_front();
            }
        }

        for (proc_name, current_bps, avg) in pending_alerts {
            self.push_alert(
                AlertKind::BandwidthAnomaly {
                    process: proc_name.clone(),
                    current_bps,
                    avg_bps: avg,
                },
                AlertSeverity::Warn,
                format!(
                    "{}: {:.1}x baseline ({:.0} KB/s vs {:.0} KB/s avg)",
                    proc_name,
                    current_bps / avg,
                    current_bps / 1024.0,
                    avg / 1024.0,
                ),
            );
        }
    }

    // ── Core ────────────────────────────────────────────────────────

    fn push_alert(&mut self, kind: AlertKind, severity: AlertSeverity, message: String) {
        // Dedup: skip if this exact message appeared recently
        if self.recent_messages.contains(&message) {
            return;
        }

        self.recent_messages.push_back(message.clone());
        if self.recent_messages.len() > self.dedup_window {
            self.recent_messages.pop_front();
        }

        let alert = Alert {
            timestamp: Utc::now(),
            kind,
            severity,
            message,
            read: false,
        };

        self.alerts.push_back(alert);

        // Evict oldest if over capacity
        while self.alerts.len() > self.max_alerts {
            self.alerts.pop_front();
        }
    }

    // ── Queries ─────────────────────────────────────────────────────

    pub fn unread_count(&self) -> usize {
        self.alerts.iter().filter(|a| !a.read).count()
    }

    pub fn highest_unread_severity(&self) -> Option<AlertSeverity> {
        let mut highest: Option<AlertSeverity> = None;
        for a in &self.alerts {
            if !a.read {
                let dominated = match (&highest, &a.severity) {
                    (None, _) => true,
                    (Some(AlertSeverity::Info), AlertSeverity::Warn | AlertSeverity::Crit) => true,
                    (Some(AlertSeverity::Warn), AlertSeverity::Crit) => true,
                    _ => false,
                };
                if dominated {
                    highest = Some(a.severity);
                }
            }
        }
        highest
    }

    pub fn recent(&self, n: usize) -> Vec<&Alert> {
        self.alerts.iter().rev().take(n).collect()
    }

    /// Return alerts filtered by category.
    pub fn by_category(&self, cat: AlertCategory) -> Vec<&Alert> {
        self.alerts
            .iter()
            .filter(|a| a.category() == cat)
            .rev()
            .collect()
    }

    /// Count alerts by severity.
    pub fn count_by_severity(&self, severity: AlertSeverity) -> usize {
        self.alerts.iter().filter(|a| a.severity == severity).count()
    }

    pub fn mark_all_read(&mut self) {
        for a in &mut self.alerts {
            a.read = true;
        }
    }
}
