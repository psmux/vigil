use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::Instant;

use chrono::{DateTime, Utc};

use crate::data;
use crate::data::*;
use crate::score;

// ─── View enum ────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    CommandCenter,
    AttackRadar,
    Doors,
    NetworkPulse,
    Geography,
    SystemVitals,
}

impl View {
    pub const ALL: [View; 6] = [
        View::CommandCenter,
        View::AttackRadar,
        View::Doors,
        View::NetworkPulse,
        View::Geography,
        View::SystemVitals,
    ];

    pub fn next(self) -> Self {
        let i = self.index();
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let i = self.index();
        Self::ALL[(i + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::CommandCenter => "Command Center",
            Self::AttackRadar => "Attack Radar",
            Self::Doors => "Doors",
            Self::NetworkPulse => "Network Pulse",
            Self::Geography => "Geography",
            Self::SystemVitals => "System Vitals",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::CommandCenter => 0,
            Self::AttackRadar => 1,
            Self::Doors => 2,
            Self::NetworkPulse => 3,
            Self::Geography => 4,
            Self::SystemVitals => 5,
        }
    }

    pub fn from_index(i: usize) -> Option<Self> {
        Self::ALL.get(i).copied()
    }
}

// ─── Aggregated attacker entry ────────────────────────────────────
/// Pre-aggregated attacker data keyed by source IP.
/// This prevents the UI from re-aggregating every frame and
/// eliminates sort-order flickering.
#[derive(Clone, Debug)]
pub struct AggregatedAttacker {
    pub source_ip: IpAddr,
    pub total_attempts: u64,
    pub last_seen: DateTime<Utc>,
    pub attack_type: AttackType,
    pub banned: bool,
}

// ─── App state ────────────────────────────────────────────────────
pub struct App {
    // Navigation
    pub view: View,
    pub should_quit: bool,
    pub paused: bool,
    pub tick_count: u64,
    pub animation_frame: u8,

    // Host info
    pub hostname: String,
    pub uptime_secs: u64,

    // Connections
    pub connections: Vec<Connection>,
    pub ports: Vec<ListeningPort>,

    // Attacks — raw events kept for heatmap / type-bars
    pub attacks: Vec<AttackEvent>,
    pub attacks_24h: [u32; 24],
    pub banned_ips: HashSet<IpAddr>,
    pub attack_count_total: u64,

    // Aggregated attacker map (IP -> aggregate) — source of truth for table
    attacker_map: HashMap<IpAddr, AggregatedAttacker>,
    /// Sorted snapshot rebuilt only when data changes — the UI reads this.
    pub attackers_sorted: Vec<AggregatedAttacker>,
    /// Dirty flag: set when attacker_map changes, cleared after re-sort.
    attackers_dirty: bool,

    // Bandwidth
    pub bandwidth_rx: RingBuffer<f64>,
    pub bandwidth_tx: RingBuffer<f64>,
    pub throughput_history: RingBuffer<(f64, f64)>,
    pub current_rx_bps: f64,
    pub current_tx_bps: f64,

    // Security
    pub security_score: u8,
    pub score_delta_1h: i8,

    // Caches
    pub geoip_cache: HashMap<IpAddr, GeoLocation>,
    pub dns_cache: HashMap<IpAddr, String>,

    // System
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub services: Vec<ServiceStatus>,
    pub interfaces: Vec<NetworkInterface>,

    // Firewall
    pub firewall_rules: Vec<FirewallRule>,
    pub firewall_default_deny: bool,
    pub firewall_active: bool,

    // UI state
    pub scroll_offset: usize,

    // Aggregated stats
    pub top_attacker_countries: Vec<(String, u32)>,

    // Data collection
    system_collector: Option<data::system::SystemCollector>,
    tick_start: Instant,
}

impl App {
    pub fn new() -> Self {
        let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".into());

        // Collect services and interfaces eagerly so the first frame is populated
        let services = data::system::collect_services();
        let interfaces = data::system::collect_interfaces();

        Self {
            view: View::CommandCenter,
            should_quit: false,
            paused: false,
            tick_count: 0,
            animation_frame: 0,

            hostname,
            uptime_secs: 0,

            connections: Vec::new(),
            ports: Vec::new(),

            attacks: Vec::new(),
            attacks_24h: [0; 24],
            banned_ips: HashSet::new(),
            attack_count_total: 0,

            attacker_map: HashMap::new(),
            attackers_sorted: Vec::new(),
            attackers_dirty: false,

            bandwidth_rx: RingBuffer::new(300),
            bandwidth_tx: RingBuffer::new(300),
            throughput_history: RingBuffer::new(300),
            current_rx_bps: 0.0,
            current_tx_bps: 0.0,

            security_score: 100,
            score_delta_1h: 0,

            geoip_cache: HashMap::new(),
            dns_cache: HashMap::new(),

            cpu: CpuInfo::default(),
            memory: MemoryInfo::default(),
            disks: Vec::new(),
            services,
            interfaces,

            firewall_rules: Vec::new(),
            firewall_default_deny: false,
            firewall_active: false,

            scroll_offset: 0,

            top_attacker_countries: Vec::new(),

            system_collector: Some(data::system::SystemCollector::new()),
            tick_start: Instant::now(),
        }
    }

    /// Drain the update channel and apply each message to app state.
    pub fn apply_updates(&mut self, rx: &mpsc::Receiver<DataUpdate>) {
        while let Ok(update) = rx.try_recv() {
            match update {
                DataUpdate::Connections(conns) => {
                    self.connections = conns;
                }
                DataUpdate::Bandwidth { rx_bps, tx_bps } => {
                    self.current_rx_bps = rx_bps;
                    self.current_tx_bps = tx_bps;
                    self.bandwidth_rx.push(rx_bps);
                    self.bandwidth_tx.push(tx_bps);
                    self.throughput_history.push((rx_bps, tx_bps));
                }
                DataUpdate::Attack(event) => {
                    // Skip placeholder / zero-count events
                    if event.count == 0 {
                        continue;
                    }

                    self.attack_count_total += event.count as u64;

                    // Bucket into 24h heatmap by hour
                    let hour = event.timestamp.format("%H").to_string();
                    if let Ok(h) = hour.parse::<usize>() {
                        if h < 24 {
                            self.attacks_24h[h] += event.count;
                        }
                    }

                    // ── GeoIP enrichment: look up immediately ────────
                    let ip = event.source_ip;
                    if !data::geoip::is_private_ip(ip) && !self.geoip_cache.contains_key(&ip) {
                        if let Some(geo) = data::geoip::lookup(ip) {
                            self.geoip_cache.insert(ip, geo);
                        }
                    }

                    // ── Aggregate into attacker_map ──────────────────
                    let banned = self.banned_ips.contains(&ip);
                    let entry = self.attacker_map.entry(ip).or_insert_with(|| {
                        AggregatedAttacker {
                            source_ip: ip,
                            total_attempts: 0,
                            last_seen: event.timestamp,
                            attack_type: event.attack_type,
                            banned,
                        }
                    });
                    entry.total_attempts += event.count as u64;
                    if event.timestamp > entry.last_seen {
                        entry.last_seen = event.timestamp;
                    }
                    entry.attack_type = event.attack_type;
                    entry.banned = banned;
                    self.attackers_dirty = true;

                    // Keep raw event for heatmap / type bars
                    self.attacks.push(event);
                }
                DataUpdate::BannedIps(ips) => {
                    self.banned_ips = ips;
                    // Update banned status in attacker_map
                    for agg in self.attacker_map.values_mut() {
                        agg.banned = self.banned_ips.contains(&agg.source_ip);
                    }
                    self.attackers_dirty = true;
                }
                DataUpdate::FirewallRules(rules, default_deny) => {
                    self.firewall_rules = rules;
                    self.firewall_default_deny = default_deny;
                    self.firewall_active = true;
                }
                DataUpdate::DnsResolved(ip, name) => {
                    self.dns_cache.insert(ip, name);
                }
            }
        }

        // Rebuild sorted snapshot if anything changed
        if self.attackers_dirty {
            self.rebuild_attackers_sorted();
            self.attackers_dirty = false;
        }
    }

    /// Rebuild the sorted attacker list from the aggregation map.
    /// Sort by total attempts descending, then by last_seen descending,
    /// then by IP string for a fully deterministic, stable ordering.
    fn rebuild_attackers_sorted(&mut self) {
        let mut sorted: Vec<AggregatedAttacker> = self.attacker_map.values().cloned().collect();
        sorted.sort_by(|a, b| {
            b.total_attempts.cmp(&a.total_attempts)
                .then_with(|| b.last_seen.cmp(&a.last_seen))
                .then_with(|| a.source_ip.to_string().cmp(&b.source_ip.to_string()))
        });
        self.attackers_sorted = sorted;
    }

    /// Called every tick interval (1 second).
    pub fn tick(&mut self) {
        self.tick_count += 1;
        self.animation_frame = (self.animation_frame + 1) % 8;

        // ── Uptime (every tick) ──────────────────────────────────────
        self.uptime_secs = sysinfo::System::uptime();

        // ── System info refresh (every 5 ticks) ─────────────────────
        if self.tick_count % 5 == 0 {
            if let Some(mut collector) = self.system_collector.take() {
                let (cpu, memory, disks) = collector.refresh();
                self.cpu = cpu;
                self.memory = memory;
                self.disks = disks;
                self.system_collector = Some(collector);
            }
        }

        // ── Services and interfaces (every 10 ticks) ────────────────
        if self.tick_count % 10 == 0 {
            self.services = data::system::collect_services();
            self.interfaces = data::system::collect_interfaces();
        }

        // ── Port analysis (every 3 ticks) ───────────────────────────
        if self.tick_count % 3 == 0 {
            self.ports = data::ports::collect_listening_ports(&self.connections);
            for port in &mut self.ports {
                port.risk = data::ports::classify_risk(
                    port.port,
                    port.bind_addr,
                    &port.process_name,
                    &self.firewall_rules,
                );
                port.auth = data::ports::detect_auth(port.port, &port.process_name);
            }
        }

        // ── GeoIP enrichment (every tick, for new connections) ───────
        let new_ips: Vec<IpAddr> = self
            .connections
            .iter()
            .map(|c| c.remote_addr.ip())
            .filter(|ip| !data::geoip::is_private_ip(*ip) && !self.geoip_cache.contains_key(ip))
            .collect();

        for ip in new_ips {
            if let Some(geo) = data::geoip::lookup(ip) {
                self.geoip_cache.insert(ip, geo);
            }
        }

        // Apply cached geo to connections that don't have it yet
        for conn in &mut self.connections {
            if conn.geo.is_none() {
                let remote_ip = conn.remote_addr.ip();
                if let Some(geo) = self.geoip_cache.get(&remote_ip) {
                    conn.geo = Some(geo.clone());
                }
            }
        }

        // ── Attack country enrichment (catch any IPs missed earlier) ─
        let attack_ips: Vec<IpAddr> = self
            .attacks
            .iter()
            .map(|a| a.source_ip)
            .filter(|ip| !data::geoip::is_private_ip(*ip) && !self.geoip_cache.contains_key(ip))
            .collect();

        for ip in attack_ips {
            if let Some(geo) = data::geoip::lookup(ip) {
                self.geoip_cache.insert(ip, geo);
            }
        }

        self.recalc_top_attacker_countries();

        // ── Security score (every 5 ticks) ──────────────────────────
        if self.tick_count % 5 == 0 {
            let (new_score, _factors) = score::compute_score(self);
            self.security_score = new_score;

            let elapsed_secs = self.tick_start.elapsed().as_secs();
            if elapsed_secs >= 3600 {
                self.score_delta_1h = 0;
            }
        }
    }

    fn recalc_top_attacker_countries(&mut self) {
        let mut country_counts: HashMap<String, u32> = HashMap::new();
        // Use the aggregated attacker map for efficiency
        for agg in self.attacker_map.values() {
            if let Some(geo) = self.geoip_cache.get(&agg.source_ip) {
                if !geo.country_code.is_empty() {
                    *country_counts.entry(geo.country_code.clone()).or_insert(0) += agg.total_attempts as u32;
                }
            }
        }
        let mut sorted: Vec<(String, u32)> = country_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(10);
        self.top_attacker_countries = sorted;
    }
}
