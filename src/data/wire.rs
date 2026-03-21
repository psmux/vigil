//! Wire tracker — Wireshark-like connection lifecycle monitoring.
//!
//! Diffs the connection table between ticks to detect new connections,
//! state transitions, closures, and data activity. Produces a scrolling
//! event log that shows what's happening "under the wire" in real time.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use chrono::{DateTime, Utc};

use crate::data::{Connection, Direction, GeoLocation, Protocol, TcpState};
use crate::data::protocols::AppProtocol;

// ─── Connection key for cross-tick tracking ─────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ConnKey {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    protocol: Protocol,
}

impl ConnKey {
    fn from_conn(conn: &Connection) -> Self {
        Self {
            local_addr: conn.local_addr,
            remote_addr: conn.remote_addr,
            protocol: conn.protocol,
        }
    }
}

// ─── Previous tick snapshot ─────────────────────────────────────────

#[derive(Clone, Debug)]
struct ConnSnapshot {
    state: TcpState,
    process_name: Option<String>,
    pid: Option<u32>,
    direction: Direction,
    tx_bps: f64,
    rx_bps: f64,
}

// ─── Wire event types ───────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireEventKind {
    /// New connection appeared in the table
    NewConnection,
    /// Connection disappeared from the table
    ConnectionClosed,
    /// TCP state changed (e.g. SYN_SENT → ESTABLISHED)
    StateChange { from: TcpState, to: TcpState },
}

/// A single event in the wire log.
#[derive(Clone, Debug)]
pub struct WireEvent {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub kind: WireEventKind,
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub direction: Direction,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub country_code: String,
    pub hostname: Option<String>,
    pub state: TcpState,
    pub service: AppProtocol,
    pub tx_bps: f64,
    pub rx_bps: f64,
    pub is_threat: bool,
}

// ─── Wire protocol stats ────────────────────────────────────────────

/// Summary counts for the header bar.
#[derive(Clone, Debug, Default)]
pub struct WireStats {
    pub total_events: u64,
    pub tcp_count: u32,
    pub udp_count: u32,
    pub tcp_inbound: u32,
    pub tcp_outbound: u32,
    pub udp_inbound: u32,
    pub udp_outbound: u32,
    pub new_this_tick: u32,
    pub closed_this_tick: u32,
    pub state_changes_this_tick: u32,
}

// ─── Wire Tracker ───────────────────────────────────────────────────

/// Tracks connection lifecycle by diffing snapshots between ticks.
pub struct WireTracker {
    prev_connections: HashMap<ConnKey, ConnSnapshot>,
    events: VecDeque<WireEvent>,
    max_events: usize,
    seq_counter: u64,
    pub stats: WireStats,
}

impl WireTracker {
    pub fn new() -> Self {
        Self {
            prev_connections: HashMap::new(),
            events: VecDeque::with_capacity(2048),
            max_events: 2000,
            seq_counter: 0,
            stats: WireStats::default(),
        }
    }

    /// Process a new snapshot of connections and generate wire events.
    pub fn process(
        &mut self,
        connections: &[Connection],
        geoip_cache: &HashMap<std::net::IpAddr, GeoLocation>,
        dns_cache: &HashMap<std::net::IpAddr, String>,
    ) {
        let now = Utc::now();
        let mut current: HashMap<ConnKey, &Connection> = HashMap::new();

        // Reset per-tick stats
        self.stats.new_this_tick = 0;
        self.stats.closed_this_tick = 0;
        self.stats.state_changes_this_tick = 0;
        self.stats.tcp_count = 0;
        self.stats.udp_count = 0;
        self.stats.tcp_inbound = 0;
        self.stats.tcp_outbound = 0;
        self.stats.udp_inbound = 0;
        self.stats.udp_outbound = 0;

        // Build current connection map and count protocol stats
        for conn in connections {
            // Skip LISTEN sockets — we want active traffic
            if conn.state == TcpState::Listen {
                continue;
            }

            let key = ConnKey::from_conn(conn);
            current.insert(key, conn);

            // Protocol stats
            match conn.protocol {
                Protocol::Tcp => {
                    self.stats.tcp_count += 1;
                    match conn.direction {
                        Direction::Inbound => self.stats.tcp_inbound += 1,
                        Direction::Outbound => self.stats.tcp_outbound += 1,
                        _ => {}
                    }
                }
                Protocol::Udp => {
                    self.stats.udp_count += 1;
                    match conn.direction {
                        Direction::Inbound => self.stats.udp_inbound += 1,
                        Direction::Outbound => self.stats.udp_outbound += 1,
                        _ => {}
                    }
                }
            }
        }

        // Collect events into a temp vec to avoid borrow checker issues
        let mut new_events: Vec<WireEvent> = Vec::new();

        // Detect NEW connections (in current but not in prev)
        for (key, conn) in &current {
            if !self.prev_connections.contains_key(key) {
                self.seq_counter += 1;
                new_events.push(WireEvent {
                    seq: self.seq_counter,
                    timestamp: now,
                    kind: WireEventKind::NewConnection,
                    protocol: conn.protocol,
                    local_addr: conn.local_addr,
                    remote_addr: conn.remote_addr,
                    direction: conn.direction,
                    process_name: conn.process_name.clone(),
                    pid: conn.pid,
                    country_code: get_country_code(conn, geoip_cache),
                    hostname: dns_cache.get(&conn.remote_addr.ip()).cloned(),
                    state: conn.state,
                    service: detect_service(conn),
                    tx_bps: conn.tx_bps,
                    rx_bps: conn.rx_bps,
                    is_threat: conn.is_threat,
                });
                self.stats.new_this_tick += 1;
            }
        }

        // Detect STATE CHANGES (in both, but state changed)
        for (key, conn) in &current {
            if let Some(prev) = self.prev_connections.get(key) {
                if prev.state != conn.state {
                    self.seq_counter += 1;
                    new_events.push(WireEvent {
                        seq: self.seq_counter,
                        timestamp: now,
                        kind: WireEventKind::StateChange {
                            from: prev.state,
                            to: conn.state,
                        },
                        protocol: conn.protocol,
                        local_addr: conn.local_addr,
                        remote_addr: conn.remote_addr,
                        direction: conn.direction,
                        process_name: conn.process_name.clone(),
                        pid: conn.pid,
                        country_code: get_country_code(conn, geoip_cache),
                        hostname: dns_cache.get(&conn.remote_addr.ip()).cloned(),
                        state: conn.state,
                        service: detect_service(conn),
                        tx_bps: conn.tx_bps,
                        rx_bps: conn.rx_bps,
                        is_threat: conn.is_threat,
                    });
                    self.stats.state_changes_this_tick += 1;
                }
            }
        }

        // Detect CLOSED connections (in prev but not in current)
        for (key, prev) in &self.prev_connections {
            if !current.contains_key(key) {
                let remote_ip = key.remote_addr.ip();
                self.seq_counter += 1;
                new_events.push(WireEvent {
                    seq: self.seq_counter,
                    timestamp: now,
                    kind: WireEventKind::ConnectionClosed,
                    protocol: key.protocol,
                    local_addr: key.local_addr,
                    remote_addr: key.remote_addr,
                    direction: prev.direction,
                    process_name: prev.process_name.clone(),
                    pid: prev.pid,
                    country_code: geoip_cache
                        .get(&remote_ip)
                        .map(|g| g.country_code.clone())
                        .unwrap_or_default(),
                    hostname: dns_cache.get(&remote_ip).cloned(),
                    state: prev.state,
                    service: detect_service_from_ports(
                        key.local_addr.port(),
                        key.remote_addr.port(),
                        key.protocol == Protocol::Tcp,
                    ),
                    tx_bps: 0.0,
                    rx_bps: 0.0,
                    is_threat: false,
                });
                self.stats.closed_this_tick += 1;
            }
        }

        // Push all collected events
        for event in new_events {
            self.push_event(event);
        }

        // Update previous snapshot
        self.prev_connections.clear();
        for (key, conn) in current {
            self.prev_connections.insert(key, ConnSnapshot {
                state: conn.state,
                process_name: conn.process_name.clone(),
                pid: conn.pid,
                direction: conn.direction,
                tx_bps: conn.tx_bps,
                rx_bps: conn.rx_bps,
            });
        }
    }

    /// Get the event log (newest first).
    pub fn events(&self) -> &VecDeque<WireEvent> {
        &self.events
    }

    /// Total events ever generated.
    pub fn total_events(&self) -> u64 {
        self.stats.total_events
    }

    fn push_event(&mut self, event: WireEvent) {
        self.events.push_front(event);
        self.stats.total_events += 1;
        while self.events.len() > self.max_events {
            self.events.pop_back();
        }
    }
}

impl Default for WireTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn get_country_code(
    conn: &Connection,
    geoip_cache: &HashMap<std::net::IpAddr, GeoLocation>,
) -> String {
    conn.geo
        .as_ref()
        .map(|g| g.country_code.clone())
        .or_else(|| {
            geoip_cache
                .get(&conn.remote_addr.ip())
                .map(|g| g.country_code.clone())
        })
        .unwrap_or_default()
}

// ─── Service detection ──────────────────────────────────────────────

fn detect_service(conn: &Connection) -> AppProtocol {
    let is_tcp = conn.protocol == Protocol::Tcp;
    let lp = conn.local_addr.port();
    let rp = conn.remote_addr.port();
    detect_service_from_ports(lp, rp, is_tcp)
}

fn detect_service_from_ports(local_port: u16, remote_port: u16, is_tcp: bool) -> AppProtocol {
    let proto_local = AppProtocol::from_port(local_port, is_tcp);
    let proto_remote = AppProtocol::from_port(remote_port, is_tcp);
    if proto_remote != AppProtocol::Other {
        proto_remote
    } else {
        proto_local
    }
}
