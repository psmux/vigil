//! Outbound connection tracking — per-app outbound stats, first-seen detection,
//! bandwidth tracking, and unusual bandwidth alerting.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};

use crate::data::{Connection, Direction, GeoLocation, TcpState};

// ─── Per-app outbound summary ───────────────────────────────────────

/// Aggregated outbound statistics for a single application.
#[derive(Clone, Debug)]
pub struct AppOutboundStats {
    pub app_name: String,
    pub pid: Option<u32>,
    /// Number of active outbound connections.
    pub conn_count: u32,
    /// Unique remote IPs.
    pub unique_remotes: u32,
    /// Countries this app connects to: (country_code, count).
    pub countries: Vec<(String, u32)>,
    /// Estimated aggregate tx bandwidth (bytes/sec) for this app.
    pub tx_bps: f64,
    /// Estimated aggregate rx bandwidth (bytes/sec) for this app.
    pub rx_bps: f64,
    /// Whether this app has any first-seen (new) outbound connections.
    pub has_new: bool,
    /// Whether this app's bandwidth is flagged as unusual.
    pub bandwidth_unusual: bool,
    /// Individual outbound connections for this app.
    pub connections: Vec<OutboundConn>,
}

/// A single outbound connection belonging to an app.
#[derive(Clone, Debug)]
pub struct OutboundConn {
    pub remote_addr: SocketAddr,
    pub country_code: String,
    pub country_name: String,
    pub hostname: Option<String>,
    pub state: TcpState,
    pub tx_bps: f64,
    pub rx_bps: f64,
    pub first_seen: DateTime<Utc>,
    pub is_new: bool,
}

// ─── Outbound Tracker ───────────────────────────────────────────────

/// Tracks outbound connections over time to detect new connections and
/// unusual bandwidth patterns.
#[derive(Clone, Debug)]
pub struct OutboundTracker {
    /// (app_name, remote_ip) → first-seen timestamp.
    first_seen: HashMap<(String, IpAddr), DateTime<Utc>>,
    /// app_name → rolling average tx_bps (exponential moving average).
    app_bandwidth_avg: HashMap<String, f64>,
    /// How many ticks old a connection is before it's no longer "new".
    new_threshold_secs: i64,
    /// Multiplier: if current bandwidth > avg * multiplier → unusual.
    unusual_multiplier: f64,
}

impl OutboundTracker {
    pub fn new() -> Self {
        Self {
            first_seen: HashMap::new(),
            app_bandwidth_avg: HashMap::new(),
            new_threshold_secs: 60, // connections are "new" for 60 seconds
            unusual_multiplier: 3.0,
        }
    }

    /// Process current connections and produce per-app outbound stats.
    pub fn process(
        &mut self,
        connections: &[Connection],
        geoip_cache: &HashMap<IpAddr, GeoLocation>,
        dns_cache: &HashMap<IpAddr, String>,
    ) -> Vec<AppOutboundStats> {
        let now = Utc::now();

        // Group outbound connections by app
        let mut app_conns: HashMap<String, Vec<&Connection>> = HashMap::new();

        for conn in connections {
            // Include Outbound and Unknown-direction established connections
            let dominated_outbound = conn.direction == Direction::Outbound
                || (conn.direction == Direction::Unknown
                    && conn.state == TcpState::Established);

            if !dominated_outbound {
                continue;
            }

            // Skip loopback and local
            if conn.remote_addr.ip().is_loopback() {
                continue;
            }

            let app_name = conn
                .process_name
                .clone()
                .unwrap_or_else(|| "<unknown>".into());

            app_conns.entry(app_name).or_default().push(conn);
        }

        let mut result: Vec<AppOutboundStats> = Vec::new();

        for (app_name, conns) in &app_conns {
            let mut country_counts: HashMap<String, u32> = HashMap::new();
            let mut unique_ips: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();
            let mut total_tx: f64 = 0.0;
            let mut total_rx: f64 = 0.0;
            let mut has_new = false;
            let mut out_conns: Vec<OutboundConn> = Vec::new();

            for conn in conns {
                let remote_ip = conn.remote_addr.ip();
                unique_ips.insert(remote_ip);

                // Country lookup
                let (cc, cn) = conn
                    .geo
                    .as_ref()
                    .or_else(|| geoip_cache.get(&remote_ip))
                    .map(|g| (g.country_code.clone(), g.country_name.clone()))
                    .unwrap_or_else(|| ("??".into(), "Unknown".into()));

                if !cc.is_empty() && cc != "??" {
                    *country_counts.entry(cc.clone()).or_insert(0) += 1;
                }

                // First-seen tracking
                let key = (app_name.clone(), remote_ip);
                let first = *self
                    .first_seen
                    .entry(key)
                    .or_insert(now);

                let age_secs = now.signed_duration_since(first).num_seconds();
                let is_new = age_secs < self.new_threshold_secs;
                if is_new {
                    has_new = true;
                }

                // Hostname
                let hostname = dns_cache.get(&remote_ip).cloned();

                total_tx += conn.tx_bps;
                total_rx += conn.rx_bps;

                out_conns.push(OutboundConn {
                    remote_addr: conn.remote_addr,
                    country_code: cc,
                    country_name: cn,
                    hostname,
                    state: conn.state,
                    tx_bps: conn.tx_bps,
                    rx_bps: conn.rx_bps,
                    first_seen: first,
                    is_new,
                });
            }

            // Sort connections: new first, then by tx_bps descending
            out_conns.sort_by(|a, b| {
                b.is_new
                    .cmp(&a.is_new)
                    .then_with(|| b.tx_bps.partial_cmp(&a.tx_bps).unwrap_or(std::cmp::Ordering::Equal))
            });

            // Unusual bandwidth detection (EMA)
            let alpha = 0.1; // smoothing factor
            let avg = self.app_bandwidth_avg.entry(app_name.clone()).or_insert(0.0);
            let bandwidth_unusual = total_tx > *avg * self.unusual_multiplier && *avg > 1024.0;
            *avg = alpha * total_tx + (1.0 - alpha) * *avg;

            // Countries sorted by count
            let mut countries: Vec<(String, u32)> = country_counts.into_iter().collect();
            countries.sort_by(|a, b| b.1.cmp(&a.1));

            let pid = conns.first().and_then(|c| c.pid);

            result.push(AppOutboundStats {
                app_name: app_name.clone(),
                pid,
                conn_count: conns.len() as u32,
                unique_remotes: unique_ips.len() as u32,
                countries,
                tx_bps: total_tx,
                rx_bps: total_rx,
                has_new,
                bandwidth_unusual,
                connections: out_conns,
            });
        }

        // Sort apps: unusual first, then by tx_bps descending
        result.sort_by(|a, b| {
            b.bandwidth_unusual
                .cmp(&a.bandwidth_unusual)
                .then_with(|| b.tx_bps.partial_cmp(&a.tx_bps).unwrap_or(std::cmp::Ordering::Equal))
        });

        result
    }

    /// Prune first-seen entries older than 1 hour to prevent unbounded growth.
    pub fn prune(&mut self) {
        let now = Utc::now();
        self.first_seen.retain(|_, ts| {
            now.signed_duration_since(*ts).num_seconds() < 3600
        });
    }
}

impl Default for OutboundTracker {
    fn default() -> Self {
        Self::new()
    }
}
