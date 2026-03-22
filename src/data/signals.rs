//! Signal tracker — aggregates live network activity into weighted tags for
//! the tag-cloud visualization.  Each signal (protocol, hostname, country,
//! process, event) carries a *weight* (overall prominence) and *heat*
//! (recency glow).  Both decay every tick so the cloud is always alive.

use std::collections::HashMap;
use std::net::IpAddr;

use ratatui::style::Color;

use crate::data::protocols::AppProtocol;
use crate::data::wire::{WireEventKind, WireTracker};
use crate::data::{Connection, GeoLocation, Protocol, TcpState};

// ─── Signal categories ──────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignalCategory {
    Protocol,
    Host,
    Country,
    Process,
    Event,
}

// ─── Public tag returned to the UI ──────────────────────────────

#[derive(Clone, Debug)]
pub struct SignalTag {
    pub label: String,
    pub category: SignalCategory,
    /// 0.0–1.0 — overall prominence (determines size / boldness).
    pub weight: f64,
    /// 0.0–1.0 — recency glow (hot = just hit, cools over ticks).
    pub heat: f64,
    /// Base color for rendering.
    pub color: Color,
}

// ─── Internal entry ─────────────────────────────────────────────

#[derive(Clone, Debug)]
struct SignalEntry {
    category: SignalCategory,
    weight: f64,
    heat: f64,
    color: Color,
}

// ─── Category summary for the header bar ────────────────────────

#[derive(Clone, Debug, Default)]
pub struct SignalSummary {
    pub total: usize,
    pub protocols: usize,
    pub hosts: usize,
    pub countries: usize,
    pub processes: usize,
    pub events: usize,
}

// ─── Signal Tracker ─────────────────────────────────────────────

pub struct SignalTracker {
    entries: HashMap<String, SignalEntry>,
    /// Sequence number of the last wire event we processed.
    prev_wire_seq: u64,
}

impl SignalTracker {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            prev_wire_seq: 0,
        }
    }

    /// Run one processing tick.  Decays existing tags, ingests current
    /// connections and new wire events, and prunes dead entries.
    pub fn process(
        &mut self,
        connections: &[Connection],
        wire: &WireTracker,
        geoip_cache: &HashMap<IpAddr, GeoLocation>,
        dns_cache: &HashMap<IpAddr, String>,
        attacks_recent: usize,
    ) {
        // ── Decay ────────────────────────────────────────────────
        const DECAY_WEIGHT: f64 = 0.93;
        const DECAY_HEAT: f64 = 0.78;

        for entry in self.entries.values_mut() {
            entry.weight *= DECAY_WEIGHT;
            entry.heat *= DECAY_HEAT;
        }

        // ── Active connections ───────────────────────────────────
        for conn in connections {
            if conn.state == TcpState::Listen {
                continue;
            }

            // Protocol — check both ports (remote first, like psnet)
            let is_tcp = conn.protocol == Protocol::Tcp;
            let proto_r = AppProtocol::from_port(conn.remote_addr.port(), is_tcp);
            let proto_l = AppProtocol::from_port(conn.local_addr.port(), is_tcp);
            let app_proto = if proto_r != AppProtocol::Other { proto_r } else { proto_l };

            if app_proto != AppProtocol::Other {
                self.bump(app_proto.label(), SignalCategory::Protocol, 0.04, app_proto.color());
            } else {
                // Bump transport protocol so TCP/UDP/ICMP/RAW are visible
                let (label, color) = match conn.protocol {
                    Protocol::Tcp => ("TCP", Color::Rgb(100, 180, 255)),
                    Protocol::Udp => ("UDP", Color::Rgb(130, 200, 130)),
                    Protocol::Icmp => ("ICMP", Color::Rgb(255, 180, 80)),
                    Protocol::Raw => ("RAW", Color::Rgb(200, 100, 200)),
                };
                self.bump(label, SignalCategory::Protocol, 0.04, color);
            }

            // Process
            if let Some(ref name) = conn.process_name {
                if name != "?" && !name.is_empty() {
                    self.bump(name, SignalCategory::Process, 0.025, Color::Rgb(180, 100, 255));
                }
            }

            // Hostname
            let ip = conn.remote_addr.ip();
            if let Some(hostname) = dns_cache.get(&ip) {
                let short = shorten_host(hostname, 28);
                self.bump(&short, SignalCategory::Host, 0.035, Color::Rgb(80, 200, 255));
            }

            // Country
            let geo = conn.geo.as_ref().or_else(|| geoip_cache.get(&ip));
            if let Some(g) = geo {
                if !g.country_code.is_empty() {
                    let color = country_color(&g.country_code);
                    self.bump(&g.country_code, SignalCategory::Country, 0.03, color);
                }
            }
        }

        // ── Wire events (new since last tick) ────────────────────
        let events = wire.events();
        for event in events.iter() {
            if event.seq <= self.prev_wire_seq {
                break;
            }

            let (event_label, event_color) = match &event.kind {
                WireEventKind::NewConnection => ("NEW", Color::Rgb(80, 200, 120)),
                WireEventKind::ConnectionClosed => ("CLOSED", Color::Rgb(255, 100, 100)),
                WireEventKind::StateChange { to, .. } => (to.label(), Color::Rgb(255, 200, 80)),
            };

            self.bump(event_label, SignalCategory::Event, 0.18, event_color);

            // Also bump the service protocol from the wire event
            if event.service != AppProtocol::Other {
                self.bump(
                    event.service.label(),
                    SignalCategory::Protocol,
                    0.12,
                    event.service.color(),
                );
            } else {
                // Bump transport protocol for full stack visibility
                let (label, color) = match event.protocol {
                    Protocol::Tcp => ("TCP", Color::Rgb(100, 180, 255)),
                    Protocol::Udp => ("UDP", Color::Rgb(130, 200, 130)),
                    Protocol::Icmp => ("ICMP", Color::Rgb(255, 180, 80)),
                    Protocol::Raw => ("RAW", Color::Rgb(200, 100, 200)),
                };
                self.bump(label, SignalCategory::Protocol, 0.12, color);
            }

            // Bump host from wire event
            if let Some(ref hostname) = event.hostname {
                let short = shorten_host(hostname, 28);
                self.bump(&short, SignalCategory::Host, 0.10, Color::Rgb(80, 200, 255));
            }

            // Bump country from wire event
            if !event.country_code.is_empty() {
                let color = country_color(&event.country_code);
                self.bump(&event.country_code, SignalCategory::Country, 0.08, color);
            }
        }

        if let Some(first) = events.front() {
            self.prev_wire_seq = first.seq;
        }

        // ── Attack events boost ─────────────────────────────────
        if attacks_recent > 0 {
            self.bump("ATTACK", SignalCategory::Event, 0.20, Color::Rgb(255, 40, 40));
        }

        // ── Prune dead entries ──────────────────────────────────
        self.entries.retain(|_, e| e.weight > 0.015);
    }

    /// Get sorted tags for the UI (heaviest first).
    pub fn tags(&self) -> Vec<SignalTag> {
        let mut tags: Vec<SignalTag> = self
            .entries
            .iter()
            .filter(|(_, e)| e.weight > 0.025)
            .map(|(label, entry)| SignalTag {
                label: label.clone(),
                category: entry.category,
                weight: entry.weight,
                heat: entry.heat,
                color: entry.color,
            })
            .collect();

        tags.sort_by(|a, b| {
            b.weight
                .partial_cmp(&a.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        tags
    }

    /// Summary counts by category for the header bar.
    pub fn summary(&self) -> SignalSummary {
        let mut s = SignalSummary::default();
        for entry in self.entries.values() {
            if entry.weight <= 0.025 {
                continue;
            }
            s.total += 1;
            match entry.category {
                SignalCategory::Protocol => s.protocols += 1,
                SignalCategory::Host => s.hosts += 1,
                SignalCategory::Country => s.countries += 1,
                SignalCategory::Process => s.processes += 1,
                SignalCategory::Event => s.events += 1,
            }
        }
        s
    }

    // ── Internal ─────────────────────────────────────────────────

    fn bump(&mut self, label: &str, category: SignalCategory, amount: f64, color: Color) {
        let entry = self.entries.entry(label.to_string()).or_insert(SignalEntry {
            category,
            weight: 0.0,
            heat: 0.0,
            color,
        });
        entry.weight = (entry.weight + amount).min(1.0);
        entry.heat = 1.0;
    }
}

impl Default for SignalTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────

fn shorten_host(host: &str, max: usize) -> String {
    if host.len() <= max {
        host.to_string()
    } else {
        // Keep the rightmost part (domain) which is most recognizable
        format!("..{}", &host[host.len() - (max - 2)..])
    }
}

fn country_color(cc: &str) -> Color {
    match cc {
        "US" => Color::Rgb(60, 140, 255),
        "CN" => Color::Rgb(255, 80, 80),
        "RU" => Color::Rgb(255, 160, 60),
        "DE" => Color::Rgb(255, 220, 80),
        "GB" => Color::Rgb(80, 200, 255),
        "FR" => Color::Rgb(100, 150, 255),
        "JP" => Color::Rgb(255, 140, 180),
        "KR" => Color::Rgb(130, 200, 140),
        "IN" => Color::Rgb(255, 180, 60),
        "BR" => Color::Rgb(80, 200, 120),
        "NL" => Color::Rgb(255, 140, 0),
        "SG" => Color::Rgb(200, 130, 255),
        "CA" => Color::Rgb(255, 100, 100),
        "AU" => Color::Rgb(255, 200, 60),
        _ => Color::Rgb(140, 160, 190),
    }
}
