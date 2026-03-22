//! Protocol tracker — direct port of psnet's ProtocolTracker.
//!
//! Tracks which network protocols are active, their counts, and recency.
//! Provides brightness-based fading over a configurable tick window.

use std::collections::HashMap;
use ratatui::style::Color;

use crate::data::protocols::AppProtocol;
use crate::data::{Connection, Protocol, TcpState};

// ─── Activity record (per protocol) ─────────────────────────────────

/// Activity record for a single protocol — mirrors psnet's ProtocolActivity.
pub struct ProtocolActivity {
    /// Total observations ever recorded.
    pub count: u64,
    /// Tick when this protocol was last seen.
    pub last_tick: u64,
    /// Observations in the recent window (last `fade_ticks` ticks).
    pub recent_count: u64,
    /// Per-tick ring buffer for computing recent_count.
    tick_counts: Vec<u64>,
    /// Current index into the ring buffer.
    tick_ring_idx: usize,
    /// Last tick when the ring was advanced.
    last_ring_tick: u64,
}

impl ProtocolActivity {
    fn new(fade_ticks: u64) -> Self {
        Self {
            count: 0,
            last_tick: 0,
            recent_count: 0,
            tick_counts: vec![0; fade_ticks as usize],
            tick_ring_idx: 0,
            last_ring_tick: 0,
        }
    }

    /// Advance the ring buffer to the current tick, zeroing skipped slots.
    fn advance_to(&mut self, tick: u64) {
        if self.last_ring_tick == 0 && self.count == 0 {
            self.last_ring_tick = tick;
            return;
        }
        let steps = tick.saturating_sub(self.last_ring_tick);
        if steps == 0 {
            return;
        }
        let len = self.tick_counts.len();
        let steps = steps.min(len as u64) as usize;
        for _ in 0..steps {
            self.tick_ring_idx = (self.tick_ring_idx + 1) % len;
            self.recent_count = self
                .recent_count
                .saturating_sub(self.tick_counts[self.tick_ring_idx]);
            self.tick_counts[self.tick_ring_idx] = 0;
        }
        self.last_ring_tick = tick;
    }

    fn record(&mut self, tick: u64, amount: u64) {
        self.advance_to(tick);
        self.count += amount;
        self.last_tick = tick;
        self.tick_counts[self.tick_ring_idx] += amount;
        self.recent_count += amount;
    }
}

// ─── Protocol Tracker ───────────────────────────────────────────────

/// Tracks protocol activity with tick-based fading — mirrors psnet's ProtocolTracker.
pub struct ProtocolTracker {
    activity: HashMap<String, (ProtocolActivity, Color)>,
    /// How many ticks before a protocol fades to invisible.
    pub fade_ticks: u64,
}

impl ProtocolTracker {
    pub fn new() -> Self {
        Self {
            activity: HashMap::new(),
            fade_ticks: 10,
        }
    }

    /// Record observations for a named protocol.
    pub fn record(&mut self, label: &str, color: Color, tick: u64, amount: u64) {
        let fade = self.fade_ticks;
        let (activity, stored_color) = self
            .activity
            .entry(label.to_string())
            .or_insert_with(|| (ProtocolActivity::new(fade), color));
        *stored_color = color;
        activity.record(tick, amount);
    }

    /// Ingest the full connection table + all low-level protocol sources.
    /// Called every tick from App::tick().
    pub fn process(
        &mut self,
        connections: &[Connection],
        low_level: &[(&str, usize)],
        tick: u64,
    ) {
        // Advance all ring buffers so stale protocols fade even if unseen
        for (activity, _) in self.activity.values_mut() {
            activity.advance_to(tick);
        }

        // Count connections per effective protocol
        let mut counts: HashMap<&str, (u64, Color)> = HashMap::new();

        for conn in connections {
            if conn.state == TcpState::Listen {
                continue;
            }

            let is_tcp = conn.protocol == Protocol::Tcp;
            let proto_r = AppProtocol::from_port(conn.remote_addr.port(), is_tcp);
            let proto_l = AppProtocol::from_port(conn.local_addr.port(), is_tcp);
            let app_proto = if proto_r != AppProtocol::Other {
                proto_r
            } else {
                proto_l
            };

            let (label, color): (&str, Color) = if app_proto != AppProtocol::Other {
                (app_proto.label(), app_proto.color())
            } else {
                match conn.protocol {
                    Protocol::Tcp => ("TCP", Color::Rgb(100, 180, 255)),
                    Protocol::Udp => ("UDP", Color::Rgb(130, 200, 130)),
                    Protocol::Icmp => ("ICMP", Color::Rgb(255, 180, 80)),
                    Protocol::Raw => ("RAW", Color::Rgb(200, 100, 200)),
                }
            };

            let entry = counts.entry(label).or_insert((0, color));
            entry.0 += 1;
        }

        // Record socket-based protocols
        for (&label, &(count, color)) in &counts {
            self.record(label, color, tick, count);
        }

        // Record ALL low-level protocols (ARP, IGMP, Unix, Netlink, etc.)
        for &(label, count) in low_level {
            if count > 0 {
                let color = low_level_color(label);
                self.record(label, color, tick, count as u64);
            }
        }
    }

    /// Returns protocols sorted by: active first, then by total count descending.
    pub fn active_protocols(&self, current_tick: u64) -> Vec<(&str, &ProtocolActivity, Color)> {
        let mut protos: Vec<(&str, &ProtocolActivity, Color)> = self
            .activity
            .iter()
            .filter(|(_, (a, _))| a.count > 0)
            .map(|(label, (activity, color))| (label.as_str(), activity, *color))
            .collect();

        let fade = self.fade_ticks;
        protos.sort_by(|a, b| {
            let a_active = current_tick.saturating_sub(a.1.last_tick) <= fade;
            let b_active = current_tick.saturating_sub(b.1.last_tick) <= fade;
            match (a_active, b_active) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b.1.count.cmp(&a.1.count),
            }
        });
        protos
    }

    /// Brightness from 1.0 (just seen) fading to 0.0 over fade_ticks.
    pub fn brightness(&self, label: &str, current_tick: u64) -> f64 {
        if let Some((activity, _)) = self.activity.get(label) {
            let age = current_tick.saturating_sub(activity.last_tick);
            if age >= self.fade_ticks {
                0.0
            } else {
                1.0 - (age as f64 / self.fade_ticks as f64)
            }
        } else {
            0.0
        }
    }
}

impl Default for ProtocolTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Distinct color for each low-level protocol.
fn low_level_color(label: &str) -> Color {
    match label {
        "ARP" => Color::Rgb(200, 180, 80),
        "IGMP" => Color::Rgb(180, 200, 100),
        "MLD" => Color::Rgb(140, 200, 140),
        "IPv6" => Color::Rgb(100, 160, 255),
        "Unix" => Color::Rgb(160, 140, 200),
        "Netlink" => Color::Rgb(120, 180, 160),
        "Packet" => Color::Rgb(200, 120, 120),
        "SCTP" => Color::Rgb(200, 160, 100),
        "DCCP" => Color::Rgb(180, 120, 180),
        "WiFi" => Color::Rgb(100, 200, 200),
        "DHCP" => Color::Rgb(180, 140, 255),
        _ => Color::Rgb(140, 140, 140),
    }
}
