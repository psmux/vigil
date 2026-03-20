//! Bandwidth tracker — samples /proc/net/dev and computes bytes-per-second deltas.

use std::collections::HashMap;
use std::time::Instant;

use crate::data::procfs;

/// Tracks bandwidth by periodically sampling /proc/net/dev and computing deltas.
pub struct BandwidthTracker {
    prev_stats: HashMap<String, (u64, u64)>,
    prev_time: Instant,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        // Take an initial sample so the first call to sample() has a baseline
        let mut prev_stats = HashMap::new();
        for (iface, rx, tx) in procfs::parse_proc_net_dev() {
        if iface == "lo" { continue; }
            prev_stats.insert(iface, (rx, tx));
        }

        Self {
            prev_stats,
            prev_time: Instant::now(),
        }
    }

    /// Sample /proc/net/dev and return the aggregate (rx_bps, tx_bps) across
    /// all interfaces since the last call.
    ///
    /// Returns `(0.0, 0.0)` if /proc is unavailable or on the first call.
    pub fn sample(&mut self) -> (f64, f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.prev_time).as_secs_f64();

        if elapsed < 0.001 {
            // Avoid division by zero if called too quickly
            return (0.0, 0.0);
        }

        let current = procfs::parse_proc_net_dev();

        let mut total_rx_delta: u64 = 0;
        let mut total_tx_delta: u64 = 0;

        let mut new_stats = HashMap::new();

        for (iface, rx, tx) in &current {
            new_stats.insert(iface.clone(), (*rx, *tx));
            if iface == "lo" { continue; }

            if let Some(&(prev_rx, prev_tx)) = self.prev_stats.get(iface) {
                // Handle counter wraps (unlikely but possible)
                let rx_delta = rx.saturating_sub(prev_rx);
                let tx_delta = tx.saturating_sub(prev_tx);
                total_rx_delta += rx_delta;
                total_tx_delta += tx_delta;
            }
        }

        self.prev_stats = new_stats;
        self.prev_time = now;

        let rx_bps = (total_rx_delta as f64) / elapsed; // bits per second
        let tx_bps = (total_tx_delta as f64) / elapsed;

        (rx_bps, tx_bps)
    }
}

impl Default for BandwidthTracker {
    fn default() -> Self {
        Self::new()
    }
}
