use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;

use crate::app::App;
use crate::data::{Connection, Direction as ConnDirection, TcpState};
use crate::format::{format_bps, format_count};
use crate::theme;
use crate::widgets::bar_chart::{draw_bar_chart, BarItem};
use crate::widgets::kpi_badge::draw_kpi_badge;
use crate::widgets::line_chart::{draw_line_chart, ChartSeries};

/// Draw the Network Pulse view (View 4).
///
/// Layout:
/// ```text
/// Vertical [
///   throughput_chart (50%)
///   bottom_row: Horizontal [
///     connection_flow (40%): KPI boxes + state bar chart
///     right_col (60%): Vertical [ destination_bars (50%) | process_bars (50%) ]
///   ]
/// ]
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Min(8),
        ])
        .split(area);

    draw_throughput_chart(f, app, rows[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(rows[1]);

    draw_connection_flow(f, app, bottom[0]);

    let right_col = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(bottom[1]);

    draw_destination_bars(f, app, right_col[0]);
    draw_process_bars(f, app, right_col[1]);
}

// ─── Throughput Chart ────────────────────────────────────────────

fn draw_throughput_chart(f: &mut Frame, app: &App, area: Rect) {
    let ordered = app.throughput_history.as_slice_ordered();

    let download_data: Vec<f64> = ordered.iter().map(|(rx, _)| *rx).collect();
    let upload_data: Vec<f64> = ordered.iter().map(|(_, tx)| *tx).collect();

    let series = vec![
        ChartSeries {
            data: download_data,
            color: theme::DOWNLOAD,
            label: format!("Download {}", format_bps(app.current_rx_bps)),
        },
        ChartSeries {
            data: upload_data,
            color: theme::UPLOAD,
            label: format!("Upload {}", format_bps(app.current_tx_bps)),
        },
    ];

    // Generate time labels spanning the last 5 minutes
    let time_labels: Vec<String> = (0..6)
        .map(|i| format!("-{}m", 5 - i))
        .collect();

    draw_line_chart(f, area, "Throughput", &series, &time_labels);
}

// ─── Connection Flow ─────────────────────────────────────────────

fn draw_connection_flow(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // KPI boxes row
            Constraint::Min(4),   // state bar chart
        ])
        .split(area);

    // KPI boxes: inbound vs outbound
    let kpi_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(chunks[0]);

    let inbound_count = app
        .connections
        .iter()
        .filter(|c| c.direction == ConnDirection::Inbound)
        .count();
    let outbound_count = app
        .connections
        .iter()
        .filter(|c| c.direction == ConnDirection::Outbound)
        .count();

    draw_kpi_badge(
        f,
        kpi_row[0],
        "Inbound",
        &format_count(inbound_count as u64),
        "connections",
        theme::CYAN,
    );
    draw_kpi_badge(
        f,
        kpi_row[1],
        "Outbound",
        &format_count(outbound_count as u64),
        "connections",
        theme::PURPLE,
    );

    // State bar chart: aggregate connections by TCP state
    let state_counts = aggregate_by_state(&app.connections);
    let items: Vec<BarItem> = state_counts
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(state, count)| BarItem {
            label: state.label().to_string(),
            value: *count as f64,
            color: theme::state_color(*state),
            suffix: None,
        })
        .collect();

    draw_bar_chart(f, chunks[1], "Connection States", &items, 12);
}

/// Aggregate connections by TCP state, returning (state, count) pairs
/// sorted by count descending.
fn aggregate_by_state(connections: &[Connection]) -> Vec<(TcpState, usize)> {
    let mut map: HashMap<TcpState, usize> = HashMap::new();
    for conn in connections {
        *map.entry(conn.state).or_insert(0) += 1;
    }
    let mut pairs: Vec<(TcpState, usize)> = map.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1));
    pairs
}

// ─── Destination Bars ────────────────────────────────────────────

fn draw_destination_bars(f: &mut Frame, app: &App, area: Rect) {
    let mut dest_counts: HashMap<String, usize> = HashMap::new();
    for conn in &app.connections {
        let ip = conn.remote_addr.ip();
        let name = app
            .dns_cache
            .get(&ip)
            .cloned()
            .unwrap_or_else(|| ip.to_string());
        *dest_counts.entry(name).or_insert(0) += 1;
    }

    let mut sorted: Vec<(String, usize)> = dest_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(5);

    let items: Vec<BarItem> = sorted
        .iter()
        .map(|(name, count)| BarItem {
            label: name.clone(),
            value: *count as f64,
            color: theme::ACCENT,
            suffix: Some("conns".into()),
        })
        .collect();

    draw_bar_chart(f, area, "Top Destinations", &items, 5);
}

// ─── Process Bars ────────────────────────────────────────────────

fn draw_process_bars(f: &mut Frame, app: &App, area: Rect) {
    let mut proc_counts: HashMap<String, usize> = HashMap::new();
    for conn in &app.connections {
        let name = conn
            .process_name
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        *proc_counts.entry(name).or_insert(0) += 1;
    }

    let mut sorted: Vec<(String, usize)> = proc_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(5);

    let items: Vec<BarItem> = sorted
        .iter()
        .map(|(name, count)| BarItem {
            label: name.clone(),
            value: *count as f64,
            color: theme::PURPLE,
            suffix: Some("conns".into()),
        })
        .collect();

    draw_bar_chart(f, area, "Top Processes", &items, 5);
}
