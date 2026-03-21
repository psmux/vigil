use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::data::PortRisk;
use crate::data::alerts::AlertSeverity;
use crate::format::{format_bps, format_count};
use crate::theme;
use crate::widgets::bar_chart::{self, BarItem};
use crate::widgets::braille_map::MapDot;
use crate::widgets::terminal_map;
use crate::widgets::gauge;
use crate::widgets::kpi_badge;
use crate::widgets::sparkline;

/// Draw the Command Center (View 1) — the main dashboard.
///
/// Layout:
/// ```text
/// top_row (45%):  [ score_gauge (20%) | attack_map (80%) ]
/// kpi_strip (5):  [ ATTACKS | DOORS | CONNS | BLOCKED | BANNED | ALERTS ]
/// bottom_row:     [ bandwidth_sparklines (40%) | top_attackers_bar (60%) ]
/// doors_strip (3): compact port exposure summary
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(45), // top row
            Constraint::Length(5),       // KPI strip
            Constraint::Min(6),          // bottom row
            Constraint::Length(3),       // doors strip
        ])
        .split(area);

    // ── Top row: score gauge + attack map ────────────────────────
    draw_top_row(f, app, main_chunks[0]);

    // ── KPI strip ────────────────────────────────────────────────
    draw_kpi_strip(f, app, main_chunks[1]);

    // ── Bottom row: bandwidth sparklines + top attackers bar ─────
    draw_bottom_row(f, app, main_chunks[2]);

    // ── Doors strip ──────────────────────────────────────────────
    draw_doors_strip(f, app, main_chunks[3]);
}

fn draw_top_row(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20), // score gauge
            Constraint::Percentage(80), // attack map
        ])
        .split(area);

    // Score gauge
    gauge::draw_score_gauge(f, cols[0], app.security_score, app.score_delta_1h);

    // Attack map — build dots from connections + aggregated attackers
    let mut dots: Vec<MapDot> = Vec::new();

    // Connection dots: green for normal, red for threats
    for conn in &app.connections {
        if let Some(geo) = &conn.geo {
            let (color, pulsing) = if conn.is_threat {
                (theme::RED, true)
            } else {
                (theme::GREEN, false)
            };
            let seed = match conn.remote_addr.ip() {
                std::net::IpAddr::V4(v4) => u32::from(v4),
                std::net::IpAddr::V6(v6) => {
                    let seg = v6.segments();
                    ((seg[6] as u32) << 16) | (seg[7] as u32)
                }
            };
            dots.push(MapDot {
                lat: geo.latitude,
                lon: geo.longitude,
                color,
                pulsing,
                radius: if conn.is_threat { 2 } else { 1 },
                jitter_seed: seed,
            });
        }
    }

    // Attack dots: one per unique attacker IP (from aggregated list), all red, pulsing
    for agg in &app.attackers_sorted {
        if let Some(geo) = app.geoip_cache.get(&agg.source_ip) {
            let seed = match agg.source_ip {
                std::net::IpAddr::V4(v4) => u32::from(v4),
                std::net::IpAddr::V6(v6) => {
                    let seg = v6.segments();
                    ((seg[6] as u32) << 16) | (seg[7] as u32)
                }
            };
            dots.push(MapDot {
                lat: geo.latitude,
                lon: geo.longitude,
                color: theme::RED,
                pulsing: true,
                radius: 2,
                jitter_seed: seed,
            });
        }
    }

    terminal_map::draw_terminal_map(f, cols[1], &dots, app.animation_frame, "Attack Map");
}

fn draw_kpi_strip(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
        ])
        .split(area);

    // ATTACKS
    kpi_badge::draw_kpi_badge(
        f,
        cols[0],
        "ATTACKS",
        &format_count(app.attack_count_total),
        "total",
        theme::DANGER,
    );

    // DOORS — exposed / total ports
    let total_ports = app.ports.len();
    let exposed = app.ports.iter().filter(|p| p.risk != PortRisk::Safe).count();
    kpi_badge::draw_kpi_badge(
        f,
        cols[1],
        "DOORS",
        &format!("{}/{}", exposed, total_ports),
        "exposed",
        if exposed > 0 { theme::WARN } else { theme::SAFE },
    );

    // CONNS
    kpi_badge::draw_kpi_badge(
        f,
        cols[2],
        "CONNS",
        &format_count(app.connections.len() as u64),
        "active",
        theme::ACCENT,
    );

    // BLOCKED — firewall deny hits
    let deny_hits: u64 = app
        .firewall_rules
        .iter()
        .filter(|r| r.action == crate::data::FirewallAction::Deny)
        .map(|r| r.hits)
        .sum();
    kpi_badge::draw_kpi_badge(
        f,
        cols[3],
        "BLOCKED",
        &format_count(deny_hits),
        "denied",
        theme::GOLD,
    );

    // BANNED
    kpi_badge::draw_kpi_badge(
        f,
        cols[4],
        "BANNED",
        &format_count(app.banned_ips.len() as u64),
        "IPs",
        theme::PURPLE,
    );

    // ALERTS — unread alert count with severity-based coloring
    let unread = app.alert_engine.unread_count();
    let alert_color = match app.alert_engine.highest_unread_severity() {
        Some(AlertSeverity::Crit) => theme::DANGER,
        Some(AlertSeverity::Warn) => theme::GOLD,
        Some(AlertSeverity::Info) => theme::BLUE,
        None => theme::SAFE,
    };
    let alert_subtitle = if unread == 0 { "all clear" } else { "unread" };
    kpi_badge::draw_kpi_badge(
        f,
        cols[5],
        "ALERTS",
        &format_count(unread as u64),
        alert_subtitle,
        alert_color,
    );
}

fn draw_bottom_row(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // bandwidth sparklines
            Constraint::Percentage(60), // top attackers bar
        ])
        .split(area);

    // Bandwidth sparklines — download + upload stacked vertically
    let spark_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(cols[0]);

    let rx_data: Vec<f64> = app.bandwidth_rx.as_slice_ordered().iter().map(|v| **v).collect();
    let tx_data: Vec<f64> = app.bandwidth_tx.as_slice_ordered().iter().map(|v| **v).collect();

    sparkline::draw_sparkline(
        f,
        spark_rows[0],
        &rx_data,
        theme::DOWNLOAD,
        "Download",
        &format_bps(app.current_rx_bps),
    );

    sparkline::draw_sparkline(
        f,
        spark_rows[1],
        &tx_data,
        theme::UPLOAD,
        "Upload",
        &format_bps(app.current_tx_bps),
    );

    // Top attackers bar chart
    let items: Vec<BarItem> = app
        .top_attacker_countries
        .iter()
        .take(10)
        .map(|(code, count)| BarItem {
            label: code.clone(),
            value: *count as f64,
            color: theme::RED,
            suffix: Some("hits".into()),
        })
        .collect();

    bar_chart::draw_bar_chart(f, cols[1], "Top Attacker Countries", &items, 10);
}

fn draw_doors_strip(f: &mut Frame, app: &App, area: Rect) {
    if app.ports.is_empty() {
        let line = Line::from(Span::styled(
            " No listening ports detected",
            Style::default().fg(theme::TEXT_DIM),
        ));
        let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
        f.render_widget(paragraph, area);
        return;
    }

    let safe_count = app.ports.iter().filter(|p| p.risk == PortRisk::Safe).count();
    let shielded_count = app.ports.iter().filter(|p| p.risk == PortRisk::Shielded).count();
    let exposed_count = app.ports.iter().filter(|p| p.risk == PortRisk::Exposed).count();
    let critical_count = app.ports.iter().filter(|p| p.risk == PortRisk::Critical).count();

    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(
        " Ports: ",
        Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
    ));

    // Render each port as a colored dot
    for port in &app.ports {
        let dot_color = theme::risk_color(port.risk);
        spans.push(Span::styled(
            format!("\u{25CF}{} ", port.port),
            Style::default().fg(dot_color),
        ));
    }

        // Summary counts
    spans.push(Span::styled(
        " \u{2500}\u{2500} ",
        Style::default().fg(theme::SEPARATOR),
    ));
    spans.push(Span::styled(
        format!("{} safe", safe_count),
        Style::default().fg(theme::SAFE),
    ));
    spans.push(Span::styled(" ", Style::default()));
    spans.push(Span::styled(
        format!("{} shielded", shielded_count),
        Style::default().fg(theme::SHIELDED),
    ));
    spans.push(Span::styled(" ", Style::default()));
    spans.push(Span::styled(
        format!("{} exposed", exposed_count),
        Style::default().fg(theme::WARN),
    ));
    spans.push(Span::styled(" ", Style::default()));
    spans.push(Span::styled(
        format!("{} critical", critical_count),
        Style::default().fg(theme::DANGER),
    ));

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, area);
}
