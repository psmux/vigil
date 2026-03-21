//! Outbound view (View 9) — per-app outbound connection tracking with
//! bandwidth, destination countries, first-seen detection, and world map.

use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::outbound::AppOutboundStats;
use crate::format::format_bps;
use crate::theme;
use crate::widgets::bar_chart::{draw_bar_chart, BarItem};
use crate::widgets::terminal_map::{country_center, draw_terminal_map, MapDot};

// ─── Color constants ────────────────────────────────────────────────
const OUTBOUND_COLOR: Color = Color::Rgb(0, 200, 160);
const NEW_COLOR: Color = Color::Rgb(255, 220, 80);
const UNUSUAL_COLOR: Color = Color::Rgb(255, 100, 60);

/// Draw the Outbound view (View 9).
///
/// Layout:
/// ```text
/// Vertical [
///   map (40%): world map showing OUTBOUND connections only
///   middle (35%): per-app outbound connection table
///   bottom (25%): Horizontal [ destination_bars | bandwidth_bars ]
/// ]
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(35),
            Constraint::Min(5),
        ])
        .split(area);

    draw_outbound_map(f, app, rows[0]);
    draw_app_table(f, app, rows[1]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(rows[2]);

    draw_destination_bars(f, app, bottom[0]);
    draw_bandwidth_bars(f, app, bottom[1]);
}

// ─── Outbound World Map ─────────────────────────────────────────────

fn draw_outbound_map(f: &mut Frame, app: &App, area: Rect) {
    let mut dots: Vec<MapDot> = Vec::new();

    for stats in &app.outbound_stats {
        for conn in &stats.connections {
            let ip = conn.remote_addr.ip();

            // Try geo from cache
            let geo = app.geoip_cache.get(&ip);

            let (lat, lon) = if let Some(geo) = geo {
                if geo.latitude == 0.0 && geo.longitude == 0.0 && geo.country_code.is_empty() {
                    continue;
                }
                (geo.latitude, geo.longitude)
            } else if let Some((lon, lat)) = country_center(&conn.country_code) {
                (lat, lon)
            } else {
                continue;
            };

            let color = if conn.is_new {
                NEW_COLOR
            } else if stats.bandwidth_unusual {
                UNUSUAL_COLOR
            } else {
                OUTBOUND_COLOR
            };

            let seed = match ip {
                std::net::IpAddr::V4(v4) => u32::from(v4),
                std::net::IpAddr::V6(v6) => {
                    let seg = v6.segments();
                    ((seg[6] as u32) << 16) | (seg[7] as u32)
                }
            };

            dots.push(MapDot {
                lat,
                lon,
                color,
                pulsing: conn.is_new || stats.bandwidth_unusual,
                radius: if stats.bandwidth_unusual { 2 } else { 1 },
                jitter_seed: seed,
            });
        }
    }

    draw_terminal_map(
        f,
        area,
        &dots,
        app.animation_frame,
        "Outbound Connections Map",
    );
}

// ─── Per-App Outbound Table ─────────────────────────────────────────

fn draw_app_table(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Outbound by Application ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 40 || inner.height < 2 {
        return;
    }

    // Header
    let header = Line::from(Span::styled(
        format!(
            "{:<16} {:>5} {:>4} {:<30} {:>10} {:>10}  {}",
            "Application", "Conns", "IPs", "Destinations", "Upload", "Download", "Flags"
        ),
        Style::default()
            .fg(theme::TEXT_DIM)
            .add_modifier(Modifier::BOLD),
    ));

    let visible_rows = (inner.height as usize).saturating_sub(1);
    let offset = app.scroll_offset.min(app.outbound_stats.len().saturating_sub(visible_rows));

    let mut lines: Vec<Line> = Vec::with_capacity(visible_rows + 1);
    lines.push(header);

    for stats in app.outbound_stats.iter().skip(offset).take(visible_rows) {
        lines.push(build_app_line(stats, inner.width as usize));
    }

    if app.outbound_stats.is_empty() {
        lines.push(Line::from(Span::styled(
            " (no outbound connections detected)",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

fn build_app_line(stats: &AppOutboundStats, _width: usize) -> Line<'static> {
    // App name (truncated)
    let app_name: String = if stats.app_name.len() > 16 {
        stats.app_name[..16].to_string()
    } else {
        format!("{:<16}", stats.app_name)
    };

    // Connection count
    let conn_str = format!("{:>5}", stats.conn_count);

    // Unique IPs
    let ips_str = format!("{:>4}", stats.unique_remotes);

    // Destination countries
    let dest_str: String = stats
        .countries
        .iter()
        .take(5)
        .map(|(cc, count)| format!("{}({})", cc, count))
        .collect::<Vec<_>>()
        .join(" ");
    let dest_display: String = if dest_str.len() > 30 {
        dest_str[..30].to_string()
    } else {
        format!("{:<30}", dest_str)
    };

    // Bandwidth
    let tx_str = format!("{:>10}", format_bps(stats.tx_bps));
    let rx_str = format!("{:>10}", format_bps(stats.rx_bps));

    // Flags
    let mut flags = Vec::new();
    if stats.has_new {
        flags.push("\u{26a1}NEW");
    }
    if stats.bandwidth_unusual {
        flags.push("\u{26a0}BW!");
    }
    let flags_str = flags.join(" ");

    let app_color = if stats.bandwidth_unusual {
        UNUSUAL_COLOR
    } else if stats.has_new {
        NEW_COLOR
    } else {
        theme::GREEN
    };

    let mut spans: Vec<Span<'static>> = vec![
        Span::styled(app_name, Style::default().fg(app_color)),
        Span::raw(" "),
        Span::styled(conn_str, Style::default().fg(theme::CYAN)),
        Span::raw(" "),
        Span::styled(ips_str, Style::default().fg(theme::TEXT)),
        Span::raw(" "),
        Span::styled(dest_display, Style::default().fg(OUTBOUND_COLOR)),
        Span::raw(" "),
        Span::styled(tx_str, Style::default().fg(theme::UPLOAD)),
        Span::raw(" "),
        Span::styled(rx_str, Style::default().fg(theme::DOWNLOAD)),
        Span::raw("  "),
    ];

    if !flags_str.is_empty() {
        let flag_color = if stats.bandwidth_unusual {
            UNUSUAL_COLOR
        } else {
            NEW_COLOR
        };
        spans.push(Span::styled(
            flags_str,
            Style::default()
                .fg(flag_color)
                .add_modifier(Modifier::BOLD),
        ));
    }

    Line::from(spans)
}

// ─── Destination Country Bars ───────────────────────────────────────

fn draw_destination_bars(f: &mut Frame, app: &App, area: Rect) {
    let mut country_counts: HashMap<String, u32> = HashMap::new();

    for stats in &app.outbound_stats {
        for (cc, count) in &stats.countries {
            *country_counts.entry(cc.clone()).or_insert(0) += count;
        }
    }

    let mut sorted: Vec<(String, u32)> = country_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(8);

    let items: Vec<BarItem> = sorted
        .iter()
        .map(|(code, count)| BarItem {
            label: code.clone(),
            value: *count as f64,
            color: OUTBOUND_COLOR,
            suffix: None,
        })
        .collect();

    draw_bar_chart(f, area, "Outbound Destinations", &items, 8);
}

// ─── Per-App Bandwidth Bars ─────────────────────────────────────────

fn draw_bandwidth_bars(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<BarItem> = app
        .outbound_stats
        .iter()
        .take(8)
        .map(|s| {
            let color = if s.bandwidth_unusual {
                UNUSUAL_COLOR
            } else {
                theme::UPLOAD
            };
            BarItem {
                label: if s.app_name.len() > 12 {
                    s.app_name[..12].to_string()
                } else {
                    s.app_name.clone()
                },
                value: s.tx_bps,
                color,
                suffix: Some(format!(" {}", format_bps(s.tx_bps))),
            }
        })
        .collect();

    draw_bar_chart(f, area, "Upload by App", &items, 8);
}
