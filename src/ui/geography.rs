use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::TcpState;
use crate::theme;
use crate::widgets::bar_chart::{draw_bar_chart, BarItem};
use crate::widgets::braille_map::{country_center, draw_world_map, MapDot};

/// Draw the Geography view (View 5).
///
/// Layout:
/// ```text
/// Vertical [
///   map (55%): full-width braille world map with ALL connections
///   bottom_row: Horizontal [ country_bars (33%) | app_country_matrix (34%) | top_apps (33%) ]
/// ]
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(55),
            Constraint::Min(6),
        ])
        .split(area);

    draw_map(f, app, rows[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(rows[1]);

    draw_country_bars(f, app, bottom[0]);
    draw_app_country_matrix(f, app, bottom[1]);
    draw_top_apps(f, app, bottom[2]);
}

// ─── World Map ───────────────────────────────────────────────────

fn draw_map(f: &mut Frame, app: &App, area: Rect) {
    let mut dots: Vec<MapDot> = Vec::new();

    for conn in &app.connections {
        let ip = conn.remote_addr.ip();

        // Try per-connection geo first, then the geoip_cache
        let geo = conn.geo.as_ref().or_else(|| app.geoip_cache.get(&ip));

        if let Some(geo) = geo {
            if geo.latitude == 0.0 && geo.longitude == 0.0 && geo.country_code.is_empty() {
                continue;
            }

            let color = if conn.is_threat { theme::RED } else { theme::GREEN };
            // Active / recently established connections pulse
            let pulsing = conn.state == TcpState::Established || conn.state == TcpState::SynSent;

            // Use IP octets as a deterministic jitter seed
            let seed = match ip {
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
        } else if let Some((lon, lat)) = lookup_country_for_ip(app, &ip) {
            // Fallback: use country center coordinates from cache
            let color = if conn.is_threat { theme::RED } else { theme::GREEN };
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
                pulsing: conn.state == TcpState::Established,
                radius: 1,
                jitter_seed: seed,
            });
        }
    }

    draw_world_map(f, area, &dots, app.animation_frame, "Connections World Map");
}

/// Try to find country center coordinates for an IP via the geoip_cache.
fn lookup_country_for_ip(app: &App, ip: &std::net::IpAddr) -> Option<(f64, f64)> {
    let geo = app.geoip_cache.get(ip)?;
    if !geo.country_code.is_empty() {
        country_center(&geo.country_code)
    } else {
        None
    }
}

// ─── Country Bars ────────────────────────────────────────────────

fn draw_country_bars(f: &mut Frame, app: &App, area: Rect) {
    let mut country_counts: HashMap<String, usize> = HashMap::new();
    let mut countries_with_threats: HashMap<String, bool> = HashMap::new();

    for conn in &app.connections {
        let ip = conn.remote_addr.ip();
        let geo = conn.geo.as_ref().or_else(|| app.geoip_cache.get(&ip));
        if let Some(geo) = geo {
            if !geo.country_code.is_empty() {
                *country_counts.entry(geo.country_code.clone()).or_insert(0) += 1;
                if conn.is_threat {
                    countries_with_threats.insert(geo.country_code.clone(), true);
                }
            }
        }
    }

    let mut sorted: Vec<(String, usize)> = country_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(8);

    let items: Vec<BarItem> = sorted
        .iter()
        .map(|(code, count)| {
            let has_attacks = countries_with_threats.contains_key(code);
            BarItem {
                label: code.clone(),
                value: *count as f64,
                color: if has_attacks { theme::RED } else { theme::ACCENT },
                suffix: if has_attacks {
                    Some(" \u{2620}".into()) // skull and crossbones
                } else {
                    None
                },
            }
        })
        .collect();

    draw_bar_chart(f, area, "Connections by Country", &items, 8);
}

// ─── App → Country Matrix ────────────────────────────────────────

/// Color for a country code — cycles through a palette for visual distinction.
fn country_color(code: &str) -> Color {
    let palette = [
        theme::CYAN,
        theme::ACCENT,
        theme::PURPLE,
        theme::GOLD,
        theme::GREEN,
        Color::Rgb(255, 140, 100), // orange
        Color::Rgb(180, 220, 100), // lime
        Color::Rgb(200, 160, 255), // lavender
    ];
    let hash: usize = code.bytes().fold(0usize, |acc, b| acc.wrapping_add(b as usize));
    palette[hash % palette.len()]
}

fn draw_app_country_matrix(f: &mut Frame, app: &App, area: Rect) {
    // Build HashMap<process_name, HashMap<country_code, count>>
    let mut app_countries: HashMap<String, HashMap<String, u32>> = HashMap::new();

    for conn in &app.connections {
        if conn.state != TcpState::Listen && conn.state != TcpState::Close {
            let proc_name = conn.process_name.clone().unwrap_or_else(|| "unknown".into());
            if let Some(geo) = &conn.geo {
                if !geo.country_code.is_empty() {
                    *app_countries
                        .entry(proc_name)
                        .or_default()
                        .entry(geo.country_code.clone())
                        .or_insert(0) += 1;
                }
            }
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " App \u{2192} Country ",
            Style::default()
                .fg(Color::Rgb(160, 180, 220))
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height == 0 {
        return;
    }

    // Sort apps by total connection count descending
    let mut app_list: Vec<(String, HashMap<String, u32>)> = app_countries.into_iter().collect();
    app_list.sort_by(|a, b| {
        let sum_a: u32 = a.1.values().sum();
        let sum_b: u32 = b.1.values().sum();
        sum_b.cmp(&sum_a)
    });

    let max_rows = inner.height as usize;
    let label_width: usize = 14;

    let mut lines: Vec<Line> = Vec::new();

    for (proc_name, countries) in app_list.iter().take(max_rows) {
        let mut country_vec: Vec<(&String, &u32)> = countries.iter().collect();
        country_vec.sort_by(|a, b| b.1.cmp(a.1));

        // Truncate or pad process name
        let truncated: String = if proc_name.len() > label_width {
            proc_name[..label_width].to_string()
        } else {
            format!("{:<width$}", proc_name, width = label_width)
        };

        let mut spans: Vec<Span> = vec![
            Span::styled(
                truncated,
                Style::default().fg(theme::GREEN),
            ),
            Span::raw(" "),
        ];

        // Add country codes with counts
        let mut remaining_width = (inner.width as usize).saturating_sub(label_width + 1);

        for (code, count) in &country_vec {
            let entry = format!("{}({}) ", code, count);
            let entry_len = entry.len();
            if entry_len > remaining_width {
                break;
            }
            spans.push(Span::styled(
                entry,
                Style::default().fg(country_color(code)),
            ));
            remaining_width = remaining_width.saturating_sub(entry_len);
        }

        lines.push(Line::from(spans));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " (no active connections with geo data)",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

// ─── Top Apps ────────────────────────────────────────────────────

fn draw_top_apps(f: &mut Frame, app: &App, area: Rect) {
    let mut process_counts: HashMap<String, usize> = HashMap::new();

    for conn in &app.connections {
        // Exclude LISTEN state — we want active outbound/established connections
        if conn.state == TcpState::Listen {
            continue;
        }
        let proc_name = conn
            .process_name
            .clone()
            .unwrap_or_else(|| "<unknown>".into());
        *process_counts.entry(proc_name).or_insert(0) += 1;
    }

    let mut sorted: Vec<(String, usize)> = process_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(8);

    let items: Vec<BarItem> = sorted
        .iter()
        .map(|(name, count)| BarItem {
            label: name.clone(),
            value: *count as f64,
            color: theme::CYAN,
            suffix: None,
        })
        .collect();

    draw_bar_chart(f, area, "Top Apps (connections)", &items, 8);
}
