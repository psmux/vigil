use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
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
///   map (60%): full-width braille world map with ALL connections
///   bottom_row: Horizontal [ country_bars (50%) | city_bars (50%) ]
/// ]
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(60),
            Constraint::Min(6),
        ])
        .split(area);

    draw_map(f, app, rows[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(rows[1]);

    draw_country_bars(f, app, bottom[0]);
    draw_city_bars(f, app, bottom[1]);
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

// ─── City Bars ───────────────────────────────────────────────────

fn draw_city_bars(f: &mut Frame, app: &App, area: Rect) {
    let mut city_counts: HashMap<String, usize> = HashMap::new();

    for conn in &app.connections {
        let ip = conn.remote_addr.ip();
        let geo = conn.geo.as_ref().or_else(|| app.geoip_cache.get(&ip));
        if let Some(geo) = geo {
            let city_name = geo
                .city
                .as_deref()
                .filter(|c| !c.is_empty())
                .unwrap_or(&geo.country_name);
            if !city_name.is_empty() {
                *city_counts.entry(city_name.to_string()).or_insert(0) += 1;
            }
        }
    }

    let mut sorted: Vec<(String, usize)> = city_counts.into_iter().collect();
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

    draw_bar_chart(f, area, "Connections by Region", &items, 8);
}
