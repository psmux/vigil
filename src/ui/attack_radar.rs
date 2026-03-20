use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::AttackType;
use crate::format::{format_count, format_time_ago};
use crate::theme;
use crate::widgets::bar_chart::{self, BarItem};
use crate::widgets::braille_map::{self, MapDot};
use crate::widgets::heatmap;

/// Draw the Attack Radar (View 2).
///
/// Layout:
/// ```text
/// heatmap (7 lines):   24-hour attack heatmap
/// middle (50%):        [ attack_type_bars (40%) | origins_map (60%) ]
/// attacker_table:      scrollable table of top attacker IPs
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),   // heatmap
            Constraint::Percentage(50), // middle row
            Constraint::Min(5),      // attacker table
        ])
        .split(area);

    // ── Heatmap ──────────────────────────────────────────────────
    let current_hour = chrono::Utc::now().format("%H").to_string()
        .parse::<u8>()
        .unwrap_or(0);
    heatmap::draw_heatmap(
        f,
        chunks[0],
        "Attack Heatmap (24h)",
        &app.attacks_24h,
        current_hour,
    );

    // ── Middle row: attack type bars + origins map ───────────────
    let mid_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(chunks[1]);

    draw_attack_type_bars(f, app, mid_cols[0]);
    draw_origins_map(f, app, mid_cols[1]);

    // ── Attacker table ───────────────────────────────────────────
    draw_attacker_table(f, app, chunks[2]);
}

fn draw_attack_type_bars(f: &mut Frame, app: &App, area: Rect) {
    // Aggregate attacks by type
    let mut type_counts: HashMap<AttackType, u64> = HashMap::new();
    for attack in &app.attacks {
        *type_counts.entry(attack.attack_type).or_insert(0) += attack.count as u64;
    }

    let mut items: Vec<BarItem> = type_counts
        .iter()
        .map(|(atype, count)| {
            let color = match atype {
                AttackType::SshBrute => theme::RED,
                AttackType::PortScan => theme::WARN,
                AttackType::HttpProbe => theme::CYAN,
                AttackType::SmtpProbe => theme::PURPLE,
                AttackType::Other => theme::TEXT_DIM,
            };
            BarItem {
                label: atype.label().to_string(),
                value: *count as f64,
                color,
                suffix: None,
            }
        })
        .collect();

    items.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap_or(std::cmp::Ordering::Equal));

    bar_chart::draw_bar_chart(f, area, "Attack Types", &items, 10);
}

fn draw_origins_map(f: &mut Frame, app: &App, area: Rect) {
    // Build dots from attacks only (all red, pulsing)
    let mut dots: Vec<MapDot> = Vec::new();

    for attack in &app.attacks {
        if let Some(geo) = app.geoip_cache.get(&attack.source_ip) {
            let seed = match attack.source_ip {
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

    braille_map::draw_world_map(f, area, &dots, app.animation_frame, "Attack Origins");
}

fn draw_attacker_table(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Top Attackers ",
            Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 40 || inner.height == 0 {
        return;
    }

    // Aggregate attacks by source IP
    let mut ip_agg: HashMap<std::net::IpAddr, (u64, Option<chrono::DateTime<chrono::Utc>>)> = HashMap::new();
    for attack in &app.attacks {
        let entry = ip_agg.entry(attack.source_ip).or_insert((0, None));
        entry.0 += attack.count as u64;
        match entry.1 {
            None => entry.1 = Some(attack.timestamp),
            Some(prev) if attack.timestamp > prev => entry.1 = Some(attack.timestamp),
            _ => {}
        }
    }

    let mut sorted: Vec<(std::net::IpAddr, u64, Option<chrono::DateTime<chrono::Utc>>)> = ip_agg
        .into_iter()
        .map(|(ip, (count, ts))| (ip, count, ts))
        .collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let max_count = sorted.first().map(|s| s.1).unwrap_or(1).max(1);

    // Header
    let header = Line::from(vec![
        Span::styled(
            format!("{:<18}", "IP"),
            Style::default().fg(theme::TEXT_DIM).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<6}", "CC"),
            Style::default().fg(theme::TEXT_DIM).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:>8}", "Attempts"),
            Style::default().fg(theme::TEXT_DIM).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  ",
            Style::default(),
        ),
        Span::styled(
            format!("{:<12}", "Intensity"),
            Style::default().fg(theme::TEXT_DIM).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<8}", "Status"),
            Style::default().fg(theme::TEXT_DIM).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Time",
            Style::default().fg(theme::TEXT_DIM).add_modifier(Modifier::BOLD),
        ),
    ]);

    let mut lines: Vec<Line> = vec![header];

    let visible_rows = (inner.height as usize).saturating_sub(1); // minus header
    let skip = app.scroll_offset.min(sorted.len().saturating_sub(visible_rows));

    for (ip, count, last_seen) in sorted.iter().skip(skip).take(visible_rows) {
        let ip_str = format!("{:<18}", ip);

        // Country code from geoip cache
        let cc = app.geoip_cache.get(ip)
            .map(|g| g.country_code.clone())
            .unwrap_or_else(|| "--".into());
        let cc_str = format!("{:<6}", cc);

        let count_str = format!("{:>8}", format_count(*count));

        // Intensity bar using block characters
        let intensity = (*count as f64 / max_count as f64).clamp(0.0, 1.0);
        let bar_width: usize = 10;
        let filled = (intensity * bar_width as f64).round() as usize;
        let bar: String = "\u{2588}".repeat(filled)
            + &"\u{2591}".repeat(bar_width.saturating_sub(filled));

        // Status: BANNED or ACTIVE
        let is_banned = app.banned_ips.contains(ip);
        let (status_str, status_color) = if is_banned {
            ("BANNED  ", theme::SAFE)
        } else {
            ("ACTIVE  ", theme::DANGER)
        };

        // Time ago
        let time_str = last_seen
            .map(|ts| format_time_ago(ts))
            .unwrap_or_else(|| "--".into());

        lines.push(Line::from(vec![
            Span::styled(ip_str, Style::default().fg(theme::TEXT)),
            Span::styled(cc_str, Style::default().fg(theme::CYAN)),
            Span::styled(count_str, Style::default().fg(theme::GOLD)),
            Span::styled("  ", Style::default()),
            Span::styled(
                format!("{:<12}", bar),
                Style::default().fg(theme::RED),
            ),
            Span::styled(status_str.to_string(), Style::default().fg(status_color)),
            Span::styled(time_str, Style::default().fg(theme::TEXT_DIM)),
        ]));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
