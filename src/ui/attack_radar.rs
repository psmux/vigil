use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::AttackType;
use crate::data::alerts::AlertSeverity;
use crate::format::{format_count, format_time_ago};
use crate::theme;
use crate::widgets::bar_chart::{self, BarItem};
use crate::widgets::braille_map::MapDot;
use crate::widgets::terminal_map;
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
            Constraint::Length(7),       // heatmap
            Constraint::Percentage(40),  // middle row
            Constraint::Min(5),          // attacker table
            Constraint::Length(8),       // recent alerts
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

    // ── Recent alerts ────────────────────────────────────────────
    draw_recent_alerts(f, app, chunks[3]);
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
    // Build dots from the aggregated attacker list (deduplicated, one dot per IP)
    let mut dots: Vec<MapDot> = Vec::new();

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

    terminal_map::draw_terminal_map(f, area, &dots, app.animation_frame, "Attack Origins");
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

    // Use the pre-sorted, pre-aggregated attacker list from app state.
    // No re-aggregation or re-sorting per frame — stable ordering guaranteed.
    let sorted = &app.attackers_sorted;

    let max_count = sorted.first().map(|s| s.total_attempts).unwrap_or(1).max(1);

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

    for agg in sorted.iter().skip(skip).take(visible_rows) {
        let ip_str = format!("{:<18}", agg.source_ip);

        // Country code from geoip cache
        let cc = app.geoip_cache.get(&agg.source_ip)
            .map(|g| g.country_code.clone())
            .unwrap_or_else(|| "--".into());
        let cc_str = format!("{:<6}", cc);

        let count_str = format!("{:>8}", format_count(agg.total_attempts));

        // Intensity bar using block characters
        let intensity = (agg.total_attempts as f64 / max_count as f64).clamp(0.0, 1.0);
        let bar_width: usize = 10;
        let filled = (intensity * bar_width as f64).round() as usize;
        let bar: String = "\u{2588}".repeat(filled)
            + &"\u{2591}".repeat(bar_width.saturating_sub(filled));

        // Status: BANNED or ACTIVE (read from pre-computed field)
        let (status_str, status_color) = if agg.banned {
            ("BANNED  ", theme::SAFE)
        } else {
            ("ACTIVE  ", theme::DANGER)
        };

        // Time ago
        let time_str = format_time_ago(agg.last_seen);

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

fn draw_recent_alerts(f: &mut Frame, app: &App, area: Rect) {
    let unread = app.alert_engine.unread_count();
    let title_text = if unread > 0 {
        format!(" Recent Alerts ({} unread) ", unread)
    } else {
        " Recent Alerts ".to_string()
    };

    let title_color = if unread > 0 { theme::GOLD } else { theme::TITLE };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            title_text,
            Style::default().fg(title_color).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 30 || inner.height == 0 {
        return;
    }

    let recent = app.alert_engine.recent(inner.height as usize);

    if recent.is_empty() {
        let line = Line::from(Span::styled(
            " No alerts yet",
            Style::default().fg(theme::TEXT_DIM),
        ));
        let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
        f.render_widget(paragraph, inner);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();

    for alert in &recent {
        // Severity badge
        let (sev_label, sev_color) = match alert.severity {
            AlertSeverity::Crit => ("CRIT", theme::DANGER),
            AlertSeverity::Warn => ("WARN", theme::GOLD),
            AlertSeverity::Info => ("INFO", theme::BLUE),
        };

        // Timestamp HH:MM:SS
        let time_str = alert.timestamp.format("%H:%M:%S").to_string();

        // Unread indicator
        let read_indicator = if alert.read { " " } else { "\u{25CF}" };

        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", read_indicator),
                Style::default().fg(if alert.read { theme::TEXT_MUTED } else { sev_color }),
            ),
            Span::styled(
                format!("{:<4}", sev_label),
                Style::default()
                    .fg(theme::BG)
                    .bg(sev_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(
                time_str,
                Style::default().fg(theme::TEXT_DIM),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(
                alert.message.clone(),
                Style::default().fg(if alert.read { theme::TEXT_DIM } else { theme::TEXT }),
            ),
        ]));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
