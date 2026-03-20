use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::data::alerts::AlertSeverity;
use crate::format::format_bps;
use crate::theme;

/// Draw the always-visible top bar.
///
/// ```text
/// VIGIL ── hostname ── HH:MM:SS UTC ── ↓rx ↑tx ── N conns ── N threats ── Score: NN ── N alerts
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let now = chrono::Utc::now();
    let time_str = now.format("%H:%M:%S UTC").to_string();

    let conn_count = app.connections.len();
    let threat_count = app.attackers_sorted.len();

    let sep = Span::styled(
        " \u{2500}\u{2500} ", // ──
        Style::default().fg(theme::SEPARATOR),
    );

    let mut spans = vec![
        Span::styled(
            "VIGIL",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ),
        sep.clone(),
        Span::styled(
            app.hostname.clone(),
            Style::default().fg(theme::TEXT),
        ),
        sep.clone(),
        Span::styled(time_str, Style::default().fg(theme::TEXT)),
        sep.clone(),
        Span::styled(
            format!("\u{2193}{}", format_bps(app.current_rx_bps)),
            Style::default().fg(theme::DOWNLOAD),
        ),
        Span::styled(" ", Style::default()),
        Span::styled(
            format!("\u{2191}{}", format_bps(app.current_tx_bps)),
            Style::default().fg(theme::UPLOAD),
        ),
        sep.clone(),
        Span::styled(
            format!("{} conns", conn_count),
            Style::default().fg(theme::TEXT),
        ),
        sep.clone(),
        Span::styled(
            format!("{} threats", threat_count),
            Style::default().fg(if threat_count > 0 { theme::DANGER } else { theme::TEXT }),
        ),
        sep.clone(),
        Span::styled("Score: ", Style::default().fg(theme::TEXT)),
        Span::styled(
            format!("{}", app.security_score),
            Style::default()
                .fg(theme::score_color(app.security_score))
                .add_modifier(Modifier::BOLD),
        ),
    ];

    // ── Alert indicator ─────────────────────────────────────────
    let unread = app.alert_engine.unread_count();
    if unread > 0 {
        let alert_color = match app.alert_engine.highest_unread_severity() {
            Some(AlertSeverity::Crit) => theme::DANGER,  // red
            Some(AlertSeverity::Warn) => theme::GOLD,    // gold
            Some(AlertSeverity::Info) => theme::BLUE,    // blue
            None => theme::TEXT,
        };

        spans.push(sep);
        // Bell character: U+1F514 (🔔) — use a simple text marker for TUI compatibility
        spans.push(Span::styled(
            format!("\u{25C6} {} alert{}", unread, if unread == 1 { "" } else { "s" }),
            Style::default()
                .fg(alert_color)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, area);
}
