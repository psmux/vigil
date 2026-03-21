use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, View};
use crate::theme;

/// Draw the view-selector tab bar.
///
/// ```text
/// [1:Cmd] [2:Atk] [3:Alert] [4:Door] [5:Net] [6:Geo] [7:Topo] [8:Sys]
/// ```
///
/// The active view is highlighted with `TAB_ACTIVE_FG` on `TAB_ACTIVE_BG` and bold.
/// Inactive tabs use `TEXT_DIM` on `TAB_BG`.
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let short_labels = ["Cmd", "Atk", "Alert", "Door", "Net", "Geo", "Topo", "Sys", "Out", "Wire"];

    let mut spans: Vec<Span> = Vec::new();

    for (i, view) in View::ALL.iter().enumerate() {
        // Keys 1-9,0 map to views 1-10
        let key = if i == 9 { "0".to_string() } else { format!("{}", i + 1) };
        let label = format!("[{}:{}]", key, short_labels[i]);

        let is_active = app.view == *view;

        // For the Alerts tab, show unread indicator when not active
        let has_unread = *view == View::Alerts && app.alert_engine.unread_count() > 0;

        let style = if is_active {
            Style::default()
                .fg(theme::TAB_ACTIVE_FG)
                .bg(theme::TAB_ACTIVE_BG)
                .add_modifier(Modifier::BOLD)
        } else if has_unread {
            // Highlight alerts tab when there are unread alerts
            let severity_color = match app.alert_engine.highest_unread_severity() {
                Some(crate::data::alerts::AlertSeverity::Crit) => theme::DANGER,
                Some(crate::data::alerts::AlertSeverity::Warn) => theme::WARN,
                _ => theme::ACCENT,
            };
            Style::default()
                .fg(severity_color)
                .bg(theme::TAB_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(theme::TEXT_DIM)
                .bg(theme::TAB_BG)
        };

        spans.push(Span::styled(label, style));

        // Space separator between tabs
        if i < View::ALL.len() - 1 {
            spans.push(Span::styled(" ", Style::default().bg(theme::BG)));
        }
    }

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, area);
}
