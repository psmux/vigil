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
/// [1:Cmd] [2:Atk] [3:Door] [4:Net] [5:Geo] [6:Topo] [7:Sys]
/// ```
///
/// The active view is highlighted with `TAB_ACTIVE_FG` on `TAB_ACTIVE_BG` and bold.
/// Inactive tabs use `TEXT_DIM` on `TAB_BG`.
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let short_labels = ["Cmd", "Atk", "Door", "Net", "Geo", "Topo", "Sys"];

    let mut spans: Vec<Span> = Vec::new();

    for (i, view) in View::ALL.iter().enumerate() {
        let label = format!("[{}:{}]", i + 1, short_labels[i]);

        let is_active = app.view == *view;
        let style = if is_active {
            Style::default()
                .fg(theme::TAB_ACTIVE_FG)
                .bg(theme::TAB_ACTIVE_BG)
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
