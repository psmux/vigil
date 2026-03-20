use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::theme;

/// Draw the bottom status bar with key hints.
///
/// ```text
/// q:Quit  1-8:View  Tab:Next  j/k:Scroll  z:Pause  ?:Help
/// ```
///
/// Key names are in `GOLD` bold; descriptions in `TEXT_DIM`.
pub fn draw(f: &mut Frame, _app: &App, area: Rect) {
    let hints: &[(&str, &str)] = &[
        ("q", "Quit"),
        ("1-8", "View"),
        ("Tab", "Next"),
        ("j/k", "Scroll"),
        ("z", "Pause"),
        ("a", "ReadAlerts"),
        ("?", "Help"),
    ];

    let mut spans: Vec<Span> = Vec::new();

    for (i, (key, desc)) in hints.iter().enumerate() {
        spans.push(Span::styled(
            key.to_string(),
            Style::default()
                .fg(theme::GOLD)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(":{}", desc),
            Style::default().fg(theme::TEXT_DIM),
        ));

        if i < hints.len() - 1 {
            spans.push(Span::styled(
                "  ",
                Style::default().fg(theme::TEXT_DIM),
            ));
        }
    }

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, area);
}
