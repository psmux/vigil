use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::theme;

/// Draw a big-number KPI badge.
///
/// Renders a bordered box with three centered lines:
/// - Line 1: title (dim)
/// - Line 2: value (bold, colored)
/// - Line 3: subtitle (dim)
pub fn draw_kpi_badge(
    f: &mut Frame,
    area: Rect,
    title: &str,
    value: &str,
    subtitle: &str,
    color: Color,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let mut lines: Vec<Line> = Vec::new();

    // Vertical centering: 3 content lines
    let content_height = 3u16;
    let padding = inner.height.saturating_sub(content_height) / 2;
    for _ in 0..padding {
        lines.push(Line::from(""));
    }

    // Title line (dim)
    lines.push(Line::from(Span::styled(
        title.to_string(),
        Style::default().fg(theme::TEXT_DIM),
    )));

    // Value line (big, bold, colored)
    lines.push(Line::from(Span::styled(
        value.to_string(),
        Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD),
    )));

    // Subtitle line (dim)
    lines.push(Line::from(Span::styled(
        subtitle.to_string(),
        Style::default().fg(theme::TEXT_DIM),
    )));

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Center)
        .style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
