use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::theme;

/// Block characters for sparkline rendering (U+2581 through U+2588).
const BARS: [char; 8] = ['\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];

/// Draw an animated sparkline using Unicode block characters.
///
/// Renders a bordered block with `label` as the title and `value_text`
/// right-aligned in the title bar.  The interior is filled with block
/// characters whose height maps each data point proportionally.
pub fn draw_sparkline(
    f: &mut Frame,
    area: Rect,
    data: &[f64],
    color: Color,
    label: &str,
    value_text: &str,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Line::from(vec![
            Span::styled(
                format!(" {} ", label),
                Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
            ),
            // Flexible spacer — we just put the value on the right side of the title
            Span::raw(""),
        ]))
        .title(
            Line::from(Span::styled(
                format!(" {} ", value_text),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ))
            .alignment(ratatui::layout::Alignment::Right),
        )
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let width = inner.width as usize;

    // Find the max value for normalization
    let max = data.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let max = if max <= 0.0 { 1.0 } else { max };

    // Build the sparkline string, padding with spaces if data is shorter than width
    let mut chars = String::with_capacity(width);
    let start = if data.len() > width {
        data.len() - width
    } else {
        0
    };
    let visible = &data[start..];

    // Leading spaces
    if visible.len() < width {
        for _ in 0..(width - visible.len()) {
            chars.push(' ');
        }
    }

    for &v in visible {
        let normalized = (v / max * 7.0).round() as usize;
        let idx = normalized.min(7);
        chars.push(BARS[idx]);
    }

    let spark_line = Line::from(Span::styled(
        chars,
        Style::default().fg(color).bg(theme::BG),
    ));

    let paragraph = Paragraph::new(spark_line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
