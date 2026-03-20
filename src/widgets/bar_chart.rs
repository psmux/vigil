use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::theme;

/// A single item in a horizontal bar chart.
pub struct BarItem {
    pub label: String,
    pub value: f64,
    pub color: Color,
    pub suffix: Option<String>,
}

/// Draw a horizontal bar chart that mirrors psnet's visual style.
///
/// Each row renders as:
/// ```text
/// label (12ch)  ████████████  value  suffix
/// ```
///
/// Bar width is proportional to the item's value relative to the maximum
/// value across all items.
pub fn draw_bar_chart(
    f: &mut Frame,
    area: Rect,
    title: &str,
    items: &[BarItem],
    max_items: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            format!(" {} ", title),
            Style::default()
                .fg(Color::Rgb(160, 180, 220))
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 20 || inner.height == 0 {
        return;
    }

    let visible = items.iter().take(max_items.min(inner.height as usize));
    let max_val = items
        .iter()
        .take(max_items)
        .map(|i| i.value)
        .fold(f64::NEG_INFINITY, f64::max)
        .max(1.0);

    let label_width: usize = 12;
    // Reserve: label(12) + space(1) + bar(variable) + space(1) + value(8) + suffix(~6)
    let value_width: usize = 8;
    let suffix_width: usize = 6;
    let bar_max_width = (inner.width as usize)
        .saturating_sub(label_width + 1 + 1 + value_width + suffix_width);

    let label_color = Color::Rgb(130, 200, 140);
    let value_color = Color::Rgb(100, 120, 150);

    let mut lines: Vec<Line> = Vec::new();

    for item in visible {
        // Truncate or pad label to label_width
        let truncated: String = if item.label.len() > label_width {
            item.label[..label_width].to_string()
        } else {
            format!("{:<width$}", item.label, width = label_width)
        };

        let ratio = if max_val > 0.0 {
            (item.value / max_val).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let bar_len = (ratio * bar_max_width as f64).round() as usize;
        let bar_str: String = "\u{2588}".repeat(bar_len);
        let bar_pad: String = " ".repeat(bar_max_width.saturating_sub(bar_len));

        let value_str = format!("{:>8.1}", item.value);
        let suffix_str = item
            .suffix
            .as_deref()
            .map(|s| format!(" {}", s))
            .unwrap_or_default();

        lines.push(Line::from(vec![
            Span::styled(truncated, Style::default().fg(label_color)),
            Span::raw(" "),
            Span::styled(bar_str, Style::default().fg(item.color)),
            Span::styled(bar_pad, Style::default().fg(theme::BG)),
            Span::raw(" "),
            Span::styled(value_str, Style::default().fg(value_color)),
            Span::styled(suffix_str, Style::default().fg(theme::TEXT_DIM)),
        ]));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
