use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::theme;

/// Draw a horizontal bar gauge like `[████████░░░░] 54%`.
///
/// The bar fills proportionally to `value / max`.
pub fn draw_bar_gauge(
    f: &mut Frame,
    area: Rect,
    label: &str,
    value: f64,
    max: f64,
    color: Color,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            format!(" {} ", label),
            Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height == 0 {
        return;
    }

    let pct = if max > 0.0 { (value / max).clamp(0.0, 1.0) } else { 0.0 };
    let pct_display = (pct * 100.0).round() as u8;

    // Reserve space for ` XXX%` suffix (5 chars)
    let bar_width = (inner.width as usize).saturating_sub(6);
    let filled = (pct * bar_width as f64).round() as usize;
    let empty = bar_width.saturating_sub(filled);

    let bar_filled: String = "\u{2588}".repeat(filled); // █
    let bar_empty: String = "\u{2591}".repeat(empty); // ░

    let line = Line::from(vec![
        Span::styled(&bar_filled, Style::default().fg(color).bg(theme::BG)),
        Span::styled(&bar_empty, Style::default().fg(theme::BORDER).bg(theme::BG)),
        Span::styled(
            format!(" {}%", pct_display),
            Style::default().fg(theme::TEXT).bg(theme::BG),
        ),
    ]);

    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

/// Draw a large centered score display with delta indicator.
///
/// - Score 80+ is green, 50-79 is gold, <50 is red.
/// - Delta line shows an up/down arrow with the change from 1h ago.
pub fn draw_score_gauge(f: &mut Frame, area: Rect, score: u8, delta: i8) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Security Score ",
            Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let score_color = match score {
        80..=255 => Color::Rgb(80, 200, 120),  // green
        50..=79 => Color::Rgb(255, 200, 80),   // gold
        _ => Color::Rgb(255, 60, 60),           // red
    };

    let (delta_arrow, delta_color) = if delta >= 0 {
        ("\u{25B2}", Color::Rgb(80, 200, 120)) // ▲ green
    } else {
        ("\u{25BC}", Color::Rgb(255, 60, 60))  // ▼ red
    };

    let delta_sign = if delta > 0 { "+" } else { "" };
    let delta_text = format!("{} {}{} from 1h ago", delta_arrow, delta_sign, delta);

    let mut lines: Vec<Line> = Vec::new();

    // Center the score vertically — add blank lines above if there's room
    let content_height = 2u16; // score + delta
    let padding = inner.height.saturating_sub(content_height) / 2;
    for _ in 0..padding {
        lines.push(Line::from(""));
    }

    // Big score number
    lines.push(Line::from(Span::styled(
        format!("{}", score),
        Style::default()
            .fg(score_color)
            .add_modifier(Modifier::BOLD),
    )));

    // Delta line
    lines.push(Line::from(Span::styled(
        delta_text,
        Style::default().fg(delta_color),
    )));

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Center)
        .style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
