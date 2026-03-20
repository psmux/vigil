use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::theme;

/// Interpolate between two RGB colors by factor t in [0.0, 1.0].
fn lerp_color(a: (u8, u8, u8), b: (u8, u8, u8), t: f64) -> Color {
    let t = t.clamp(0.0, 1.0);
    Color::Rgb(
        (a.0 as f64 + (b.0 as f64 - a.0 as f64) * t).round() as u8,
        (a.1 as f64 + (b.1 as f64 - a.1 as f64) * t).round() as u8,
        (a.2 as f64 + (b.2 as f64 - a.2 as f64) * t).round() as u8,
    )
}

/// Heat block characters ordered by intensity.
const HEAT_CHARS: [char; 4] = [' ', '\u{2591}', '\u{2592}', '\u{2588}']; // ░▒█

/// Draw a 24-hour heat strip.
///
/// - Row 1: heat blocks, each hour mapped to color gradient from
///   `Rgb(30, 50, 85)` (cold) to `Rgb(255, 60, 60)` (hot).
/// - Row 2: hour labels (00, 06, 12, 18) evenly spaced.
/// - Row 3: "Peak: HH:00 (N attacks/hr)" left-aligned; "▲ now" marker
///   at the current hour position.
pub fn draw_heatmap(
    f: &mut Frame,
    area: Rect,
    title: &str,
    buckets: &[u32; 24],
    current_hour: u8,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            format!(" {} ", title),
            Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 24 || inner.height < 3 {
        return;
    }

    let width = inner.width as usize;
    let max_val = *buckets.iter().max().unwrap_or(&1);
    let max_val = max_val.max(1);

    let cold = (30u8, 50u8, 85u8);
    let hot = (255u8, 60u8, 60u8);

    // Chars per hour bucket
    let chars_per_hour = width / 24;
    let remainder = width - chars_per_hour * 24;

    // --- Row 1: Heat blocks ---
    let mut heat_spans: Vec<Span> = Vec::new();
    for (i, &count) in buckets.iter().enumerate() {
        let t = count as f64 / max_val as f64;
        let color = lerp_color(cold, hot, t);
        let char_idx = (t * 3.0).round() as usize;
        let ch = HEAT_CHARS[char_idx.min(3)];
        let extra = if i < remainder { 1 } else { 0 };
        let span_width = chars_per_hour + extra;
        heat_spans.push(Span::styled(
            ch.to_string().repeat(span_width),
            Style::default().fg(color).bg(theme::BG),
        ));
    }
    let heat_line = Line::from(heat_spans);

    // --- Row 2: Hour labels ---
    let hour_labels: [(usize, &str); 4] = [(0, "00"), (6, "06"), (12, "12"), (18, "18")];
    let mut label_buf = vec![' '; width];
    for &(hour, lbl) in &hour_labels {
        let pos = hour * chars_per_hour + hour.min(remainder);
        for (j, ch) in lbl.chars().enumerate() {
            if pos + j < width {
                label_buf[pos + j] = ch;
            }
        }
    }
    let label_str: String = label_buf.iter().collect();
    let label_line = Line::from(Span::styled(
        label_str,
        Style::default().fg(theme::TEXT_DIM),
    ));

    // --- Row 3: Peak info + now marker ---
    let peak_hour = buckets
        .iter()
        .enumerate()
        .max_by_key(|(_, &v)| v)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let peak_text = format!(
        "Peak: {:02}:00 ({} attacks/hr)",
        peak_hour, buckets[peak_hour]
    );

    // Build the "▲ now" marker positioned at the current hour
    let now_pos = (current_hour as usize) * chars_per_hour
        + (current_hour as usize).min(remainder);
    let mut info_buf = vec![' '; width];

    // Write peak text at left
    for (j, ch) in peak_text.chars().enumerate() {
        if j < width {
            info_buf[j] = ch;
        }
    }

    // Write "▲ now" at the current hour position (overwrite if overlapping)
    let now_marker = "\u{25B2} now";
    let marker_start = now_pos.min(width.saturating_sub(5));
    for (j, ch) in now_marker.chars().enumerate() {
        if marker_start + j < width {
            info_buf[marker_start + j] = ch;
        }
    }

    let info_str: String = info_buf.iter().collect();

    // Color the info line: peak text in TEXT_DIM, now marker in ACCENT
    let peak_len = peak_text.len().min(width);
    let mut info_spans: Vec<Span> = Vec::new();

    // We split the info string into segments for coloring
    // Simple approach: render the whole thing, then color the ▲ now portion
    if marker_start > peak_len {
        // No overlap
        info_spans.push(Span::styled(
            info_str[..peak_len].to_string(),
            Style::default().fg(theme::TEXT_DIM),
        ));
        info_spans.push(Span::styled(
            info_str[peak_len..marker_start].to_string(),
            Style::default().fg(theme::BG),
        ));
        info_spans.push(Span::styled(
            info_str[marker_start..].to_string(),
            Style::default().fg(theme::ACCENT),
        ));
    } else {
        // Overlap — just render with mixed colors
        info_spans.push(Span::styled(
            info_str[..marker_start].to_string(),
            Style::default().fg(theme::TEXT_DIM),
        ));
        info_spans.push(Span::styled(
            info_str[marker_start..].to_string(),
            Style::default().fg(theme::ACCENT),
        ));
    }

    let info_line = Line::from(info_spans);

    let paragraph = Paragraph::new(vec![heat_line, label_line, info_line])
        .style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
