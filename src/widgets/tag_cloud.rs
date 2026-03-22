//! Tag-cloud widget — renders weighted signal tags in a flowing layout.
//!
//! Tags are sized and styled by weight (prominence) and heat (recency).
//! Heavy tags are bold with block delimiters, medium tags are bracketed,
//! light tags are plain and dim.  Hot tags pulse on alternating animation
//! frames.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::data::signals::{SignalCategory, SignalTag};
use crate::theme;

/// Draw a tag cloud filling the given area.
///
/// `tags` should be pre-sorted by weight descending.
pub fn draw_tag_cloud(
    f: &mut Frame,
    area: Rect,
    tags: &[SignalTag],
    title: &str,
    animation_frame: u8,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            format!(" {} ", title),
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height < 2 {
        return;
    }

    if tags.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  Waiting for network signals…",
            Style::default().fg(theme::TEXT_DIM),
        )))
        .style(Style::default().bg(theme::BG));
        f.render_widget(msg, inner);
        return;
    }

    let lines = layout_tags(tags, inner.width, inner.height, animation_frame);
    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

// ─── Pulse-style tag cloud (psnet-inspired) ─────────────────────

/// Draw a pulse-style signal cloud — compact tags with activity markers.
///
/// Unlike the decorator-heavy `draw_tag_cloud`, this renders signals as
/// minimal labels with pulsing `●` markers for hot signals.  Event-category
/// signals (NEW, CLOSED, CONNECT) are filtered out — only protocols, hosts,
/// countries, and processes are shown.
pub fn draw_pulse_cloud(
    f: &mut Frame,
    area: Rect,
    tags: &[SignalTag],
    title: &str,
    animation_frame: u8,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            format!(" {} ", title),
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height < 1 {
        return;
    }

    // Filter out Event category (NEW, CLOSED, CONNECT, ATTACK, state labels)
    let filtered: Vec<&SignalTag> = tags
        .iter()
        .filter(|t| t.category != SignalCategory::Event)
        .collect();

    if filtered.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  Waiting for network signals\u{2026}",
            Style::default().fg(theme::TEXT_DIM),
        )))
        .style(Style::default().bg(theme::BG));
        f.render_widget(msg, inner);
        return;
    }

    let lines = layout_pulse_tags(&filtered, inner.width, inner.height, animation_frame);
    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

/// Flow pulse tags left-to-right, wrapping to next line.
fn layout_pulse_tags(
    tags: &[&SignalTag],
    width: u16,
    max_lines: u16,
    animation_frame: u8,
) -> Vec<Line<'static>> {
    let w = width as usize;
    let pulse_on = animation_frame % 4 < 2;

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut row_spans: Vec<Span<'static>> = Vec::new();
    let mut row_width: usize = 0;

    for tag in tags {
        let rendered = render_pulse_tag(tag, pulse_on);
        let tag_width = rendered.width;
        let gap = if row_width == 0 { 1 } else { 2 };

        if row_width > 0 && row_width + gap + tag_width > w {
            lines.push(Line::from(row_spans));
            row_spans = Vec::new();
            row_width = 0;
            if lines.len() >= max_lines as usize {
                break;
            }
        }

        if row_width == 0 {
            row_spans.push(Span::raw(" "));
            row_width = 1;
        } else {
            row_spans.push(Span::styled(
                " ",
                Style::default().fg(theme::TEXT_MUTED),
            ));
            row_width += 1;
        }

        row_spans.extend(rendered.spans);
        row_width += tag_width;
    }

    if !row_spans.is_empty() && lines.len() < max_lines as usize {
        lines.push(Line::from(row_spans));
    }

    lines
}

/// Render a single tag in pulse style: `● LABEL` for hot, `LABEL` for cool.
fn render_pulse_tag(tag: &SignalTag, pulse_on: bool) -> RenderedTag {
    let is_hot = tag.heat > 0.5;

    // Brightness oscillates for hot tags to create pulse effect
    let brightness = if is_hot {
        if pulse_on { 1.3 } else { 0.85 }
    } else {
        tag.weight.max(0.25)
    };
    let color = scale_color(tag.color, brightness);

    // Hot signals get activity marker
    let (marker, marker_style) = if is_hot && pulse_on {
        ("\u{25cf}", Style::default().fg(color)) // ● filled
    } else if is_hot {
        ("\u{25c7}", Style::default().fg(dim_color(color, 0.5))) // ◇ hollow dim
    } else {
        ("", Style::default())
    };

    let label_style = if tag.weight > 0.5 {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    } else if tag.weight > 0.15 {
        Style::default().fg(color)
    } else {
        Style::default().fg(dim_color(color, 0.45))
    };

    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut w = 0;

    if !marker.is_empty() {
        spans.push(Span::styled(marker.to_string(), marker_style));
        w += 1;
    }

    spans.push(Span::styled(tag.label.clone(), label_style));
    w += display_width(&tag.label);

    RenderedTag { spans, width: w }
}

// ─── Tag layout engine ──────────────────────────────────────────

/// Flow tags left-to-right, wrapping to next line when the row fills.
fn layout_tags(
    tags: &[SignalTag],
    width: u16,
    max_lines: u16,
    animation_frame: u8,
) -> Vec<Line<'static>> {
    let w = width as usize;
    let pulsing = animation_frame % 4 < 2;

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut row_spans: Vec<Span<'static>> = Vec::new();
    let mut row_width: usize = 0;

    for tag in tags {
        let rendered = render_tag(tag, pulsing);
        let tag_width = rendered.width;
        let gap = if row_width == 0 { 1 } else { 2 };

        // Wrap to next line if this tag doesn't fit
        if row_width > 0 && row_width + gap + tag_width > w {
            lines.push(Line::from(row_spans));
            row_spans = Vec::new();
            row_width = 0;

            if lines.len() >= max_lines as usize {
                break;
            }
        }

        // Leading space / gap
        if row_width == 0 {
            row_spans.push(Span::raw(" "));
            row_width = 1;
        } else {
            row_spans.push(Span::styled(
                "  ",
                Style::default().fg(theme::TEXT_MUTED),
            ));
            row_width += 2;
        }

        row_spans.extend(rendered.spans);
        row_width += tag_width;
    }

    // Flush last row
    if !row_spans.is_empty() && lines.len() < max_lines as usize {
        lines.push(Line::from(row_spans));
    }

    lines
}

// ─── Single tag rendering ───────────────────────────────────────

struct RenderedTag {
    spans: Vec<Span<'static>>,
    width: usize,
}

fn render_tag(tag: &SignalTag, pulsing: bool) -> RenderedTag {
    let is_hot = tag.heat > 0.5;
    let brightness = if is_hot && pulsing { 1.4 } else { 1.0 };
    let color = scale_color(tag.color, tag.weight.max(0.3) * brightness);

    // Category decorator
    let (prefix, suffix) = category_decorator(tag.category, tag.weight);

    // Display width: count chars (Unicode decorators are 1 column each)
    let w = display_width(&prefix) + display_width(&tag.label) + display_width(&suffix);

    if tag.weight > 0.55 {
        // ── Heavy: bold + bright ─────────────────────────────
        let style = Style::default().fg(color).add_modifier(Modifier::BOLD);
        let decor_style = Style::default().fg(dim_color(color, 0.6));
        RenderedTag {
            spans: vec![
                Span::styled(prefix, decor_style),
                Span::styled(tag.label.clone(), style),
                Span::styled(suffix, decor_style),
            ],
            width: w,
        }
    } else if tag.weight > 0.2 {
        // ── Medium: normal weight ────────────────────────────
        let style = Style::default().fg(color);
        let decor_style = Style::default().fg(dim_color(color, 0.5));
        RenderedTag {
            spans: vec![
                Span::styled(prefix, decor_style),
                Span::styled(tag.label.clone(), style),
                Span::styled(suffix, decor_style),
            ],
            width: w,
        }
    } else {
        // ── Light: dim ───────────────────────────────────────
        let dimmed = dim_color(color, 0.5);
        let style = Style::default().fg(dimmed);
        RenderedTag {
            spans: vec![
                Span::styled(prefix, style),
                Span::styled(tag.label.clone(), style),
                Span::styled(suffix, style),
            ],
            width: w,
        }
    }
}

/// Approximate display width (character count, not byte count).
fn display_width(s: &str) -> usize {
    s.chars().count()
}

/// Category-specific decorators that give visual identity to each tag type.
fn category_decorator(category: SignalCategory, weight: f64) -> (String, String) {
    if weight > 0.55 {
        match category {
            SignalCategory::Protocol => ("\u{ab}".into(), "\u{bb}".into()), // «»
            SignalCategory::Host => ("\u{2039}".into(), "\u{203a}".into()), // ‹›
            SignalCategory::Country => ("[".into(), "]".into()),
            SignalCategory::Process => ("{".into(), "}".into()),
            SignalCategory::Event => ("\u{25cf}".into(), String::new()), // ●
        }
    } else if weight > 0.2 {
        match category {
            SignalCategory::Protocol => ("\u{ab}".into(), "\u{bb}".into()),
            SignalCategory::Host => (String::new(), String::new()),
            SignalCategory::Country => ("[".into(), "]".into()),
            SignalCategory::Process => ("{".into(), "}".into()),
            SignalCategory::Event => ("\u{2022}".into(), String::new()), // •
        }
    } else {
        (String::new(), String::new())
    }
}

// ─── Color helpers ──────────────────────────────────────────────

fn scale_color(color: ratatui::style::Color, factor: f64) -> ratatui::style::Color {
    use ratatui::style::Color;
    match color {
        Color::Rgb(r, g, b) => {
            let f = factor.clamp(0.15, 1.6);
            Color::Rgb(
                ((r as f64 * f) as u16).min(255) as u8,
                ((g as f64 * f) as u16).min(255) as u8,
                ((b as f64 * f) as u16).min(255) as u8,
            )
        }
        other => other,
    }
}

fn dim_color(color: ratatui::style::Color, factor: f64) -> ratatui::style::Color {
    scale_color(color, factor)
}
