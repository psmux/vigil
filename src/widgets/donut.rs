use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::theme;

/// A segment of the donut chart.
pub struct DonutSegment {
    pub label: String,
    pub value: u32,
    pub color: Color,
}

/// Donut ring template: 7 rows x 15 columns.
///
/// Each cell is either `Some(index)` — a ring position to be colored —
/// or `None` — empty or center space.
///
/// The ring has 36 cells total, mapped clockwise from top-center.
fn ring_template() -> Vec<Vec<Option<usize>>> {
    // A simple ASCII donut ring pattern (7 tall, 15 wide).
    // Ring positions 0-35 are mapped clockwise starting from top-center.
    //
    // Visual layout (. = space, # = ring cell):
    //
    //    . . . # # # # # . . .
    //    . # #           # # .
    //    # #               # #
    //    #                   #
    //    # #               # #
    //    . # #           # # .
    //    . . . # # # # # . . .
    //
    // We number them clockwise from top.

    // Row templates: (col, ring_index) pairs for each of the 7 rows.
    let ring_positions: [Vec<(usize, usize)>; 7] = [
        // Row 0: top of ring (positions 0-4)
        vec![(4, 0), (5, 1), (6, 2), (7, 3), (8, 4), (9, 5), (10, 6)],
        // Row 1: upper sides
        vec![(2, 35), (3, 34), (11, 7), (12, 8)],
        // Row 2: mid-upper sides
        vec![(1, 33), (2, 32), (12, 9), (13, 10)],
        // Row 3: middle sides
        vec![(1, 31), (13, 11)],
        // Row 4: mid-lower sides
        vec![(1, 30), (2, 29), (12, 12), (13, 13)],
        // Row 5: lower sides
        vec![(2, 28), (3, 27), (11, 14), (12, 15)],
        // Row 6: bottom (positions ~16-22)
        vec![(4, 26), (5, 25), (6, 24), (7, 23), (8, 22), (9, 21), (10, 20)],
    ];

    let mut grid = vec![vec![None; 15]; 7];
    for (row, positions) in ring_positions.iter().enumerate() {
        for &(col, idx) in positions {
            if col < 15 {
                grid[row][col] = Some(idx);
            }
        }
    }
    grid
}

/// Draw a simple ASCII donut chart.
///
/// Renders a ring of colored `\u{2588}` characters with segments sized
/// proportionally.  Center text is displayed inside the ring.  A legend
/// listing each segment appears below the donut.
pub fn draw_donut(
    f: &mut Frame,
    area: Rect,
    title: &str,
    segments: &[DonutSegment],
    center_text: &str,
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

    if inner.width < 15 || inner.height < 7 {
        return;
    }

    let total: u32 = segments.iter().map(|s| s.value).sum();
    let total = total.max(1);
    let ring_cells: usize = 36;

    // Assign each ring cell to a segment color
    let mut cell_colors: Vec<Color> = Vec::with_capacity(ring_cells);
    let mut used = 0usize;
    for (i, seg) in segments.iter().enumerate() {
        let count = if i == segments.len() - 1 {
            ring_cells - used
        } else {
            ((seg.value as f64 / total as f64) * ring_cells as f64).round() as usize
        };
        for _ in 0..count {
            cell_colors.push(seg.color);
        }
        used += count;
    }
    // Pad if rounding left us short
    while cell_colors.len() < ring_cells {
        if let Some(last) = segments.last() {
            cell_colors.push(last.color);
        } else {
            cell_colors.push(theme::TEXT_DIM);
        }
    }

    let template = ring_template();
    let mut lines: Vec<Line> = Vec::new();

    // Center the donut horizontally
    let donut_width = 15usize;
    let h_pad = (inner.width as usize).saturating_sub(donut_width) / 2;
    let pad_str = " ".repeat(h_pad);

    for (row_idx, row) in template.iter().enumerate() {
        let mut spans: Vec<Span> = Vec::new();
        spans.push(Span::raw(pad_str.clone()));

        for &cell in row {
            match cell {
                Some(idx) => {
                    let color = cell_colors.get(idx).copied().unwrap_or(theme::TEXT_DIM);
                    spans.push(Span::styled(
                        "\u{2588}",
                        Style::default().fg(color).bg(theme::BG),
                    ));
                }
                None => {
                    // If this is the center row (row 3) and roughly centered,
                    // render center_text
                    spans.push(Span::styled(" ", Style::default().bg(theme::BG)));
                }
            }
        }

        lines.push(Line::from(spans));

        // Overlay center text on middle row
        if row_idx == 3 && !center_text.is_empty() {
            // Replace the last line with one that includes center_text
            let last = lines.len() - 1;
            let center_avail = 9usize; // space inside the ring
            let text: String = if center_text.len() > center_avail {
                center_text[..center_avail].to_string()
            } else {
                let lpad = (center_avail - center_text.len()) / 2;
                format!(
                    "{}{}{}",
                    " ".repeat(lpad),
                    center_text,
                    " ".repeat(center_avail - center_text.len() - lpad)
                )
            };

            // Rebuild the center row with text
            let mut spans: Vec<Span> = Vec::new();
            spans.push(Span::raw(pad_str.clone()));
            // Ring left cell (col 1)
            let left_color = cell_colors.get(31).copied().unwrap_or(theme::TEXT_DIM);
            spans.push(Span::styled(
                "\u{2588}",
                Style::default().fg(left_color).bg(theme::BG),
            ));
            // Spaces before center
            spans.push(Span::raw("  "));
            // Center text
            spans.push(Span::styled(
                text,
                Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD),
            ));
            // Spaces after center
            spans.push(Span::raw("  "));
            // Ring right cell (col 13)
            let right_color = cell_colors.get(11).copied().unwrap_or(theme::TEXT_DIM);
            spans.push(Span::styled(
                "\u{2588}",
                Style::default().fg(right_color).bg(theme::BG),
            ));

            lines[last] = Line::from(spans);
        }
    }

    // Legend below donut (one blank line, then segments)
    if inner.height as usize > 8 {
        lines.push(Line::from(""));
        for seg in segments {
            let pct = (seg.value as f64 / total as f64 * 100.0).round() as u32;
            lines.push(Line::from(vec![
                Span::raw(pad_str.clone()),
                Span::styled(
                    "\u{2588}\u{2588}",
                    Style::default().fg(seg.color).bg(theme::BG),
                ),
                Span::styled(
                    format!(" {} {}%", seg.label, pct),
                    Style::default().fg(theme::TEXT),
                ),
            ]));
        }
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
