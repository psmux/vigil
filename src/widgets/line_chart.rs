use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::theme;

/// A single data series for the line chart.
pub struct ChartSeries {
    pub data: Vec<f64>,
    pub color: Color,
    pub label: String,
}

/// Local braille grid for line-chart rendering at 2x4 sub-cell resolution.
struct BrailleGrid {
    cols: usize,
    rows: usize,
    /// Dot buffer: indexed [dy][dx].
    dots: Vec<Vec<bool>>,
    /// Per-dot color (only the last write wins per cell).
    dot_colors: Vec<Vec<Color>>,
}

impl BrailleGrid {
    fn new(cols: usize, rows: usize) -> Self {
        let dots_w = cols * 2;
        let dots_h = rows * 4;
        Self {
            cols,
            rows,
            dots: vec![vec![false; dots_w]; dots_h],
            dot_colors: vec![vec![theme::TEXT_DIM; dots_w]; dots_h],
        }
    }

    fn set(&mut self, dx: usize, dy: usize, color: Color) {
        let dots_w = self.cols * 2;
        let dots_h = self.rows * 4;
        if dx < dots_w && dy < dots_h {
            self.dots[dy][dx] = true;
            self.dot_colors[dy][dx] = color;
        }
    }

    /// Render to Lines, picking the cell color from the last set dot.
    fn render(&self) -> Vec<Line<'static>> {
        let bit_map: [[u8; 4]; 2] = [
            [0, 1, 2, 6],
            [3, 4, 5, 7],
        ];

        let mut lines = Vec::with_capacity(self.rows);
        for row in 0..self.rows {
            let mut spans: Vec<Span<'static>> = Vec::with_capacity(self.cols);
            for col in 0..self.cols {
                let mut code_point: u32 = 0x2800;
                let mut cell_color = theme::TEXT_DIM;
                let mut has_dot = false;

                for lc in 0..2usize {
                    for lr in 0..4usize {
                        let dx = col * 2 + lc;
                        let dy = row * 4 + lr;
                        if dx < self.cols * 2 && dy < self.rows * 4 && self.dots[dy][dx] {
                            code_point |= 1 << bit_map[lc][lr];
                            cell_color = self.dot_colors[dy][dx];
                            has_dot = true;
                        }
                    }
                }

                let ch = char::from_u32(code_point).unwrap_or(' ');
                let fg = if has_dot { cell_color } else { theme::BG };
                spans.push(Span::styled(
                    ch.to_string(),
                    Style::default().fg(fg).bg(theme::BG),
                ));
            }
            lines.push(Line::from(spans));
        }
        lines
    }
}

/// Draw a line chart using braille characters for smooth rendering.
///
/// - Y-axis labels on the left (3 chars wide).
/// - Time labels along the bottom.
/// - Each series is plotted as connected braille dots.
pub fn draw_line_chart(
    f: &mut Frame,
    area: Rect,
    title: &str,
    series: &[ChartSeries],
    time_labels: &[String],
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

    // We need at least: 3 (y-axis) + 1 (separator) + 4 (chart) columns,
    // and 2 (chart) + 1 (time labels) rows.
    let y_axis_width: usize = 3;
    let separator_width: usize = 1;
    if inner.width as usize <= y_axis_width + separator_width + 2 || inner.height < 3 {
        return;
    }

    let chart_cols = inner.width as usize - y_axis_width - separator_width;
    let chart_rows = (inner.height as usize).saturating_sub(1); // reserve 1 row for time labels

    if chart_cols == 0 || chart_rows == 0 {
        return;
    }

    // Find global min/max across all series
    let mut global_min = f64::INFINITY;
    let mut global_max = f64::NEG_INFINITY;
    for s in series {
        for &v in &s.data {
            if v < global_min {
                global_min = v;
            }
            if v > global_max {
                global_max = v;
            }
        }
    }
    if global_min == f64::INFINITY {
        global_min = 0.0;
    }
    if global_max == f64::NEG_INFINITY {
        global_max = 1.0;
    }
    if (global_max - global_min).abs() < f64::EPSILON {
        global_max = global_min + 1.0;
    }

    let dots_w = chart_cols * 2;
    let dots_h = chart_rows * 4;

    let mut grid = BrailleGrid::new(chart_cols, chart_rows);

    // Plot each series
    for s in series {
        if s.data.is_empty() {
            continue;
        }
        let n = s.data.len();
        // Map data indices to dot x-coordinates
        for i in 0..n {
            let x = if n == 1 {
                dots_w / 2
            } else {
                (i as f64 / (n - 1) as f64 * (dots_w - 1) as f64).round() as usize
            };
            let normalized = (s.data[i] - global_min) / (global_max - global_min);
            let y = ((1.0 - normalized) * (dots_h - 1) as f64).round() as usize;

            grid.set(x.min(dots_w - 1), y.min(dots_h - 1), s.color);

            // Connect to next point with line interpolation
            if i + 1 < n {
                let x2 = if n == 1 {
                    dots_w / 2
                } else {
                    ((i + 1) as f64 / (n - 1) as f64 * (dots_w - 1) as f64).round() as usize
                };
                let norm2 = (s.data[i + 1] - global_min) / (global_max - global_min);
                let y2 = ((1.0 - norm2) * (dots_h - 1) as f64).round() as usize;

                // Bresenham-style line
                let dx = (x2 as isize - x as isize).abs();
                let dy = (y2 as isize - y as isize).abs();
                let sx: isize = if x2 > x { 1 } else { -1 };
                let sy: isize = if y2 > y { 1 } else { -1 };
                let mut err = dx - dy;
                let mut cx = x as isize;
                let mut cy = y as isize;
                let tx = x2 as isize;
                let ty = y2 as isize;

                loop {
                    if cx >= 0
                        && cy >= 0
                        && (cx as usize) < dots_w
                        && (cy as usize) < dots_h
                    {
                        grid.set(cx as usize, cy as usize, s.color);
                    }
                    if cx == tx && cy == ty {
                        break;
                    }
                    let e2 = 2 * err;
                    if e2 > -dy {
                        err -= dy;
                        cx += sx;
                    }
                    if e2 < dx {
                        err += dx;
                        cy += sy;
                    }
                }
            }
        }
    }

    let chart_lines = grid.render();

    // Build output lines: y-axis | chart | time labels
    let mut output_lines: Vec<Line> = Vec::new();

    // Y-axis labels: top = max, mid, bottom = min
    for (row_idx, chart_line) in chart_lines.iter().enumerate() {
        let y_label = if row_idx == 0 {
            format!("{:>3}", format_value(global_max))
        } else if row_idx == chart_rows / 2 {
            format!("{:>3}", format_value((global_max + global_min) / 2.0))
        } else if row_idx == chart_rows - 1 {
            format!("{:>3}", format_value(global_min))
        } else {
            "   ".to_string()
        };

        let mut spans: Vec<Span> = Vec::new();
        spans.push(Span::styled(
            y_label,
            Style::default().fg(theme::TEXT_DIM),
        ));
        spans.push(Span::styled(
            "\u{2502}",
            Style::default().fg(theme::BORDER),
        )); // │
        spans.extend(chart_line.spans.clone());
        output_lines.push(Line::from(spans));
    }

    // Time label row
    let mut time_row_spans: Vec<Span> = Vec::new();
    time_row_spans.push(Span::raw("   ")); // y-axis spacer
    time_row_spans.push(Span::styled(
        "\u{2514}",
        Style::default().fg(theme::BORDER),
    )); // └

    if !time_labels.is_empty() {
        let avail = chart_cols;
        let mut buf = vec!['\u{2500}'; avail]; // ─ baseline

        let spacing = if time_labels.len() > 1 {
            avail / time_labels.len()
        } else {
            avail
        };

        for (i, lbl) in time_labels.iter().enumerate() {
            let pos = i * spacing;
            for (j, ch) in lbl.chars().enumerate() {
                if pos + j < avail {
                    buf[pos + j] = ch;
                }
            }
        }

        let time_str: String = buf.iter().collect();
        time_row_spans.push(Span::styled(
            time_str,
            Style::default().fg(theme::TEXT_DIM),
        ));
    }

    output_lines.push(Line::from(time_row_spans));

    // Legend line if multiple series and there's room
    if series.len() > 1 && inner.height as usize > chart_rows + 2 {
        let mut legend_spans: Vec<Span> = Vec::new();
        legend_spans.push(Span::raw("    "));
        for (i, s) in series.iter().enumerate() {
            if i > 0 {
                legend_spans.push(Span::raw("  "));
            }
            legend_spans.push(Span::styled(
                "\u{2501}\u{2501}",
                Style::default().fg(s.color),
            )); // ━━
            legend_spans.push(Span::styled(
                format!(" {}", s.label),
                Style::default().fg(theme::TEXT),
            ));
        }
        output_lines.push(Line::from(legend_spans));
    }

    let paragraph = Paragraph::new(output_lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

/// Format a numeric value for the Y-axis: compact representation.
fn format_value(v: f64) -> String {
    if v.abs() >= 1_000_000.0 {
        format!("{:.0}M", v / 1_000_000.0)
    } else if v.abs() >= 1_000.0 {
        format!("{:.0}k", v / 1_000.0)
    } else if v.abs() >= 100.0 {
        format!("{:.0}", v)
    } else if v.abs() >= 10.0 {
        format!("{:.1}", v)
    } else {
        format!("{:.1}", v)
    }
}
