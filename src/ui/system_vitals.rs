use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::format::format_bytes;
use crate::theme;
use crate::widgets::gauge::draw_bar_gauge;

/// Draw the System Vitals view (View 6).
///
/// Layout:
/// ```text
/// Vertical [
///   top_row (40%): Horizontal [ cpu_section (50%) | memory_section (50%) ]
///   mid_row (30%): Horizontal [ disk_section (50%) | interfaces (50%) ]
///   services (remaining): service status grid
/// ]
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Min(4),
        ])
        .split(area);

    let top_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(rows[0]);

    draw_cpu_section(f, app, top_row[0]);
    draw_memory_section(f, app, top_row[1]);

    let mid_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(rows[1]);

    draw_disk_section(f, app, mid_row[0]);
    draw_interfaces(f, app, mid_row[1]);

    draw_services(f, app, rows[2]);
}

// ─── CPU Section ─────────────────────────────────────────────────

fn draw_cpu_section(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " CPU ",
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

    // Per-core bar gauges, each taking 3 rows (border top/bottom + bar)
    let core_count = app.cpu.cores.len();
    let gauge_height = 3u16;
    // Reserve 1 row for load average text at the bottom
    let available_for_cores = inner.height.saturating_sub(1);
    let max_cores = (available_for_cores / gauge_height) as usize;
    let visible_cores = core_count.min(max_cores).max(1);

    let mut constraints: Vec<Constraint> = (0..visible_cores)
        .map(|_| Constraint::Length(gauge_height))
        .collect();
    constraints.push(Constraint::Min(1)); // load average row

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for (i, core) in app.cpu.cores.iter().take(visible_cores).enumerate() {
        let usage = core.usage_percent as f64;
        let color = cpu_usage_color(usage);
        draw_bar_gauge(
            f,
            chunks[i],
            &format!("Core {}", core.id),
            usage,
            100.0,
            color,
        );
    }

    // Load averages in the last chunk
    let load_area = chunks[visible_cores];
    let (l1, l5, l15) = app.cpu.load_avg;
    let load_text = format!("Load avg: {:.2} / {:.2} / {:.2}", l1, l5, l15);
    let load_line = Line::from(Span::styled(
        load_text,
        Style::default().fg(theme::TEXT_DIM),
    ));
    let paragraph = Paragraph::new(load_line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, load_area);
}

/// Map CPU usage percentage to a color: green < 60%, gold 60-85%, red > 85%.
fn cpu_usage_color(pct: f64) -> Color {
    if pct > 85.0 {
        theme::DANGER
    } else if pct > 60.0 {
        theme::GOLD
    } else {
        theme::SAFE
    }
}

// ─── Memory Section ──────────────────────────────────────────────

fn draw_memory_section(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Memory ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height < 4 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // RAM gauge
            Constraint::Length(1), // RAM text
            Constraint::Length(3), // Swap gauge
            Constraint::Min(1),   // Swap text
        ])
        .split(inner);

    // RAM bar gauge
    let ram_used = app.memory.used as f64;
    let ram_total = app.memory.total.max(1) as f64;
    let ram_pct = ram_used / ram_total;
    let ram_color = if ram_pct > 0.9 {
        theme::DANGER
    } else if ram_pct > 0.7 {
        theme::GOLD
    } else {
        theme::SAFE
    };
    draw_bar_gauge(f, chunks[0], "RAM", ram_used, ram_total, ram_color);

    // RAM used/total text
    let ram_text = format!(
        "{} / {}",
        format_bytes(app.memory.used),
        format_bytes(app.memory.total),
    );
    let ram_line = Line::from(Span::styled(
        ram_text,
        Style::default().fg(theme::TEXT_DIM),
    ));
    f.render_widget(
        Paragraph::new(ram_line).style(Style::default().bg(theme::BG)),
        chunks[1],
    );

    // Swap bar gauge
    let swap_used = app.memory.swap_used as f64;
    let swap_total = app.memory.swap_total.max(1) as f64;
    let swap_pct = swap_used / swap_total;
    let swap_color = if swap_pct > 0.5 {
        theme::DANGER
    } else if swap_pct > 0.2 {
        theme::GOLD
    } else {
        theme::SAFE
    };
    draw_bar_gauge(f, chunks[2], "Swap", swap_used, swap_total, swap_color);

    // Swap used/total text
    let swap_text = format!(
        "{} / {}",
        format_bytes(app.memory.swap_used),
        format_bytes(app.memory.swap_total),
    );
    let swap_line = Line::from(Span::styled(
        swap_text,
        Style::default().fg(theme::TEXT_DIM),
    ));
    f.render_widget(
        Paragraph::new(swap_line).style(Style::default().bg(theme::BG)),
        chunks[3],
    );
}

// ─── Disk Section ────────────────────────────────────────────────

fn draw_disk_section(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Disks ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height < 3 {
        return;
    }

    if app.disks.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "No disk data",
            Style::default().fg(theme::TEXT_DIM),
        )))
        .style(Style::default().bg(theme::BG));
        f.render_widget(msg, inner);
        return;
    }

    let gauge_height = 3u16;
    let max_disks = (inner.height / gauge_height) as usize;
    let visible_disks = app.disks.len().min(max_disks).max(1);

    let constraints: Vec<Constraint> = (0..visible_disks)
        .map(|_| Constraint::Length(gauge_height))
        .chain(std::iter::once(Constraint::Min(0)))
        .collect();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for (i, disk) in app.disks.iter().take(visible_disks).enumerate() {
        let used = disk.used as f64;
        let total = disk.total.max(1) as f64;
        let pct = used / total;
        let color = if pct > 0.9 {
            theme::DANGER
        } else if pct > 0.75 {
            theme::GOLD
        } else {
            theme::SAFE
        };
        let label = format!(
            "{} ({}/{})",
            disk.mount,
            format_bytes(disk.used),
            format_bytes(disk.total),
        );
        draw_bar_gauge(f, chunks[i], &label, used, total, color);
    }
}

// ─── Network Interfaces ──────────────────────────────────────────

fn draw_interfaces(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Interfaces ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height == 0 {
        return;
    }

    let mut lines: Vec<Line> = Vec::new();

    for iface in &app.interfaces {
        let (arrow, arrow_color) = if iface.up {
            ("\u{25B2} UP", theme::SAFE) // ▲ UP
        } else {
            ("\u{25BC} DOWN", theme::DANGER) // ▼ DOWN
        };

        let speed_str = iface
            .speed_mbps
            .map(|s| format!(" {}Mbps", s))
            .unwrap_or_default();

        let line = Line::from(vec![
            Span::styled(
                format!("{:<7}", arrow),
                Style::default().fg(arrow_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:<12}", iface.name),
                Style::default().fg(theme::TEXT),
            ),
            Span::styled(
                format!("{:<18}", iface.ip),
                Style::default().fg(theme::ACCENT),
            ),
            Span::styled(speed_str, Style::default().fg(theme::TEXT_DIM)),
        ]);

        lines.push(line);

        if lines.len() >= inner.height as usize {
            break;
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No interface data",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

// ─── Services Grid ───────────────────────────────────────────────

fn draw_services(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Services ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height == 0 {
        return;
    }

    if app.services.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "No service data",
            Style::default().fg(theme::TEXT_DIM),
        )))
        .style(Style::default().bg(theme::BG));
        f.render_widget(msg, inner);
        return;
    }

    // Arrange services in a 3-column grid
    let cols = 3usize;
    let col_width = (inner.width as usize) / cols;

    let mut lines: Vec<Line> = Vec::new();

    for chunk in app.services.chunks(cols) {
        let mut spans: Vec<Span> = Vec::new();

        for svc in chunk {
            let (dot, color) = if svc.active {
                ("\u{25CF}", theme::SAFE) // ● green
            } else {
                ("\u{25CB}", theme::DANGER) // ○ red
            };

            let entry = format!("{} {}", dot, svc.name);
            // Pad to column width
            let padded = format!("{:<width$}", entry, width = col_width);
            spans.push(Span::styled(padded, Style::default().fg(color)));
        }

        lines.push(Line::from(spans));

        if lines.len() >= inner.height as usize {
            break;
        }
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
