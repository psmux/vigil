//! Wire view (View 0) — Wireshark-like real-time connection lifecycle monitor.
//!
//! Shows a scrolling log of network events: new connections, state transitions,
//! closures, and data activity — everything happening "under the wire".

use ratatui::layout::{Constraint, Direction as LayoutDir, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::wire::{WireEvent, WireEventKind};
use crate::data::{Direction, Protocol, TcpState};
use crate::data::protocols::AppProtocol;
use crate::format::format_bps;
use crate::theme;

// ─── Color constants ────────────────────────────────────────────────
const NEW_CONN: Color = Color::Rgb(80, 220, 120);
const CLOSED_CONN: Color = Color::Rgb(180, 80, 80);
const STATE_CHANGE: Color = Color::Rgb(255, 200, 80);
const SEQ_COLOR: Color = Color::Rgb(60, 70, 90);
const TIME_COLOR: Color = Color::Rgb(100, 120, 150);
const THREAT_COLOR: Color = Color::Rgb(255, 50, 50);

/// Draw the Wire view (View 0).
///
/// Layout:
/// ```text
/// Vertical [
///   stats_bar (3 lines): protocol summary + live counters
///   event_log (rest): scrolling Wireshark-like event table
/// ]
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
        ])
        .split(area);

    draw_stats_bar(f, app, rows[0]);
    draw_event_log(f, app, rows[1]);
}

// ─── Stats Bar ──────────────────────────────────────────────────────

fn draw_stats_bar(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Wire Stats ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 20 || inner.height == 0 {
        return;
    }

    let stats = &app.wire_tracker.stats;

    let line = Line::from(vec![
        Span::styled(" TCP ", Style::default().fg(theme::CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("{}", stats.tcp_count),
            Style::default().fg(theme::TEXT),
        ),
        Span::styled(
            format!(" (\u{2192}{} \u{2190}{})", stats.tcp_outbound, stats.tcp_inbound),
            Style::default().fg(theme::TEXT_DIM),
        ),
        Span::styled("  UDP ", Style::default().fg(theme::PURPLE).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("{}", stats.udp_count),
            Style::default().fg(theme::TEXT),
        ),
        Span::styled(
            format!(" (\u{2192}{} \u{2190}{})", stats.udp_outbound, stats.udp_inbound),
            Style::default().fg(theme::TEXT_DIM),
        ),
        Span::styled("  \u{2502} ", Style::default().fg(theme::BORDER)),
        Span::styled(
            format!("Events: {} ", stats.total_events),
            Style::default().fg(theme::TEXT),
        ),
        Span::styled("  \u{2502} ", Style::default().fg(theme::BORDER)),
        Span::styled(
            format!("+{}", stats.new_this_tick),
            Style::default().fg(NEW_CONN).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!("-{}", stats.closed_this_tick),
            Style::default().fg(CLOSED_CONN),
        ),
        Span::raw(" "),
        Span::styled(
            format!("\u{2194}{}", stats.state_changes_this_tick),
            Style::default().fg(STATE_CHANGE),
        ),
        Span::styled("  \u{2502} ", Style::default().fg(theme::BORDER)),
        Span::styled(
            "\u{25cf}NEW ".to_string(),
            Style::default().fg(NEW_CONN),
        ),
        Span::styled(
            "\u{25cf}CLOSE ".to_string(),
            Style::default().fg(CLOSED_CONN),
        ),
        Span::styled(
            "\u{25cf}STATE".to_string(),
            Style::default().fg(STATE_CHANGE),
        ),
    ]);

    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

// ─── Event Log ──────────────────────────────────────────────────────

fn draw_event_log(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Live Wire ",
            Style::default()
                .fg(Color::Rgb(60, 220, 180))
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 60 || inner.height < 3 {
        return;
    }

    // Header
    let header = Line::from(Span::styled(
        format!(
            " {:<6} {:<8} {:>3} {:<5} {:<22} {:<22} {:<8} {:<14} {:>2}  {}",
            "#", "TIME", "DIR", "PROTO", "SOURCE", "DESTINATION", "SERVICE", "PROCESS", "CC", "INFO"
        ),
        Style::default()
            .fg(theme::TEXT_DIM)
            .add_modifier(Modifier::BOLD),
    ));

    let events = app.wire_tracker.events();
    let visible_rows = (inner.height as usize).saturating_sub(1);
    let total = events.len();
    let max_scroll = total.saturating_sub(visible_rows);
    let offset = app.scroll_offset.min(max_scroll);

    let mut lines: Vec<Line> = Vec::with_capacity(visible_rows + 1);
    lines.push(header);

    for event in events.iter().skip(offset).take(visible_rows) {
        lines.push(build_event_line(event, app, inner.width as usize));
    }

    if events.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Listening for network activity...",
            Style::default().fg(theme::TEXT_DIM),
        )));
        lines.push(Line::from(Span::styled(
            "  Events will appear here as connections open, change state, and close.",
            Style::default().fg(theme::TEXT_MUTED),
        )));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

/// Build a single event line in Wireshark style.
fn build_event_line<'a>(event: &WireEvent, app: &App, _width: usize) -> Line<'a> {
    // Seq number
    let seq_str = format!(" {:<6}", event.seq);

    // Timestamp (HH:MM:SS)
    let time_str = event.timestamp.format("%H:%M:%S").to_string();
    let time_display = format!("{:<8}", time_str);

    // Direction arrow
    let (dir_str, dir_color) = match event.direction {
        Direction::Outbound => (" \u{2192} ", theme::GREEN),
        Direction::Inbound => (" \u{2190} ", theme::CYAN),
        Direction::Local => (" \u{2194} ", theme::TEXT_DIM),
        Direction::Unknown => (" ? ", theme::TEXT_DIM),
    };

    // Protocol
    let proto_str = match event.protocol {
        Protocol::Tcp => "TCP  ",
        Protocol::Udp => "UDP  ",
    };
    let proto_color = match event.protocol {
        Protocol::Tcp => theme::CYAN,
        Protocol::Udp => theme::PURPLE,
    };

    // Source
    let src = format!("{}", event.local_addr);
    let src_display: String = if src.len() > 22 { src[..22].to_string() } else { format!("{:<22}", src) };

    // Destination (hostname if available, else IP)
    let dst_raw = event
        .hostname
        .as_deref()
        .map(|h| {
            let port = event.remote_addr.port();
            if h.len() > 16 {
                format!("{}..:{}", &h[..16], port)
            } else {
                format!("{}:{}", h, port)
            }
        })
        .unwrap_or_else(|| format!("{}", event.remote_addr));
    let dst_display: String = if dst_raw.len() > 22 {
        dst_raw[..22].to_string()
    } else {
        format!("{:<22}", dst_raw)
    };

    // Service
    let service_str = format!("{:<8}", event.service.label());
    let service_color = event.service.color();

    // Process
    let proc_name = event.process_name.as_deref().unwrap_or("?");
    let proc_display: String = if proc_name.len() > 14 {
        proc_name[..14].to_string()
    } else {
        format!("{:<14}", proc_name)
    };

    // Country code
    let cc = if event.country_code.is_empty() {
        "--".to_string()
    } else {
        event.country_code.clone()
    };
    let cc_display = format!("{:>2}", cc);

    // Event kind info
    let (info_str, info_color) = match &event.kind {
        WireEventKind::NewConnection => {
            let flag = if event.is_threat { "\u{2620} THREAT " } else { "" };
            (format!("{}new connection", flag), NEW_CONN)
        }
        WireEventKind::ConnectionClosed => {
            ("connection closed".to_string(), CLOSED_CONN)
        }
        WireEventKind::StateChange { from, to } => {
            (format!("{} \u{2192} {}", from.label(), to.label()), STATE_CHANGE)
        }
    };

    // Row background tint based on event kind
    let row_fg = if event.is_threat {
        THREAT_COLOR
    } else {
        match &event.kind {
            WireEventKind::NewConnection => NEW_CONN,
            WireEventKind::ConnectionClosed => CLOSED_CONN,
            WireEventKind::StateChange { .. } => STATE_CHANGE,
        }
    };

    let dim = |c: Color| -> Color {
        match c {
            Color::Rgb(r, g, b) => Color::Rgb(
                (r as f32 * 0.6) as u8,
                (g as f32 * 0.6) as u8,
                (b as f32 * 0.6) as u8,
            ),
            other => other,
        }
    };

    let spans: Vec<Span<'a>> = vec![
        Span::styled(seq_str, Style::default().fg(SEQ_COLOR)),
        Span::styled(time_display, Style::default().fg(TIME_COLOR)),
        Span::styled(dir_str.to_string(), Style::default().fg(dir_color)),
        Span::styled(proto_str.to_string(), Style::default().fg(proto_color)),
        Span::styled(src_display, Style::default().fg(dim(theme::TEXT))),
        Span::raw(" "),
        Span::styled(dst_display, Style::default().fg(Color::White)),
        Span::raw(" "),
        Span::styled(service_str, Style::default().fg(service_color)),
        Span::styled(proc_display, Style::default().fg(theme::GREEN)),
        Span::raw(" "),
        Span::styled(cc_display, Style::default().fg(theme::TEXT_DIM)),
        Span::raw("  "),
        Span::styled(
            info_str,
            Style::default().fg(info_color).add_modifier(Modifier::BOLD),
        ),
    ];

    Line::from(spans)
}
