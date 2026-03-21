//! Wire view (View 0) — Wireshark-style three-pane network monitor.
//!
//! Replicates Wireshark's classic layout:
//!   Top pane:    Packet/event list with color-coded rows, selectable cursor
//!   Middle pane: Detail breakdown of the selected event (protocol layers)
//!   Bottom pane: Connection metadata (process, geo, bandwidth, timestamps)
//!
//! Auto-scrolls to newest events in live mode. Scrolling up pauses auto-scroll.
//! Press 'G' to jump to latest / resume auto-scroll.

use ratatui::layout::{Constraint, Direction as LayoutDir, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::wire::{WireEvent, WireEventKind};
use crate::data::{Direction, Protocol, TcpState};
use crate::data::protocols::AppProtocol;
use crate::format::{format_bps, format_time_ago};
use crate::theme;

// ─── Wireshark-inspired row colors (full row background) ────────────
// These mimic Wireshark's default coloring rules where each protocol
// gets a distinct background tint so you can visually scan traffic.

/// TCP SYN/handshake — light gray (Wireshark: light purple)
const BG_TCP_SYN: Color = Color::Rgb(18, 16, 28);
/// TCP established normal — subtle dark (Wireshark: light purple)
const BG_TCP: Color = Color::Rgb(12, 14, 26);
/// TCP FIN/RST/close — darker tint (Wireshark: dark gray)
const BG_TCP_CLOSE: Color = Color::Rgb(20, 12, 12);
/// HTTP/HTTPS — green tint (Wireshark: green)
const BG_HTTP: Color = Color::Rgb(10, 20, 14);
/// DNS — blue tint (Wireshark: blue)
const BG_DNS: Color = Color::Rgb(10, 14, 24);
/// SSH — yellow tint (Wireshark: light yellow)
const BG_SSH: Color = Color::Rgb(18, 18, 10);
/// Database (PostgreSQL, MySQL, Redis, MongoDB)
const BG_DB: Color = Color::Rgb(16, 12, 20);
/// Threat/bad — red tint (Wireshark: red for errors)
const BG_THREAT: Color = Color::Rgb(30, 8, 8);
/// Selected row highlight
const BG_SELECTED: Color = Color::Rgb(25, 35, 60);
/// Default
const BG_DEFAULT: Color = Color::Rgb(10, 13, 24);

/// Draw the Wire view.
///
/// Wireshark three-pane layout:
/// ```text
/// ┌─ Packet List ──────────────────────────────────────────────────┐
/// │ No.  Time     Source              Destination         Proto Inf│
/// │  1   0.000    192.168.1.5:43210   142.250.80.4:443    TLS  [SY│ ← selected (highlighted)
/// │  2   0.034    142.250.80.4:443    192.168.1.5:43210   TLS  [SY│
/// │  3   2.101    192.168.1.5:52100   8.8.8.8:53          DNS  Sta│
/// ├─ Event Detail ─────────────────────────────────────────────────┤
/// │ ▸ Event: New Connection (TCP SYN_SENT)                        │
/// │ ▸ Network: 192.168.1.5:43210 → 142.250.80.4:443 (HTTPS)      │
/// │ ▸ Process: chrome (PID 14523)                                 │
/// │ ▸ GeoIP: US — United States (Mountain View, CA)               │
/// ├─ Status ───────────────────────────────────────────────────────┤
/// │ Live ● 1,234 events | TCP:89 UDP:23 | ↑12.4KB/s ↓45.2KB/s    │
/// └────────────────────────────────────────────────────────────────┘
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Percentage(60),  // packet list
            Constraint::Percentage(30),  // detail pane
            Constraint::Length(3),       // status bar
        ])
        .split(area);

    draw_packet_list(f, app, rows[0]);
    draw_detail_pane(f, app, rows[1]);
    draw_status_bar(f, app, rows[2]);
}

// ─── Packet List Pane (Top) ─────────────────────────────────────────

fn draw_packet_list(f: &mut Frame, app: &App, area: Rect) {
    let live_indicator = if app.wire_auto_scroll { " \u{25cf} Live" } else { " \u{25cb} Paused" };
    let live_color = if app.wire_auto_scroll { Color::Rgb(80, 220, 120) } else { Color::Rgb(200, 160, 60) };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(vec![
            Span::styled(
                " \u{26a1} Wire ",
                Style::default().fg(Color::Rgb(60, 220, 180)).add_modifier(Modifier::BOLD),
            ),
            Span::styled(live_indicator, Style::default().fg(live_color)),
        ])
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 60 || inner.height < 3 {
        return;
    }

    // Column header — Wireshark style
    let header = build_header(inner.width as usize);

    let events = app.wire_tracker.events();
    let visible_rows = (inner.height as usize).saturating_sub(1); // minus header
    let total = events.len();

    // Determine scroll position
    let offset = if app.wire_auto_scroll {
        0 // newest first, show from top
    } else {
        let max_scroll = total.saturating_sub(visible_rows);
        app.wire_selected.min(max_scroll)
    };

    let mut lines: Vec<Line> = Vec::with_capacity(visible_rows + 1);
    lines.push(header);

    if events.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Capturing... waiting for network activity",
            Style::default().fg(theme::TEXT_DIM),
        )));
    } else {
        for (i, event) in events.iter().skip(offset).take(visible_rows).enumerate() {
            let is_selected = (offset + i) == app.wire_selected;
            lines.push(build_packet_row(event, app, inner.width as usize, is_selected));
        }
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

fn build_header(width: usize) -> Line<'static> {
    let h = format!(
        " {:<6} {:<10} {:<22} {:<22} {:<7} {}",
        "No.", "Time", "Source", "Destination", "Proto", "Info"
    );
    let truncated = if h.len() > width { h[..width].to_string() } else { h };
    Line::from(Span::styled(
        truncated,
        Style::default()
            .fg(Color::Rgb(140, 150, 170))
            .bg(Color::Rgb(16, 20, 35))
            .add_modifier(Modifier::BOLD),
    ))
}

fn build_packet_row<'a>(event: &WireEvent, app: &App, width: usize, selected: bool) -> Line<'a> {
    // Row background color — protocol-based like Wireshark
    let row_bg = if selected {
        BG_SELECTED
    } else if event.is_threat {
        BG_THREAT
    } else {
        match &event.kind {
            WireEventKind::ConnectionClosed => BG_TCP_CLOSE,
            _ => match event.service {
                AppProtocol::HTTP | AppProtocol::HTTPS => BG_HTTP,
                AppProtocol::DNS => BG_DNS,
                AppProtocol::SSH => BG_SSH,
                AppProtocol::PostgreSQL | AppProtocol::MySQL | AppProtocol::Redis | AppProtocol::MongoDB => BG_DB,
                _ => match &event.kind {
                    WireEventKind::NewConnection if event.state == TcpState::SynSent || event.state == TcpState::SynRecv => BG_TCP_SYN,
                    _ => BG_DEFAULT,
                }
            }
        }
    };

    // No. column
    let seq = format!(" {:<6}", event.seq);

    // Time — relative seconds since event (like Wireshark's relative time)
    let time_str = event.timestamp.format("%H:%M:%S").to_string();
    let time_display = format!("{:<10}", time_str);

    // Source
    let src = if event.direction == Direction::Outbound || event.direction == Direction::Local {
        format!("{}", event.local_addr)
    } else {
        format!("{}", event.remote_addr)
    };
    let src_display = truncpad(&src, 22);

    // Destination
    let dst_raw = if event.direction == Direction::Outbound || event.direction == Direction::Local {
        // Show hostname if available for outbound destinations
        event.hostname.as_deref()
            .map(|h| {
                let port = event.remote_addr.port();
                if h.len() > 16 { format!("{}..:{}", &h[..16], port) }
                else { format!("{}:{}", h, port) }
            })
            .unwrap_or_else(|| format!("{}", event.remote_addr))
    } else {
        format!("{}", event.local_addr)
    };
    let dst_display = truncpad(&dst_raw, 22);

    // Protocol — show service name, color by protocol
    let proto_label = event.service.label();
    let proto_display = format!("{:<7}", proto_label);
    let proto_color = event.service.color();

    // Info column — Wireshark-style description with TCP flags
    let info = build_info_string(event);

    let sel_mod = if selected { Modifier::BOLD } else { Modifier::empty() };

    let spans: Vec<Span<'a>> = vec![
        Span::styled(seq, Style::default().fg(Color::Rgb(70, 80, 100)).bg(row_bg).add_modifier(sel_mod)),
        Span::styled(time_display, Style::default().fg(Color::Rgb(120, 135, 160)).bg(row_bg).add_modifier(sel_mod)),
        Span::styled(src_display, Style::default().fg(Color::Rgb(160, 170, 190)).bg(row_bg).add_modifier(sel_mod)),
        Span::raw(" "),
        Span::styled(dst_display, Style::default().fg(Color::Rgb(190, 200, 220)).bg(row_bg).add_modifier(sel_mod)),
        Span::raw(" "),
        Span::styled(proto_display, Style::default().fg(proto_color).bg(row_bg).add_modifier(sel_mod)),
        Span::styled(info, Style::default().fg(Color::Rgb(200, 210, 230)).bg(row_bg).add_modifier(sel_mod)),
    ];

    Line::from(spans)
}

/// Build the Info column string — mimics Wireshark's protocol-specific summaries.
fn build_info_string(event: &WireEvent) -> String {
    let dir_arrow = match event.direction {
        Direction::Outbound => "\u{2192}",
        Direction::Inbound => "\u{2190}",
        Direction::Local => "\u{2194}",
        Direction::Unknown => "?",
    };

    let ports = format!(
        "{} {} {}",
        event.local_addr.port(),
        dir_arrow,
        event.remote_addr.port()
    );

    match &event.kind {
        WireEventKind::NewConnection => {
            let flags = tcp_flags_str(event.state);
            let threat = if event.is_threat { " \u{2620}THREAT" } else { "" };
            let proc = event.process_name.as_deref().unwrap_or("?");
            format!("{} {} Len=0 <{}>{}",  ports, flags, proc, threat)
        }
        WireEventKind::StateChange { from, to } => {
            let flags = tcp_flags_str(*to);
            format!("{} {} {} \u{2192} {}", ports, flags, short_state(*from), short_state(*to))
        }
        WireEventKind::ConnectionClosed => {
            let proc = event.process_name.as_deref().unwrap_or("?");
            format!("{} [FIN, ACK] connection closed <{}>", ports, proc)
        }
    }
}

/// Map TCP state to Wireshark-like flag notation.
fn tcp_flags_str(state: TcpState) -> &'static str {
    match state {
        TcpState::SynSent => "[SYN]",
        TcpState::SynRecv => "[SYN, ACK]",
        TcpState::Established => "[ACK]",
        TcpState::FinWait1 => "[FIN, ACK]",
        TcpState::FinWait2 => "[FIN, ACK]",
        TcpState::CloseWait => "[FIN, ACK]",
        TcpState::LastAck => "[ACK]",
        TcpState::TimeWait => "[ACK]",
        TcpState::Closing => "[RST]",
        TcpState::Close => "[RST, ACK]",
        _ => "",
    }
}

fn short_state(state: TcpState) -> &'static str {
    match state {
        TcpState::Established => "EST",
        TcpState::SynSent => "SYN",
        TcpState::SynRecv => "SYN+A",
        TcpState::FinWait1 => "FIN1",
        TcpState::FinWait2 => "FIN2",
        TcpState::TimeWait => "TW",
        TcpState::Close => "CLOSE",
        TcpState::CloseWait => "CW",
        TcpState::LastAck => "LACK",
        TcpState::Listen => "LISTEN",
        TcpState::Closing => "CLOSING",
        TcpState::Unknown => "?",
    }
}

// ─── Detail Pane (Middle) ───────────────────────────────────────────

fn draw_detail_pane(f: &mut Frame, app: &App, area: Rect) {
    let expand_icon = if app.wire_detail_expanded { "\u{25bc}" } else { "\u{25b6}" };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(vec![
            Span::styled(
                format!(" {} Event Detail ", expand_icon),
                Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " Enter=expand/collapse ",
                Style::default().fg(Color::Rgb(80, 90, 110)),
            ),
        ])
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 30 || inner.height < 1 {
        return;
    }

    let events = app.wire_tracker.events();
    let selected = app.wire_selected;
    let event = events.get(selected);

    let mut lines: Vec<Line> = Vec::new();
    let lbl = Style::default().fg(Color::Rgb(100, 180, 255)).add_modifier(Modifier::BOLD);
    let val = Style::default().fg(theme::TEXT);
    let dim = Style::default().fg(theme::TEXT_DIM);

    if let Some(ev) = event {
        // Always show the summary line (even when collapsed)
        let kind_str = match &ev.kind {
            WireEventKind::NewConnection => "New Connection",
            WireEventKind::ConnectionClosed => "Connection Closed",
            WireEventKind::StateChange { .. } => "State Transition",
        };
        let proc_name = ev.process_name.as_deref().unwrap_or("?");
        let proto = if ev.protocol == Protocol::Tcp { "TCP" } else { "UDP" };

        lines.push(Line::from(vec![
            Span::styled("  \u{25b8} ", lbl),
            Span::styled(format!("{} ", kind_str), val),
            Span::styled(format!("| {} {} \u{2192} {} ", proto, ev.local_addr, ev.remote_addr), dim),
            Span::styled(format!("| {} ", ev.service.label()), Style::default().fg(ev.service.color())),
            Span::styled(format!("| {} ", proc_name), Style::default().fg(theme::GREEN)),
        ]));

        // Expanded detail layers
        if app.wire_detail_expanded {
            // Network layer
            let dir_label = match ev.direction {
                Direction::Outbound => "\u{2192} Outbound",
                Direction::Inbound => "\u{2190} Inbound",
                Direction::Local => "\u{2194} Local",
                Direction::Unknown => "? Unknown",
            };
            lines.push(Line::from(vec![
                Span::styled("    \u{25b8} Network: ", lbl),
                Span::styled(format!("{} {} \u{2192} {} ", proto, ev.local_addr, ev.remote_addr), val),
                Span::styled(format!("({})", dir_label), dim),
            ]));

            // Service
            lines.push(Line::from(vec![
                Span::styled("    \u{25b8} Service: ", lbl),
                Span::styled(ev.service.label().to_string(), Style::default().fg(ev.service.color())),
                Span::styled(format!("  (port {})", ev.remote_addr.port()), dim),
            ]));

            // Process
            let pid_str = ev.pid.map(|p| format!(" (PID {})", p)).unwrap_or_default();
            lines.push(Line::from(vec![
                Span::styled("    \u{25b8} Process: ", lbl),
                Span::styled(proc_name.to_string(), Style::default().fg(theme::GREEN)),
                Span::styled(pid_str, dim),
            ]));

            // GeoIP
            if !ev.country_code.is_empty() {
                let hostname = ev.hostname.as_deref().unwrap_or("");
                lines.push(Line::from(vec![
                    Span::styled("    \u{25b8} GeoIP:   ", lbl),
                    Span::styled(ev.country_code.clone(), Style::default().fg(theme::CYAN)),
                    Span::styled(if hostname.is_empty() { String::new() } else { format!("  {}", hostname) }, dim),
                ]));
            }

            // Bandwidth
            if ev.tx_bps > 0.0 || ev.rx_bps > 0.0 {
                lines.push(Line::from(vec![
                    Span::styled("    \u{25b8} Traffic: ", lbl),
                    Span::styled(format!("\u{2191}{}", format_bps(ev.tx_bps)), Style::default().fg(theme::UPLOAD)),
                    Span::styled("  ", dim),
                    Span::styled(format!("\u{2193}{}", format_bps(ev.rx_bps)), Style::default().fg(theme::DOWNLOAD)),
                ]));
            }

            // Timestamp
            lines.push(Line::from(vec![
                Span::styled("    \u{25b8} Time:    ", lbl),
                Span::styled(ev.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(), dim),
                Span::styled(format!("  ({})", format_time_ago(ev.timestamp)), dim),
            ]));

            // Threat
            if ev.is_threat {
                lines.push(Line::from(vec![
                    Span::styled("    \u{25b8} ", lbl),
                    Span::styled(
                        "\u{2620} THREAT — IP on threat intelligence blocklist",
                        Style::default().fg(Color::Rgb(255, 60, 60)).add_modifier(Modifier::BOLD),
                    ),
                ]));
            }

            // State change
            if let WireEventKind::StateChange { from, to } = &ev.kind {
                lines.push(Line::from(vec![
                    Span::styled("    \u{25b8} Change:  ", lbl),
                    Span::styled(from.label().to_string(), Style::default().fg(theme::WARN)),
                    Span::styled(" \u{2192} ", dim),
                    Span::styled(to.label().to_string(), Style::default().fg(theme::GREEN)),
                ]));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  Select an event with j/k to view details (Enter to expand)",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

// ─── Status Bar (Bottom) ────────────────────────────────────────────

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 20 || inner.height == 0 {
        return;
    }

    let stats = &app.wire_tracker.stats;

    let line = Line::from(vec![
        Span::styled(
            if app.wire_auto_scroll { " \u{25cf} Live " } else { " \u{25cb} Scroll " },
            Style::default().fg(if app.wire_auto_scroll { Color::Rgb(80, 220, 120) } else { Color::Rgb(200, 160, 60) }).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} events", stats.total_events),
            Style::default().fg(theme::TEXT),
        ),
        Span::styled(" \u{2502} ", Style::default().fg(theme::BORDER)),
        Span::styled(format!("TCP:{} ", stats.tcp_count), Style::default().fg(theme::CYAN)),
        Span::styled(format!("UDP:{} ", stats.udp_count), Style::default().fg(theme::PURPLE)),
        Span::styled(" \u{2502} ", Style::default().fg(theme::BORDER)),
        Span::styled(format!("\u{2191}{} ", format_bps(app.current_tx_bps)), Style::default().fg(theme::UPLOAD)),
        Span::styled(format!("\u{2193}{} ", format_bps(app.current_rx_bps)), Style::default().fg(theme::DOWNLOAD)),
        Span::styled(" \u{2502} ", Style::default().fg(theme::BORDER)),
        Span::styled(" j", Style::default().fg(Color::Rgb(255, 200, 80))),
        Span::styled("/", Style::default().fg(theme::TEXT_DIM)),
        Span::styled("k", Style::default().fg(Color::Rgb(255, 200, 80))),
        Span::styled(":select ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled("G", Style::default().fg(Color::Rgb(255, 200, 80))),
        Span::styled(":latest ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled("Enter", Style::default().fg(Color::Rgb(255, 200, 80))),
        Span::styled(":detail ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled("?", Style::default().fg(Color::Rgb(255, 200, 80))),
        Span::styled(":help ", Style::default().fg(theme::TEXT_DIM)),
    ]);

    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

// ─── Helpers ────────────────────────────────────────────────────────

fn truncpad(s: &str, width: usize) -> String {
    if s.len() > width {
        s[..width].to_string()
    } else {
        format!("{:<width$}", s, width = width)
    }
}
