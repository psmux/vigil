//! Wire view (View 0) — Wireshark-style three-pane network monitor.
//!
//! Top:    Packet list — color-coded rows, selectable cursor, auto-scroll
//! Middle: Protocol detail — expandable tree showing all layers of selected event
//! Bottom: Packet data — hex-dump style view of TCP internals + connection metadata

use ratatui::layout::{Constraint, Direction as LayoutDir, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::wire::{WireEvent, WireEventKind};
use crate::data::{Direction, Protocol, TcpState};
use crate::data::protocols::AppProtocol;
use crate::format::{format_bps, format_bytes, format_time_ago};
use crate::theme;

// ─── Wireshark row background colors by protocol ────────────────────
const BG_TCP_SYN: Color = Color::Rgb(18, 16, 28);
const BG_TCP: Color = Color::Rgb(12, 14, 26);
const BG_TCP_CLOSE: Color = Color::Rgb(20, 12, 12);
const BG_HTTP: Color = Color::Rgb(10, 20, 14);
const BG_DNS: Color = Color::Rgb(10, 14, 24);
const BG_SSH: Color = Color::Rgb(18, 18, 10);
const BG_DB: Color = Color::Rgb(16, 12, 20);
const BG_THREAT: Color = Color::Rgb(30, 8, 8);
const BG_SELECTED: Color = Color::Rgb(25, 35, 60);
const BG_DEFAULT: Color = Color::Rgb(10, 13, 24);

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    // Wireshark three-pane: adjust ratio based on detail expanded
    let constraints = if app.wire_detail_expanded {
        vec![
            Constraint::Percentage(45),
            Constraint::Percentage(30),
            Constraint::Percentage(22),
            Constraint::Length(3),
        ]
    } else {
        vec![
            Constraint::Percentage(75),
            Constraint::Length(3), // collapsed detail = just title
            Constraint::Percentage(0),
            Constraint::Length(3),
        ]
    };

    let rows = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints(constraints)
        .split(area);

    draw_packet_list(f, app, rows[0]);
    draw_detail_pane(f, app, rows[1]);
    if app.wire_detail_expanded {
        draw_bytes_pane(f, app, rows[2]);
    }
    let status_area = if app.wire_detail_expanded { rows[3] } else { rows[3] };
    draw_status_bar(f, app, status_area);
}

// ═══════════════════════════════════════════════════════════════════
// PANE 1: PACKET LIST
// ═══════════════════════════════════════════════════════════════════

fn draw_packet_list(f: &mut Frame, app: &App, area: Rect) {
    let live_str = if app.wire_auto_scroll { " \u{25cf} Live" } else { " \u{25cb} Scroll" };
    let live_color = if app.wire_auto_scroll { Color::Rgb(80, 220, 120) } else { Color::Rgb(200, 160, 60) };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(vec![
            Span::styled(" \u{26a1} Wire ", Style::default().fg(Color::Rgb(60, 220, 180)).add_modifier(Modifier::BOLD)),
            Span::styled(live_str, Style::default().fg(live_color)),
        ])
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width < 60 || inner.height < 3 { return; }

    let w = inner.width as usize;

    // Wireshark-style column header
    let header = Line::from(Span::styled(
        truncpad(&format!(
            " {:<6} {:<10} {:<21} {:<21} {:<8} {:<5} {}",
            "No.", "Time", "Source", "Destination", "Protocol", "Len", "Info"
        ), w),
        Style::default().fg(Color::Rgb(140, 150, 170)).bg(Color::Rgb(16, 20, 35)).add_modifier(Modifier::BOLD),
    ));

    let events = app.wire_tracker.events();
    let visible = (inner.height as usize).saturating_sub(1);
    let total = events.len();
    let offset = if app.wire_auto_scroll { 0 } else {
        app.wire_selected.saturating_sub(visible / 2).min(total.saturating_sub(visible))
    };

    let mut lines: Vec<Line> = Vec::with_capacity(visible + 1);
    lines.push(header);

    if events.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Capturing... waiting for network activity",
            Style::default().fg(theme::TEXT_DIM),
        )));
    } else {
        for (i, ev) in events.iter().skip(offset).take(visible).enumerate() {
            let selected = (offset + i) == app.wire_selected;
            lines.push(build_packet_row(ev, app, w, selected));
        }
    }

    f.render_widget(Paragraph::new(lines).style(Style::default().bg(theme::BG)), inner);
}

fn build_packet_row<'a>(ev: &WireEvent, _app: &App, width: usize, selected: bool) -> Line<'a> {
    let row_bg = if selected { BG_SELECTED }
        else if ev.is_threat { BG_THREAT }
        else { match &ev.kind {
            WireEventKind::ConnectionClosed => BG_TCP_CLOSE,
            _ => match ev.service {
                AppProtocol::HTTP | AppProtocol::HTTPS => BG_HTTP,
                AppProtocol::DNS => BG_DNS,
                AppProtocol::SSH => BG_SSH,
                AppProtocol::PostgreSQL | AppProtocol::MySQL | AppProtocol::Redis | AppProtocol::MongoDB => BG_DB,
                _ if matches!(&ev.kind, WireEventKind::NewConnection) && (ev.state == TcpState::SynSent || ev.state == TcpState::SynRecv) => BG_TCP_SYN,
                _ => BG_DEFAULT,
            }
        }};

    let sel = if selected { Modifier::BOLD } else { Modifier::empty() };
    let s = |fg: Color| Style::default().fg(fg).bg(row_bg).add_modifier(sel);

    // No.
    let seq = format!(" {:<6}", ev.seq);
    // Time
    let time = format!("{:<10}", ev.timestamp.format("%H:%M:%S"));
    // Source / Destination — show like Wireshark (src→dst based on who initiated)
    let (src, dst) = if ev.direction == Direction::Outbound || ev.direction == Direction::Local {
        (format!("{}", ev.local_addr), format_dst(ev))
    } else {
        (format!("{}", ev.remote_addr), format!("{}", ev.local_addr))
    };
    let src_d = truncpad(&src, 21);
    let dst_d = truncpad(&dst, 21);
    // Protocol
    let proto = format!("{:<8}", ev.service.label());
    // Length (tx_queue + rx_queue as byte estimate)
    let len = ev.tx_queue + ev.rx_queue;
    let len_str = format!("{:<5}", if len > 0 { format!("{}", len) } else { "-".into() });
    // Info — Wireshark-style with TCP flags and content preview
    let info = build_info(ev);

    Line::from(vec![
        Span::styled(seq, s(Color::Rgb(70, 80, 100))),
        Span::styled(time, s(Color::Rgb(120, 135, 160))),
        Span::styled(src_d, s(Color::Rgb(160, 170, 190))),
        Span::raw(" "),
        Span::styled(dst_d, s(Color::Rgb(190, 200, 220))),
        Span::raw(" "),
        Span::styled(proto, s(ev.service.color())),
        Span::styled(len_str, s(Color::Rgb(100, 110, 130))),
        Span::styled(truncpad(&info, width.saturating_sub(78)), s(Color::Rgb(200, 210, 230))),
    ])
}

/// Wireshark-style Info column with TCP flags, port arrows, and content hints.
fn build_info(ev: &WireEvent) -> String {
    let lp = ev.local_addr.port();
    let rp = ev.remote_addr.port();
    let arrow = match ev.direction {
        Direction::Outbound => "\u{2192}",
        Direction::Inbound => "\u{2190}",
        _ => "\u{2194}",
    };

    match &ev.kind {
        WireEventKind::NewConnection => {
            let flags = state_to_flags(ev.state);
            let win = if ev.rx_queue > 0 { format!(" Win={}", ev.rx_queue) } else { String::new() };
            let host = ev.hostname.as_deref().map(|h| format!(" [{}]", h)).unwrap_or_default();
            let threat = if ev.is_threat { " \u{2620}THREAT" } else { "" };
            format!("{} {} {} {} Seq=0{} Len=0{}{}", lp, arrow, rp, flags, win, host, threat)
        }
        WireEventKind::StateChange { from, to } => {
            let flags = state_to_flags(*to);
            let retrans = if ev.retransmits > 0 { format!(" [{}x retrans]", ev.retransmits) } else { String::new() };
            let queue = if ev.tx_queue > 0 || ev.rx_queue > 0 {
                format!(" TxQ={} RxQ={}", ev.tx_queue, ev.rx_queue)
            } else { String::new() };
            format!("{} {} {} {} {} \u{2192} {}{}{}", lp, arrow, rp, flags, short_state(*from), short_state(*to), queue, retrans)
        }
        WireEventKind::ConnectionClosed => {
            let proc = ev.process_name.as_deref().unwrap_or("?");
            let host = ev.hostname.as_deref().map(|h| format!(" [{}]", h)).unwrap_or_default();
            format!("{} {} {} [FIN, ACK] closed <{}>{}", lp, arrow, rp, proc, host)
        }
    }
}

fn state_to_flags(state: TcpState) -> &'static str {
    match state {
        TcpState::SynSent => "[SYN]",
        TcpState::SynRecv => "[SYN, ACK]",
        TcpState::Established => "[ACK]",
        TcpState::FinWait1 | TcpState::FinWait2 | TcpState::CloseWait => "[FIN, ACK]",
        TcpState::LastAck | TcpState::TimeWait => "[ACK]",
        TcpState::Closing | TcpState::Close => "[RST, ACK]",
        _ => "",
    }
}

fn short_state(s: TcpState) -> &'static str {
    match s {
        TcpState::Established => "EST",  TcpState::SynSent => "SYN",
        TcpState::SynRecv => "SYN+A",   TcpState::FinWait1 => "FIN1",
        TcpState::FinWait2 => "FIN2",   TcpState::TimeWait => "TW",
        TcpState::Close => "CLOSE",     TcpState::CloseWait => "CW",
        TcpState::LastAck => "LACK",    TcpState::Listen => "LISTEN",
        TcpState::Closing => "CLOSING", TcpState::Unknown => "?",
    }
}

fn format_dst(ev: &WireEvent) -> String {
    ev.hostname.as_deref()
        .map(|h| {
            let p = ev.remote_addr.port();
            if h.len() > 15 { format!("{}..:{}", &h[..15], p) }
            else { format!("{}:{}", h, p) }
        })
        .unwrap_or_else(|| format!("{}", ev.remote_addr))
}

// ═══════════════════════════════════════════════════════════════════
// PANE 2: PROTOCOL DETAIL (expandable tree)
// ═══════════════════════════════════════════════════════════════════

fn draw_detail_pane(f: &mut Frame, app: &App, area: Rect) {
    let icon = if app.wire_detail_expanded { "\u{25bc}" } else { "\u{25b6}" };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(vec![
            Span::styled(format!(" {} Protocol Detail ", icon), Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD)),
            Span::styled("  Enter: expand/collapse  ", Style::default().fg(Color::Rgb(255, 200, 80))),
        ])
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width < 30 || inner.height < 1 { return; }

    let events = app.wire_tracker.events();
    let ev = events.get(app.wire_selected);

    let lbl = Style::default().fg(Color::Rgb(100, 180, 255)).add_modifier(Modifier::BOLD);
    let val = Style::default().fg(theme::TEXT);
    let dim = Style::default().fg(theme::TEXT_DIM);
    let tree = Style::default().fg(Color::Rgb(40, 50, 70));

    let mut lines: Vec<Line> = Vec::new();

    match ev {
        None => {
            lines.push(Line::from(Span::styled(
                "  Use j/k to select an event, Enter to expand detail",
                Style::default().fg(theme::TEXT_DIM),
            )));
        }
        Some(ev) if !app.wire_detail_expanded => {
            // Collapsed: single summary line
            let kind = match &ev.kind {
                WireEventKind::NewConnection => "NEW",
                WireEventKind::ConnectionClosed => "CLOSE",
                WireEventKind::StateChange { .. } => "STATE",
            };
            let proto = if ev.protocol == Protocol::Tcp { "TCP" } else { "UDP" };
            let proc = ev.process_name.as_deref().unwrap_or("?");
            lines.push(Line::from(vec![
                Span::styled("  ", dim),
                Span::styled(format!("[{}] ", kind), lbl),
                Span::styled(format!("{} {} \u{2192} {} ", proto, ev.local_addr, ev.remote_addr), val),
                Span::styled(format!("({}) ", ev.service.label()), Style::default().fg(ev.service.color())),
                Span::styled(format!("<{}>", proc), Style::default().fg(theme::GREEN)),
            ]));
        }
        Some(ev) => {
            // Expanded: full Wireshark-style protocol tree
            let proto = if ev.protocol == Protocol::Tcp { "TCP" } else { "UDP" };
            let proc = ev.process_name.as_deref().unwrap_or("unknown");
            let kind_str = match &ev.kind {
                WireEventKind::NewConnection => "New Connection",
                WireEventKind::ConnectionClosed => "Connection Closed",
                WireEventKind::StateChange { from, to } => {
                    // Can't return a temp string, handle below
                    "State Transition"
                }
            };

            // Layer 1: Frame / Event
            lines.push(Line::from(vec![
                Span::styled("  \u{251c}\u{2500} ", tree),
                Span::styled("Event: ", lbl),
                Span::styled(kind_str.to_string(), val),
                Span::styled(format!("  state={}", ev.state.label()), dim),
            ]));
            if let WireEventKind::StateChange { from, to } = &ev.kind {
                lines.push(Line::from(vec![
                    Span::styled("  \u{2502}  \u{2514}\u{2500} ", tree),
                    Span::styled(format!("{} \u{2192} {}", from.label(), to.label()), Style::default().fg(theme::WARN)),
                ]));
            }

            // Layer 2: Network
            let dir_label = match ev.direction {
                Direction::Outbound => "\u{2192} Outbound",
                Direction::Inbound => "\u{2190} Inbound",
                Direction::Local => "\u{2194} Local",
                Direction::Unknown => "? Unknown",
            };
            lines.push(Line::from(vec![
                Span::styled("  \u{251c}\u{2500} ", tree),
                Span::styled(format!("{}, ", proto), lbl),
                Span::styled(format!("Src: {}  Dst: {}  ", ev.local_addr, ev.remote_addr), val),
                Span::styled(format!("({})", dir_label), dim),
            ]));

            // Layer 3: Service / Application
            lines.push(Line::from(vec![
                Span::styled("  \u{251c}\u{2500} ", tree),
                Span::styled("Service: ", lbl),
                Span::styled(format!("{}  ", ev.service.label()), Style::default().fg(ev.service.color())),
                Span::styled(format!("port={}", ev.remote_addr.port()), dim),
            ]));

            // Layer 4: Process
            let pid_str = ev.pid.map(|p| format!("  PID={}", p)).unwrap_or_default();
            lines.push(Line::from(vec![
                Span::styled("  \u{251c}\u{2500} ", tree),
                Span::styled("Process: ", lbl),
                Span::styled(proc.to_string(), Style::default().fg(theme::GREEN)),
                Span::styled(pid_str, dim),
            ]));

            // Layer 5: GeoIP + Hostname
            if !ev.country_code.is_empty() || ev.hostname.is_some() {
                let host = ev.hostname.as_deref().unwrap_or("");
                lines.push(Line::from(vec![
                    Span::styled("  \u{251c}\u{2500} ", tree),
                    Span::styled("GeoIP: ", lbl),
                    Span::styled(ev.country_code.clone(), Style::default().fg(theme::CYAN)),
                    Span::styled(if host.is_empty() { String::new() } else { format!("  hostname={}", host) }, dim),
                ]));
            }

            // Layer 6: TCP Internals
            if ev.tx_queue > 0 || ev.rx_queue > 0 || ev.retransmits > 0 || ev.tx_bps > 0.0 {
                let mut parts = vec![
                    Span::styled("  \u{251c}\u{2500} ", tree),
                    Span::styled("TCP: ", lbl),
                ];
                if ev.tx_queue > 0 { parts.push(Span::styled(format!("TxQueue={}  ", format_bytes(ev.tx_queue as u64)), val)); }
                if ev.rx_queue > 0 { parts.push(Span::styled(format!("RxQueue={}  ", format_bytes(ev.rx_queue as u64)), val)); }
                if ev.retransmits > 0 { parts.push(Span::styled(format!("Retrans={}  ", ev.retransmits), Style::default().fg(theme::RED))); }
                if ev.tx_bps > 0.0 { parts.push(Span::styled(format!("\u{2191}{}  ", format_bps(ev.tx_bps)), Style::default().fg(theme::UPLOAD))); }
                if ev.rx_bps > 0.0 { parts.push(Span::styled(format!("\u{2193}{}", format_bps(ev.rx_bps)), Style::default().fg(theme::DOWNLOAD))); }
                lines.push(Line::from(parts));
            }

            // Layer 7: Timestamp
            lines.push(Line::from(vec![
                Span::styled("  \u{251c}\u{2500} ", tree),
                Span::styled("Time: ", lbl),
                Span::styled(ev.timestamp.format("%Y-%m-%d %H:%M:%S.%3f UTC").to_string(), dim),
                Span::styled(format!("  ({})", format_time_ago(ev.timestamp)), dim),
            ]));

            // Threat
            if ev.is_threat {
                lines.push(Line::from(vec![
                    Span::styled("  \u{251c}\u{2500} ", tree),
                    Span::styled("\u{2620} THREAT ", Style::default().fg(theme::RED).add_modifier(Modifier::BOLD)),
                    Span::styled("IP on threat intelligence blocklist", Style::default().fg(theme::RED)),
                ]));
            }

            // End cap
            lines.push(Line::from(Span::styled("  \u{2514}\u{2500}\u{2500}\u{2500}", tree)));
        }
    }

    f.render_widget(Paragraph::new(lines).style(Style::default().bg(theme::BG)), inner);
}

// ═══════════════════════════════════════════════════════════════════
// PANE 3: PACKET BYTES (hex-dump style connection metadata)
// ═══════════════════════════════════════════════════════════════════

fn draw_bytes_pane(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Packet Data ",
            Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width < 40 || inner.height < 2 { return; }

    let events = app.wire_tracker.events();
    let ev = match events.get(app.wire_selected) {
        Some(e) => e,
        None => {
            f.render_widget(Paragraph::new("").style(Style::default().bg(theme::BG)), inner);
            return;
        }
    };

    let hex_fg = Style::default().fg(Color::Rgb(100, 160, 220));
    let ascii_fg = Style::default().fg(Color::Rgb(80, 200, 120));
    let offset_fg = Style::default().fg(Color::Rgb(60, 70, 90));
    let label_fg = Style::default().fg(Color::Rgb(140, 150, 170));

    // Build a pseudo-packet from connection metadata (like Wireshark's hex pane)
    // Format: offset | hex bytes | ASCII interpretation
    let mut data_lines: Vec<(String, String, String)> = Vec::new();

    // Row 1: Protocol + State
    let proto = if ev.protocol == Protocol::Tcp { "TCP" } else { "UDP" };
    let state_hex = format!("{:02x}", ev.state as u8);
    data_lines.push((
        "0000".into(),
        format!("{:<24}", format!("{:02x} {:02x} {:02x} {} {:02x} {:02x}",
            if ev.protocol == Protocol::Tcp { 0x06 } else { 0x11 },
            ev.state as u8,
            match ev.direction { Direction::Inbound => 0x01, Direction::Outbound => 0x02, Direction::Local => 0x03, _ => 0x00 },
            format_port_hex(ev.local_addr.port()),
            (ev.remote_addr.port() >> 8) as u8,
            (ev.remote_addr.port() & 0xff) as u8,
        )),
        format!("{} {} {}", proto, ev.state.label(), match ev.direction { Direction::Outbound => "OUT", Direction::Inbound => "IN", Direction::Local => "LO", _ => "??" }),
    ));

    // Row 2: Source IP
    let src_ip = ev.local_addr.ip();
    data_lines.push((
        "0008".into(),
        format!("{:<24}", format_ip_hex(src_ip)),
        format!("Src: {}", src_ip),
    ));

    // Row 3: Dest IP
    let dst_ip = ev.remote_addr.ip();
    data_lines.push((
        "0010".into(),
        format!("{:<24}", format_ip_hex(dst_ip)),
        format!("Dst: {}", dst_ip),
    ));

    // Row 4: Queues + retransmits
    data_lines.push((
        "0018".into(),
        format!("{:<24}", format!("{:04x} {:04x} {:04x} 0000",
            ev.tx_queue.min(0xffff) as u16,
            ev.rx_queue.min(0xffff) as u16,
            ev.retransmits.min(0xffff) as u16,
        )),
        format!("TxQ={} RxQ={} Ret={}", ev.tx_queue, ev.rx_queue, ev.retransmits),
    ));

    // Row 5: Service + hostname preview
    let svc = ev.service.label();
    let host = ev.hostname.as_deref().unwrap_or("-");
    let host_trunc = if host.len() > 20 { &host[..20] } else { host };
    data_lines.push((
        "0020".into(),
        format!("{:<24}", string_to_hex(svc)),
        format!("{} [{}]", svc, host_trunc),
    ));

    // Row 6: Process name
    let proc = ev.process_name.as_deref().unwrap_or("?");
    data_lines.push((
        "0028".into(),
        format!("{:<24}", string_to_hex(proc)),
        format!("Process: {}", proc),
    ));

    let mut lines: Vec<Line> = Vec::with_capacity(data_lines.len());
    for (offset, hex, ascii) in &data_lines {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}  ", offset), offset_fg),
            Span::styled(format!("{}  ", hex), hex_fg),
            Span::styled(ascii.clone(), ascii_fg),
        ]));
    }

    f.render_widget(Paragraph::new(lines).style(Style::default().bg(theme::BG)), inner);
}

fn format_port_hex(port: u16) -> String {
    format!("{:02x} {:02x}", (port >> 8) as u8, (port & 0xff) as u8)
}

fn format_ip_hex(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{:02x} {:02x} {:02x} {:02x} 00 00 00 00", o[0], o[1], o[2], o[3])
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:04x} {:04x} {:04x} {:04x}", s[0], s[1], s[2], s[3])
        }
    }
}

fn string_to_hex(s: &str) -> String {
    s.bytes().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

// ═══════════════════════════════════════════════════════════════════
// STATUS BAR
// ═══════════════════════════════════════════════════════════════════

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width < 20 || inner.height == 0 { return; }

    let stats = &app.wire_tracker.stats;
    let k = |s: &str| Span::styled(s.to_string(), Style::default().fg(Color::Rgb(255, 200, 80)));
    let t = |s: &str| Span::styled(s.to_string(), Style::default().fg(theme::TEXT_DIM));
    let sep = || Span::styled(" \u{2502} ", Style::default().fg(theme::BORDER));

    let line = Line::from(vec![
        Span::styled(
            if app.wire_auto_scroll { " \u{25cf} Live " } else { " \u{25cb} Scroll " },
            Style::default().fg(if app.wire_auto_scroll { Color::Rgb(80, 220, 120) } else { Color::Rgb(200, 160, 60) }).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{} events", stats.total_events), Style::default().fg(theme::TEXT)),
        sep(),
        Span::styled(format!("TCP:{} ", stats.tcp_count), Style::default().fg(theme::CYAN)),
        Span::styled(format!("UDP:{}", stats.udp_count), Style::default().fg(theme::PURPLE)),
        sep(),
        Span::styled(format!("\u{2191}{} ", format_bps(app.current_tx_bps)), Style::default().fg(theme::UPLOAD)),
        Span::styled(format!("\u{2193}{}", format_bps(app.current_rx_bps)), Style::default().fg(theme::DOWNLOAD)),
        sep(),
        k("j"), t("/"), k("k"), t(":select "),
        k("G"), t(":latest "),
        k("Enter"), t(":expand "),
        k("?"), t(":help"),
    ]);

    f.render_widget(Paragraph::new(line).style(Style::default().bg(theme::BG)), inner);
}

fn truncpad(s: &str, w: usize) -> String {
    if s.len() > w { s[..w].to_string() } else { format!("{:<width$}", s, width = w) }
}
