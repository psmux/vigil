use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::{Connection, Direction as ConnDirection, TcpState};
use crate::format::format_bps;
use crate::theme;
use crate::widgets::bar_chart::{draw_bar_chart, BarItem};
use crate::widgets::sparkline::draw_sparkline;

// ─── Color constants for this view ────────────────────────────────
const TEAL: Color = Color::Rgb(0, 200, 180);
const ORANGE: Color = Color::Rgb(255, 160, 60);

/// Draw the Network Pulse / Connections view (View 4).
///
/// Layout:
/// ```text
/// Vertical [
///   top_section (25%): Vertical [
///     bandwidth_sparklines (50%)
///     state_bar_chart (50%)
///   ]
///   pulse_cloud (Length 8): signal tag cloud (protocols, hosts, countries, processes)
///   connection_table (remaining)
/// ]
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let main_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),        // direction summary
            Constraint::Percentage(20),   // sparklines + state chart
            Constraint::Length(8),        // protocol cloud
            Constraint::Min(10),          // connection table
        ])
        .split(area);

    // ── Direction summary bar — the key numbers at a glance ──────
    draw_direction_summary(f, app, main_rows[0]);

    // ── Sparklines + state bar chart ─────────────────────────────
    let top_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(main_rows[1]);

    draw_bandwidth_sparklines(f, app, top_rows[0]);
    draw_state_bar_chart(f, app, top_rows[1]);

    // ── Protocol signal cloud (psnet-style) ──────────────────────
    draw_protocol_cloud(f, app, main_rows[2]);

    // ── Connection table ─────────────────────────────────────────
    draw_connection_table(f, app, main_rows[3]);
}

// ─── Direction Summary ───────────────────────────────────────────

fn draw_direction_summary(f: &mut Frame, app: &App, area: Rect) {
    use crate::data::{Direction as D, TcpState};

    let inbound = app.connections.iter()
        .filter(|c| c.direction == D::Inbound && c.state != TcpState::Listen)
        .count();
    let outbound = app.connections.iter()
        .filter(|c| c.direction == D::Outbound)
        .count();
    let local = app.connections.iter()
        .filter(|c| c.direction == D::Local && c.state != TcpState::Listen)
        .count();
    let listening = app.connections.iter()
        .filter(|c| c.state == TcpState::Listen)
        .count();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Traffic Summary ",
            Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let line = Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            format!("\u{2190} {} Inbound", inbound),
            Style::default().fg(theme::CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled("     ", Style::default()),
        Span::styled(
            format!("\u{2192} {} Outbound", outbound),
            Style::default().fg(theme::GREEN).add_modifier(Modifier::BOLD),
        ),
        Span::styled("     ", Style::default()),
        Span::styled(
            format!("\u{2194} {} Local", local),
            Style::default().fg(theme::TEXT_DIM),
        ),
        Span::styled("     ", Style::default()),
        Span::styled(
            format!("\u{25C9} {} Listening", listening),
            Style::default().fg(theme::BLUE).add_modifier(Modifier::BOLD),
        ),
    ]);

    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

// ─── Bandwidth Sparklines ─────────────────────────────────────────

fn draw_bandwidth_sparklines(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(area);

    let rx_data: Vec<f64> = app.bandwidth_rx.as_slice_ordered().iter().map(|v| **v).collect();
    let tx_data: Vec<f64> = app.bandwidth_tx.as_slice_ordered().iter().map(|v| **v).collect();

    draw_sparkline(
        f,
        cols[0],
        &rx_data,
        theme::DOWNLOAD,
        "Download",
        &format_bps(app.current_rx_bps),
    );

    draw_sparkline(
        f,
        cols[1],
        &tx_data,
        theme::UPLOAD,
        "Upload",
        &format_bps(app.current_tx_bps),
    );
}

// ─── State Bar Chart ──────────────────────────────────────────────

fn draw_state_bar_chart(f: &mut Frame, app: &App, area: Rect) {
    let state_counts = aggregate_by_state(&app.connections);

    let items: Vec<BarItem> = state_counts
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(state, count)| {
            let color = match state {
                TcpState::Established => theme::GREEN,
                TcpState::TimeWait => theme::PURPLE,
                TcpState::CloseWait => ORANGE,
                TcpState::SynSent => theme::CYAN,
                TcpState::Listen => theme::BLUE,
                _ => theme::state_color(*state),
            };
            BarItem {
                label: state.label().to_string(),
                value: *count as f64,
                color,
                suffix: None,
            }
        })
        .collect();

    draw_bar_chart(f, area, "Connection States", &items, 12);
}

/// Aggregate connections by TCP state, sorted by count descending.
fn aggregate_by_state(connections: &[Connection]) -> Vec<(TcpState, usize)> {
    let mut map: HashMap<TcpState, usize> = HashMap::new();
    for conn in connections {
        *map.entry(conn.state).or_insert(0) += 1;
    }
    let mut pairs: Vec<(TcpState, usize)> = map.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1));
    pairs
}

// ─── Connection Table ─────────────────────────────────────────────

/// Sort priority for TCP states (lower = shown first).
fn state_sort_priority(state: TcpState) -> u8 {
    match state {
        TcpState::Established => 0,
        TcpState::SynSent => 1,
        TcpState::SynRecv => 2,
        TcpState::CloseWait => 3,
        TcpState::TimeWait => 4,
        TcpState::FinWait1 => 5,
        TcpState::FinWait2 => 6,
        TcpState::LastAck => 7,
        TcpState::Closing => 8,
        TcpState::Close => 9,
        TcpState::Unknown => 10,
        TcpState::Listen => 11,
    }
}

fn draw_connection_table(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Connections ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 40 || inner.height < 2 {
        return;
    }

    // ── Filter and sort connections ───────────────────────────────
    let mut conns: Vec<&Connection> = app
        .connections
        .iter()
        .filter(|c| c.state != TcpState::Listen)
        .collect();

    conns.sort_by(|a, b| {
        state_sort_priority(a.state)
            .cmp(&state_sort_priority(b.state))
            .then_with(|| a.remote_addr.port().cmp(&b.remote_addr.port()))
    });

    let total = conns.len();

    // ── Header line ──────────────────────────────────────────────
    let header = build_header_line(inner.width as usize);

    // ── Visible rows (account for header) ────────────────────────
    let visible_rows = (inner.height as usize).saturating_sub(1);
    let max_scroll = total.saturating_sub(visible_rows);
    let offset = app.scroll_offset.min(max_scroll);

    let mut lines: Vec<Line> = Vec::with_capacity(visible_rows + 1);
    lines.push(header);

    for conn in conns.iter().skip(offset).take(visible_rows) {
        lines.push(build_connection_line(conn, app, inner.width as usize));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

/// Build the header line with column labels.
fn build_header_line(width: usize) -> Line<'static> {
    let header_str = format!(
        "{:<15} {:<7} {:<3} {:<22} {:<22} {:<20} {:<4} {:<12} {:>9} {:>9}",
        "Process", "PID", "Dir", "Local", "Remote", "Hostname", "CC", "State", "Rx", "Tx"
    );

    let truncated = if header_str.len() > width {
        header_str[..width].to_string()
    } else {
        header_str
    };

    Line::from(Span::styled(
        truncated,
        Style::default()
            .fg(theme::TEXT_DIM)
            .add_modifier(Modifier::BOLD),
    ))
}

/// Build a single connection row as a styled Line.
fn build_connection_line<'a>(conn: &Connection, app: &App, width: usize) -> Line<'a> {
    // ── Process name ─────────────────────────────────────────────
    let proc_name = conn.process_name.as_deref().unwrap_or("?");
    let proc_display: String = if proc_name.len() > 15 {
        proc_name[..15].to_string()
    } else {
        format!("{:<15}", proc_name)
    };

    // ── PID ──────────────────────────────────────────────────────
    let pid_display = conn
        .pid
        .map(|p| format!("{:<7}", p))
        .unwrap_or_else(|| format!("{:<7}", "-"));

    // ── Direction ────────────────────────────────────────────────
    let (dir_char, dir_color) = match conn.direction {
        ConnDirection::Inbound => ("\u{2190}  ", theme::CYAN),
        ConnDirection::Outbound => ("\u{2192}  ", theme::GREEN),
        ConnDirection::Local => ("\u{2194}  ", theme::TEXT_DIM),
        ConnDirection::Unknown => ("?  ", theme::TEXT_DIM),
    };

    // ── Local address ────────────────────────────────────────────
    let local_str = format!("{}", conn.local_addr);
    let local_display: String = if local_str.len() > 22 {
        local_str[..22].to_string()
    } else {
        format!("{:<22}", local_str)
    };

    // ── Remote address ───────────────────────────────────────────
    let remote_str = format!("{}", conn.remote_addr);
    let remote_display: String = if remote_str.len() > 22 {
        remote_str[..22].to_string()
    } else {
        format!("{:<22}", remote_str)
    };

    // ── Hostname (DNS lookup) ────────────────────────────────────
    let remote_ip = conn.remote_addr.ip();
    let (hostname_display, hostname_color): (String, Color) = match app.dns_cache.get(&remote_ip) {
        Some(name) => {
            let n: &str = name.as_str();
            let display = if n.len() > 20 {
                n[..20].to_string()
            } else {
                format!("{:<20}", n)
            };
            (display, TEAL)
        }
        None => {
            let ip_str = remote_ip.to_string();
            let display = if ip_str.len() > 20 {
                ip_str[..20].to_string()
            } else {
                format!("{:<20}", ip_str)
            };
            (display, theme::TEXT_DIM)
        }
    };

    // ── Country ──────────────────────────────────────────────────
    let (country_display, country_color) = match app.geoip_cache.get(&remote_ip) {
        Some(geo) if !geo.country_code.is_empty() => {
            let cc = &geo.country_code;
            (format!("{:<4}", cc), country_code_color(cc))
        }
        _ => (format!("{:<4}", "--"), theme::TEXT_DIM),
    };

    // ── State ────────────────────────────────────────────────────
    let state_label = conn.state.label();
    let state_display = format!("{:<12}", state_label);
    let state_color = theme::state_color(conn.state);

    // ── Rx / Tx — real per-connection bandwidth from AF_PACKET capture
    let rx_display = if conn.rx_bps > 0.0 {
        format!("{:>9}", format_bps(conn.rx_bps))
    } else {
        format!("{:>9}", "\u{2014}")
    };
    let tx_display = if conn.tx_bps > 0.0 {
        format!("{:>9}", format_bps(conn.tx_bps))
    } else {
        format!("{:>9}", "\u{2014}")
    };

    // ── Assemble spans ───────────────────────────────────────────
    let spans: Vec<Span<'a>> = vec![
        Span::styled(proc_display, Style::default().fg(theme::GREEN)),
        Span::raw(" "),
        Span::styled(pid_display, Style::default().fg(theme::TEXT_DIM)),
        Span::styled(dir_char.to_string(), Style::default().fg(dir_color)),
        Span::styled(local_display, Style::default().fg(theme::TEXT_DIM)),
        Span::raw(" "),
        Span::styled(remote_display, Style::default().fg(Color::White)),
        Span::raw(" "),
        Span::styled(hostname_display, Style::default().fg(hostname_color)),
        Span::raw(" "),
        Span::styled(country_display, Style::default().fg(country_color)),
        Span::styled(state_display, Style::default().fg(state_color)),
        Span::styled(rx_display, Style::default().fg(theme::TEXT_DIM)),
        Span::raw(" "),
        Span::styled(tx_display, Style::default().fg(theme::TEXT_DIM)),
    ];

    let _ = width;

    Line::from(spans)
}

/// Pick a color for a 2-letter country code for visual variety.
fn country_code_color(cc: &str) -> Color {
    match cc {
        "US" => Color::Rgb(60, 140, 255),
        "CN" => Color::Rgb(255, 80, 80),
        "RU" => Color::Rgb(255, 160, 60),
        "DE" => Color::Rgb(255, 220, 80),
        "GB" => Color::Rgb(80, 200, 255),
        "FR" => Color::Rgb(100, 150, 255),
        "JP" => Color::Rgb(255, 140, 180),
        "KR" => Color::Rgb(130, 200, 140),
        "IN" => Color::Rgb(255, 180, 60),
        "BR" => Color::Rgb(80, 200, 120),
        "NL" => Color::Rgb(255, 140, 0),
        "SG" => Color::Rgb(200, 130, 255),
        _ => Color::Rgb(140, 160, 190),
    }
}

// ─── Protocol Cloud (ported from psnet/src/ui/widgets/protocol_cloud.rs) ─

/// Compact count formatting — identical to psnet's compact_count().
fn compact_count(n: u64) -> String {
    if n >= 1_000_000 {
        let m = n as f64 / 1_000_000.0;
        if m >= 100.0 { format!("{}M", m as u64) }
        else if m >= 10.0 { format!("{:.0}M", m) }
        else { format!("{:.1}M", m) }
    } else if n >= 1_000 {
        let k = n as f64 / 1_000.0;
        if k >= 100.0 { format!("{}k", k as u64) }
        else if k >= 10.0 { format!("{:.0}k", k) }
        else { format!("{:.1}k", k) }
    } else {
        format!("{}", n)
    }
}

/// Interpolate a color toward dim — identical to psnet's fade_color().
fn fade_color(base: Color, brightness: f64) -> Color {
    match base {
        Color::Rgb(r, g, b) => {
            let (dr, dg, db) = (40u8, 45u8, 55u8);
            let br = brightness.clamp(0.0, 1.0);
            Color::Rgb(
                (dr as f64 + (r as f64 - dr as f64) * br) as u8,
                (dg as f64 + (g as f64 - dg as f64) * br) as u8,
                (db as f64 + (b as f64 - db as f64) * br) as u8,
            )
        }
        other => if brightness > 0.3 { other } else { Color::DarkGray },
    }
}

/// Draw the protocol tag cloud — ported from psnet's draw_protocol_cloud().
///
/// Uses `app.proto_tracker` (psnet's ProtocolTracker) directly.
fn draw_protocol_cloud(f: &mut Frame, app: &App, area: Rect) {
    let bg = Color::Rgb(8, 12, 24);
    let border_color = Color::Rgb(30, 50, 85);
    let title_color = Color::Rgb(100, 160, 255);

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Network Signals ", Style::default().fg(title_color)),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(bg));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 4 || inner.height < 1 {
        return;
    }

    let tick = app.tick_count;
    let protos = app.proto_tracker.active_protocols(tick);

    if protos.is_empty() {
        let empty = Paragraph::new(Line::from(vec![
            Span::styled(
                "  Waiting for packets...",
                Style::default().fg(Color::Rgb(60, 70, 90)),
            ),
        ]))
        .style(Style::default().bg(bg));
        f.render_widget(empty, inner);
        return;
    }

    let max_width = inner.width as usize;
    let max_lines = inner.height as usize;

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut current_spans: Vec<Span<'static>> = Vec::new();
    let mut current_width: usize = 0;

    for (label, activity, color) in &protos {
        let brightness = app.proto_tracker.brightness(label, tick);
        let is_active = brightness > 0.0;

        let count_str = compact_count(activity.count);
        let tag_text = format!("{}:{}", label, count_str);
        let tag_width = tag_text.len() + 1; // +1 trailing space

        // Wrap to next line if needed
        if current_width + tag_width > max_width && !current_spans.is_empty() {
            lines.push(Line::from(current_spans));
            current_spans = Vec::new();
            current_width = 0;
            if lines.len() >= max_lines {
                break;
            }
        }

        let fg = fade_color(*color, brightness);
        let mut style = Style::default().fg(fg).bg(bg);
        if is_active {
            style = style.add_modifier(Modifier::BOLD);
        }

        // Recent activity marker: ● prefix for very active protocols
        if is_active && activity.recent_count > 0 {
            let dot_brightness = brightness.clamp(0.5, 1.0);
            let dot_color = fade_color(*color, dot_brightness);
            current_spans.push(Span::styled(
                "\u{25cf}".to_string(),
                Style::default().fg(dot_color).bg(bg),
            ));
            current_width += 1;
        }

        current_spans.push(Span::styled(tag_text, style));
        current_spans.push(Span::styled(" ".to_string(), Style::default().bg(bg)));
        current_width += tag_width;
    }

    if !current_spans.is_empty() && lines.len() < max_lines {
        lines.push(Line::from(current_spans));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(bg));
    f.render_widget(paragraph, inner);
}
