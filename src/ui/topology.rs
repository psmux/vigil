//! Topology view — hub-and-spoke network diagram.
//!
//! Three-column layout showing infrastructure (left), this server (center),
//! and remote hosts (right) with Unicode connection lines between them.

use std::collections::HashMap;
use std::net::IpAddr;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::data::geoip;
use crate::data::TcpState;
use crate::format;
use crate::theme;

/// Draw the Topology view (View 6).
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),  // left: infrastructure
            Constraint::Length(1),       // connector
            Constraint::Percentage(30),  // center: this server
            Constraint::Length(1),       // connector
            Constraint::Percentage(44),  // right: remote hosts
        ])
        .split(area);

    draw_infrastructure(f, app, columns[0]);
    draw_connector(f, columns[1]);
    draw_this_server(f, app, columns[2]);
    draw_connector(f, columns[3]);
    draw_remote_hosts(f, app, columns[4], app.scroll_offset);
}

// ─── Left column: Infrastructure ────────────────────────────────────

fn draw_infrastructure(f: &mut Frame, app: &App, area: Rect) {
    // Split into gateway box, DNS box, LAN devices box
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),   // gateway
            Constraint::Length(4 + app.dns_servers.len().min(3) as u16), // DNS
            Constraint::Min(4),      // LAN devices
        ])
        .split(area);

    draw_gateway_box(f, app, chunks[0]);
    draw_dns_box(f, app, chunks[1]);
    draw_lan_box(f, app, chunks[2]);
}

fn draw_gateway_box(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER_HL))
        .title(Span::styled(" Gateway ", Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD)));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();
    if let Some(gw) = &app.gateway {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}", gw), Style::default().fg(theme::ACCENT)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled("\u{25CF}", Style::default().fg(theme::GREEN)),
            Span::styled(" Online", Style::default().fg(theme::TEXT_DIM)),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("  No gateway", Style::default().fg(theme::TEXT_DIM)),
        ]));
    }

    let para = Paragraph::new(lines);
    f.render_widget(para, inner);
}

fn draw_dns_box(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title(Span::styled(" DNS Servers ", Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD)));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();
    if app.dns_servers.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  None found", Style::default().fg(theme::TEXT_DIM)),
        ]));
    } else {
        for dns in app.dns_servers.iter().take(3) {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(format!("{}", dns), Style::default().fg(theme::CYAN)),
                Span::styled(" ", Style::default()),
                Span::styled("\u{25CF}", Style::default().fg(theme::GREEN)),
            ]));
        }
    }

    let para = Paragraph::new(lines);
    f.render_widget(para, inner);
}

fn draw_lan_box(f: &mut Frame, app: &App, area: Rect) {
    let count = app.neighbors.len();
    let title = format!(" LAN ({} devices) ", count);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title(Span::styled(title, Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD)));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let max_rows = inner.height as usize;
    let mut lines = Vec::new();

    for device in app.neighbors.iter().take(max_rows) {
        let ip_str = format!("{}", device.ip);
        let status_dot = if device.is_online { "\u{25CF}" } else { "\u{25CB}" };
        let status_color = if device.is_online { theme::GREEN } else { theme::TEXT_DIM };

        let label = device.hostname.as_deref()
            .or(device.vendor.as_deref())
            .unwrap_or("");

        // Truncate label to fit
        let max_label = (inner.width as usize).saturating_sub(ip_str.len() + 4);
        let short_label: String = if label.len() > max_label {
            format!("{}..", &label[..max_label.saturating_sub(2)])
        } else {
            label.to_string()
        };

        let mut spans = vec![
            Span::styled(format!(" {}", status_dot), Style::default().fg(status_color)),
            Span::styled(format!(" {}", ip_str), Style::default().fg(theme::TEXT)),
        ];
        if !short_label.is_empty() {
            spans.push(Span::styled(format!(" {}", short_label), Style::default().fg(theme::TEXT_DIM)));
        }
        lines.push(Line::from(spans));
    }

    if lines.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  No neighbors", Style::default().fg(theme::TEXT_DIM)),
        ]));
    }

    let para = Paragraph::new(lines);
    f.render_widget(para, inner);
}

// ─── Connector column ──────────────────────────────────────────────

fn draw_connector(f: &mut Frame, area: Rect) {
    let mut lines = Vec::new();
    for row in 0..area.height {
        let ch = if row == area.height / 2 {
            "\u{2500}" // ─  horizontal line at midpoint
        } else {
            "\u{2502}" // │  vertical line
        };
        lines.push(Line::from(Span::styled(ch, Style::default().fg(theme::BORDER_HL))));
    }
    let para = Paragraph::new(lines);
    f.render_widget(para, area);
}

// ─── Center column: This Server ─────────────────────────────────────

fn draw_this_server(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD))
        .title(Span::styled(" This Server ", Style::default().fg(theme::TAB_ACTIVE_FG).add_modifier(Modifier::BOLD)));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();

    // Hostname
    lines.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(&app.hostname, Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD)),
    ]));

    // Primary IP (first non-loopback interface)
    let primary_ip = app.interfaces.iter()
        .find(|i| i.up && i.ip != "127.0.0.1" && !i.ip.is_empty())
        .map(|i| i.ip.clone())
        .unwrap_or_else(|| "unknown".into());
    lines.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(primary_ip, Style::default().fg(theme::TEXT)),
    ]));

    // Blank separator
    lines.push(Line::from(""));

    // Bandwidth
    let rx = format::format_bps(app.current_rx_bps);
    let tx = format::format_bps(app.current_tx_bps);
    lines.push(Line::from(vec![
        Span::styled("  \u{2193}", Style::default().fg(theme::DOWNLOAD)),
        Span::styled(format!("{}", rx), Style::default().fg(theme::DOWNLOAD)),
        Span::styled("  \u{2191}", Style::default().fg(theme::UPLOAD)),
        Span::styled(format!("{}", tx), Style::default().fg(theme::UPLOAD)),
    ]));

    // Blank separator
    lines.push(Line::from(""));

    // Firewall status
    let fw_label = if app.firewall_active { "ON" } else { "OFF" };
    let fw_color = if app.firewall_active { theme::GREEN } else { theme::RED };
    lines.push(Line::from(vec![
        Span::styled("  FW: ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled(fw_label, Style::default().fg(fw_color).add_modifier(Modifier::BOLD)),
    ]));

    // Security score
    let score = app.security_score;
    let sc = theme::score_color(score);
    lines.push(Line::from(vec![
        Span::styled("  Score: ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled(format!("{}", score), Style::default().fg(sc).add_modifier(Modifier::BOLD)),
    ]));

    // Blank separator
    lines.push(Line::from(""));

    // Uptime
    lines.push(Line::from(vec![
        Span::styled("  Up: ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled(format::format_duration(app.uptime_secs), Style::default().fg(theme::TEXT)),
    ]));

    // Connection count
    let conn_count = app.connections.len();
    lines.push(Line::from(vec![
        Span::styled("  Conns: ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled(format!("{}", conn_count), Style::default().fg(theme::TEXT)),
    ]));

    // Listening ports count
    let listen_count = app.ports.len();
    lines.push(Line::from(vec![
        Span::styled("  Ports: ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled(format!("{}", listen_count), Style::default().fg(theme::TEXT)),
    ]));

    // Active attacks
    let attack_count = app.attack_count_total;
    if attack_count > 0 {
        lines.push(Line::from(vec![
            Span::styled("  Attacks: ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format::format_count(attack_count), Style::default().fg(theme::RED)),
        ]));
    }

    // CPU / Memory summary
    if !app.cpu.cores.is_empty() {
        let avg_cpu: f32 = app.cpu.cores.iter().map(|c| c.usage_percent).sum::<f32>()
            / app.cpu.cores.len() as f32;
        lines.push(Line::from(vec![
            Span::styled("  CPU: ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format!("{:.0}%", avg_cpu), Style::default().fg(
                if avg_cpu > 80.0 { theme::RED } else if avg_cpu > 50.0 { theme::GOLD } else { theme::GREEN }
            )),
        ]));
    }

    if app.memory.total > 0 {
        let mem_pct = (app.memory.used as f64 / app.memory.total as f64 * 100.0) as u8;
        lines.push(Line::from(vec![
            Span::styled("  Mem: ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format!("{}%", mem_pct), Style::default().fg(
                if mem_pct > 85 { theme::RED } else if mem_pct > 60 { theme::GOLD } else { theme::GREEN }
            )),
        ]));
    }

    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(para, inner);
}

// ─── Right column: Remote Hosts ─────────────────────────────────────

/// Aggregated remote host for display.
struct RemoteHost {
    ip: IpAddr,
    hostname: Option<String>,
    country_code: String,
    conn_count: usize,
    protocols: String,
    is_threat: bool,
}

fn draw_remote_hosts(f: &mut Frame, app: &App, area: Rect, scroll: usize) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title(Span::styled(" Remote Hosts ", Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD)));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Aggregate connections by remote IP
    let mut host_map: HashMap<IpAddr, (usize, bool, HashMap<String, usize>)> = HashMap::new();
    for conn in &app.connections {
        let ip = conn.remote_addr.ip();
        // Skip loopback / private for remote hosts display
        if geoip::is_private_ip(ip) {
            continue;
        }
        let entry = host_map.entry(ip).or_insert_with(|| (0, false, HashMap::new()));
        entry.0 += 1;
        if conn.is_threat {
            entry.1 = true;
        }
        let proto = match conn.protocol {
            crate::data::Protocol::Tcp => match conn.state {
                TcpState::Established => "TCP",
                TcpState::SynSent | TcpState::SynRecv => "SYN",
                TcpState::TimeWait => "TW",
                _ => "TCP",
            },
            crate::data::Protocol::Udp => "UDP",
        };
        *entry.2.entry(proto.to_string()).or_insert(0) += 1;
    }

    let mut hosts: Vec<RemoteHost> = host_map.into_iter().map(|(ip, (count, threat, protos))| {
        let hostname = app.dns_cache.get(&ip).cloned();
        let country_code = app.geoip_cache.get(&ip)
            .map(|g| g.country_code.clone())
            .unwrap_or_default();

        // Build protocol summary: "3xTCP 1xUDP"
        let mut proto_parts: Vec<(String, usize)> = protos.into_iter().collect();
        proto_parts.sort_by(|a, b| b.1.cmp(&a.1));
        let protocols = proto_parts.iter()
            .map(|(p, c)| format!("{}x{}", c, p))
            .collect::<Vec<_>>()
            .join(" ");

        RemoteHost { ip, hostname, country_code, conn_count: count, protocols, is_threat: threat }
    }).collect();

    // Sort by connection count descending
    hosts.sort_by(|a, b| b.conn_count.cmp(&a.conn_count));

    if hosts.is_empty() {
        let para = Paragraph::new(Line::from(vec![
            Span::styled("  No remote connections", Style::default().fg(theme::TEXT_DIM)),
        ]));
        f.render_widget(para, inner);
        return;
    }

    // Each host uses 3 lines (IP line, protocol line, separator)
    let lines_per_host: usize = 3;
    let visible_hosts = (inner.height as usize) / lines_per_host;
    let max_scroll = hosts.len().saturating_sub(visible_hosts);
    let effective_scroll = scroll.min(max_scroll);

    let mut lines: Vec<Line> = Vec::new();

    for (_i, host) in hosts.iter().skip(effective_scroll).enumerate() {
        if lines.len() + lines_per_host > inner.height as usize {
            break;
        }

        let color = if host.is_threat {
            theme::RED
        } else {
            theme::GREEN
        };

        // Line 1: IP (or hostname) + country flag
        let ip_display = format::format_ip_masked(host.ip);
        let display_name = host.hostname.as_deref().unwrap_or(&ip_display);
        // Truncate display name
        let max_name = (inner.width as usize).saturating_sub(6);
        let short_name: String = if display_name.len() > max_name {
            format!("{}..", &display_name[..max_name.saturating_sub(2)])
        } else {
            display_name.to_string()
        };

        let mut name_spans = vec![
            Span::styled(format!(" {}", short_name), Style::default().fg(color)),
        ];
        if !host.country_code.is_empty() {
            name_spans.push(Span::styled(
                format!(" ({})", host.country_code),
                Style::default().fg(theme::TEXT_DIM),
            ));
        }
        lines.push(Line::from(name_spans));

        // Line 2: connection count + protocols
        lines.push(Line::from(vec![
            Span::styled(format!("  {}  ", host.protocols), Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                if host.is_threat { "\u{26A0} threat" } else { "" },
                Style::default().fg(if host.is_threat { theme::RED } else { theme::TEXT_DIM }),
            ),
        ]));

        // Line 3: separator
        let sep_width = inner.width as usize;
        let sep = "\u{2500}".repeat(sep_width);
        lines.push(Line::from(Span::styled(sep, Style::default().fg(theme::SEPARATOR))));
    }

    // Scroll indicator
    if hosts.len() > visible_hosts {
        let shown_end = (effective_scroll + visible_hosts).min(hosts.len());
        let indicator = format!(" [{}-{} of {}] j/k scroll ", effective_scroll + 1, shown_end, hosts.len());
        if lines.len() < inner.height as usize {
            lines.push(Line::from(Span::styled(indicator, Style::default().fg(theme::TEXT_DIM))));
        }
    }

    let para = Paragraph::new(lines);
    f.render_widget(para, inner);
}
