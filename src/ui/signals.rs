//! Signals view — live network activity tag cloud.
//!
//! Layout:
//! ```text
//! ┌─ header stats bar ──────────────────────────────────────┐
//! │  47 signals · 8 proto · 23 hosts · 12 countries · 5 proc│
//! ├─────────────────────────────────────────────────────────┤
//! │                                                          │
//! │  «HTTPS»  «SSH»  [US]  github.com  {nginx}  «DNS»      │
//! │  [DE]  {sshd}  cloudflare.com  «NTP»  [JP]  ●NEW       │
//! │  {postgres}  [GB]  «SMTP»  curl  ●CLOSED  [FR]         │
//! │                                                          │
//! ├─ Live Activity ─────────────────────────────────────────┤
//! │  → «HTTPS» github.com [US] {chrome}       12:34:56      │
//! │  ← «SSH»   192.168.1.5  {sshd}            12:34:55      │
//! │  × ●CLOSE  :5432 {postgres}               12:34:54      │
//! └─────────────────────────────────────────────────────────┘
//! ```

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::protocols::AppProtocol;
use crate::data::wire::WireEventKind;
use crate::theme;
use crate::widgets::tag_cloud::draw_tag_cloud;

/// Draw the Signals view.
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // summary bar
            Constraint::Min(6),   // tag cloud
            Constraint::Length(8), // live activity ticker
        ])
        .split(area);

    draw_summary_bar(f, app, rows[0]);

    let summary = app.signal_tracker.summary();
    let title = format!(
        "Signal Cloud \u{2500}\u{2500} {} active",
        summary.total,
    );
    draw_tag_cloud(f, rows[1], &app.signal_tags, &title, app.animation_frame);

    draw_live_ticker(f, app, rows[2]);
}

// ─── Summary bar ────────────────────────────────────────────────

fn draw_summary_bar(f: &mut Frame, app: &App, area: Rect) {
    let summary = app.signal_tracker.summary();
    let dim = Style::default().fg(theme::TEXT_DIM).bg(theme::BG);
    let accent = Style::default().fg(theme::ACCENT).bg(theme::BG).add_modifier(Modifier::BOLD);
    let proto_c = Style::default().fg(Color::Rgb(60, 200, 120)).bg(theme::BG);
    let host_c = Style::default().fg(Color::Rgb(80, 200, 255)).bg(theme::BG);
    let country_c = Style::default().fg(Color::Rgb(255, 200, 80)).bg(theme::BG);
    let proc_c = Style::default().fg(Color::Rgb(180, 100, 255)).bg(theme::BG);
    let event_c = Style::default().fg(Color::Rgb(255, 100, 100)).bg(theme::BG);

    let line = Line::from(vec![
        Span::styled("  ", dim),
        Span::styled(format!("{}", summary.total), accent),
        Span::styled(" signals  ", dim),
        Span::styled("\u{2502} ", dim), // │
        Span::styled(format!("{}", summary.protocols), proto_c),
        Span::styled(" proto  ", dim),
        Span::styled("\u{2502} ", dim),
        Span::styled(format!("{}", summary.hosts), host_c),
        Span::styled(" hosts  ", dim),
        Span::styled("\u{2502} ", dim),
        Span::styled(format!("{}", summary.countries), country_c),
        Span::styled(" countries  ", dim),
        Span::styled("\u{2502} ", dim),
        Span::styled(format!("{}", summary.processes), proc_c),
        Span::styled(" proc  ", dim),
        Span::styled("\u{2502} ", dim),
        Span::styled(format!("{}", summary.events), event_c),
        Span::styled(" events", dim),
    ]);

    let bar = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(bar, area);
}

// ─── Live activity ticker ───────────────────────────────────────

fn draw_live_ticker(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Live Activity ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 20 || inner.height < 1 {
        return;
    }

    let events = app.wire_tracker.events();
    let visible = inner.height as usize;

    let mut lines: Vec<Line> = Vec::with_capacity(visible);

    for event in events.iter().take(visible) {
        let time_str = event.timestamp.format("%H:%M:%S").to_string();

        // Direction arrow
        let (arrow, arrow_color) = match &event.kind {
            WireEventKind::NewConnection => match event.direction {
                crate::data::Direction::Inbound => ("\u{2190}", theme::CYAN),  // ←
                crate::data::Direction::Outbound => ("\u{2192}", theme::GREEN), // →
                _ => ("\u{2194}", theme::TEXT_DIM),                             // ↔
            },
            WireEventKind::ConnectionClosed => ("\u{00d7}", theme::RED), // ×
            WireEventKind::StateChange { .. } => ("\u{25b8}", theme::GOLD), // ▸
        };

        // Protocol
        let proto_label = if event.service != AppProtocol::Other {
            event.service.label()
        } else {
            event.protocol.label()
        };
        let proto_color = if event.service != AppProtocol::Other {
            event.service.color()
        } else {
            theme::TEXT_DIM
        };

        // Host / IP
        let ip_str = event.remote_addr.ip().to_string();
        let host = event.hostname.as_deref().unwrap_or(&ip_str);
        let host_short: String = if host.len() > 24 {
            host[..24].to_string()
        } else {
            host.to_string()
        };

        // Country
        let cc = if event.country_code.is_empty() {
            "--"
        } else {
            &event.country_code
        };

        // Process
        let proc_name = event.process_name.as_deref().unwrap_or("?");

        // Event kind label
        let kind_label = match &event.kind {
            WireEventKind::NewConnection => "NEW",
            WireEventKind::ConnectionClosed => "FIN",
            WireEventKind::StateChange { to, .. } => to.label(),
        };

        let is_threat = event.is_threat;

        let spans = vec![
            Span::styled(
                format!("  {} ", arrow),
                Style::default().fg(arrow_color),
            ),
            Span::styled(
                format!("{:<6}", kind_label),
                Style::default().fg(if is_threat { theme::RED } else { arrow_color }),
            ),
            Span::styled(
                format!("\u{ab}{}\u{bb}", proto_label),
                Style::default().fg(proto_color),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{:<24}", host_short),
                Style::default().fg(Color::Rgb(80, 200, 255)),
            ),
            Span::raw(" "),
            Span::styled(
                format!("[{}]", cc),
                Style::default().fg(theme::TEXT_DIM),
            ),
            Span::raw(" "),
            Span::styled(
                format!("{{{}}}", proc_name),
                Style::default().fg(Color::Rgb(180, 100, 255)),
            ),
            Span::raw("  "),
            Span::styled(
                time_str,
                Style::default().fg(theme::TEXT_MUTED),
            ),
        ];

        lines.push(Line::from(spans));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Waiting for wire events…",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
