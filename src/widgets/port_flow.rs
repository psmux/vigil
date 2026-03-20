use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::data::{AuthMethod, ListeningPort, PortRisk};
use crate::theme;

/// Draw a single-line port flow diagram.
///
/// ```text
/// :PORT ── process ── bind_addr ── AUTH ── N conns ── [RISK_BADGE]
/// ```
///
/// Each segment is colored by its meaning:
/// - Port number in accent blue
/// - Process name in standard text
/// - Bind address in green/yellow/red depending on exposure
/// - Auth method colored by strength
/// - Connection count in text
/// - Risk badge with background color
pub fn draw_port_flow(
    f: &mut Frame,
    area: Rect,
    port: &ListeningPort,
    risk: PortRisk,
    auth: AuthMethod,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 30 || inner.height == 0 {
        return;
    }

    let sep = Span::styled(
        " \u{2500}\u{2500} ",
        Style::default().fg(theme::SEPARATOR),
    ); // ──

    // Port number
    let port_span = Span::styled(
        format!(":{}", port.port),
        Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
    );

    // Process name
    let process_span = Span::styled(
        port.process_name.clone(),
        Style::default().fg(theme::TEXT),
    );

    // Bind address — color by exposure
    let bind_str = port.bind_addr.to_string();
    let bind_color = if bind_str == "127.0.0.1" || bind_str == "::1" {
        theme::SAFE // loopback = safe
    } else if bind_str == "0.0.0.0" || bind_str == "::" {
        theme::DANGER // all interfaces = exposed
    } else {
        theme::WARN // specific interface
    };
    let bind_span = Span::styled(bind_str, Style::default().fg(bind_color));

    // Auth method
    let auth_color = match auth {
        AuthMethod::KeyAuth | AuthMethod::JwtAuth => theme::SAFE,
        AuthMethod::PasswordAuth | AuthMethod::TokenAuth => theme::WARN,
        AuthMethod::NoAuth => theme::DANGER,
        AuthMethod::Unknown => theme::TEXT_DIM,
    };
    let auth_span = Span::styled(
        auth.label().to_string(),
        Style::default().fg(auth_color).add_modifier(Modifier::BOLD),
    );

    // Connection count
    let conn_span = Span::styled(
        format!("{} conns", port.conn_count),
        Style::default().fg(theme::TEXT),
    );

    // Risk badge with background color
    let (risk_fg, risk_bg) = match risk {
        PortRisk::Safe => (theme::BG, theme::SAFE),
        PortRisk::Shielded => (theme::BG, theme::SHIELDED),
        PortRisk::Exposed => (theme::BG, theme::WARN),
        PortRisk::Critical => (Color::Rgb(255, 255, 255), theme::DANGER),
    };

    let risk_span = Span::styled(
        format!(" {} ", risk.label()),
        Style::default()
            .fg(risk_fg)
            .bg(risk_bg)
            .add_modifier(Modifier::BOLD),
    );

    let line = Line::from(vec![
        port_span,
        sep.clone(),
        process_span,
        sep.clone(),
        bind_span,
        sep.clone(),
        auth_span,
        sep.clone(),
        conn_span,
        sep,
        risk_span,
    ]);

    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
