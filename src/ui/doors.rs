use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::PortRisk;
use crate::theme;
use crate::widgets::donut::{self, DonutSegment};
use crate::widgets::gauge;
use crate::widgets::port_flow;

/// Draw the Doors view (View 3) — port exposure and firewall coverage.
///
/// Layout:
/// ```text
/// top_row (40%):    [ donut (40%) | firewall_coverage (60%) ]
/// port_map:         one port_flow widget per listening port (scrollable)
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40), // top row
            Constraint::Min(4),          // port map
        ])
        .split(area);

    // ── Top row: donut + firewall coverage ───────────────────────
    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // donut
            Constraint::Percentage(60), // firewall coverage
        ])
        .split(chunks[0]);

    draw_port_donut(f, app, top_cols[0]);
    draw_firewall_coverage(f, app, top_cols[1]);

    // ── Port map ─────────────────────────────────────────────────
    draw_port_map(f, app, chunks[1]);
}

fn draw_port_donut(f: &mut Frame, app: &App, area: Rect) {
    let safe = app.ports.iter().filter(|p| p.risk == PortRisk::Safe).count() as u32;
    let exposed = app.ports.iter().filter(|p| p.risk == PortRisk::Exposed).count() as u32;
    let critical = app.ports.iter().filter(|p| p.risk == PortRisk::Critical).count() as u32;

    let segments = vec![
        DonutSegment { label: "Safe".into(), value: safe, color: theme::SAFE },
        DonutSegment { label: "Exposed".into(), value: exposed, color: theme::WARN },
        DonutSegment { label: "Critical".into(), value: critical, color: theme::DANGER },
    ];

    let total = app.ports.len();
    let center_text = format!("{} ports", total);

    donut::draw_donut(f, area, "Port Exposure", &segments, &center_text);
}

fn draw_firewall_coverage(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Span::styled(
            " Firewall Coverage ",
            Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 10 || inner.height < 2 {
        return;
    }

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // gauge
            Constraint::Min(1),    // rule checklist
        ])
        .split(inner);

    // Coverage gauge — percentage of ports that are covered by at least one firewall rule
    let total_ports = app.ports.len().max(1);
    let covered = if app.firewall_active {
        // Count ports that have a matching allow/deny rule
        app.ports
            .iter()
            .filter(|p| {
                app.firewall_rules.iter().any(|r| {
                    r.port.map_or(false, |rp| rp == p.port)
                }) || app.firewall_default_deny
            })
            .count()
    } else {
        0
    };
    let coverage_pct = (covered as f64 / total_ports as f64 * 100.0).round() as u8;

    let coverage_color = match coverage_pct {
        80..=100 => theme::SAFE,
        50..=79 => theme::WARN,
        _ => theme::DANGER,
    };

    gauge::draw_bar_gauge(
        f,
        inner_chunks[0],
        "Coverage",
        covered as f64,
        total_ports as f64,
        coverage_color,
    );

    // Rule checklist
    let mut lines: Vec<Line> = Vec::new();

    // Overall status line
    let fw_status = if app.firewall_active { "ACTIVE" } else { "INACTIVE" };
    let fw_color = if app.firewall_active { theme::SAFE } else { theme::DANGER };
    lines.push(Line::from(vec![
        Span::styled(" Firewall: ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled(
            fw_status,
            Style::default().fg(fw_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", Style::default()),
        Span::styled("Default deny: ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled(
            if app.firewall_default_deny { "\u{2713}" } else { "\u{25CB}" },
            Style::default().fg(if app.firewall_default_deny { theme::SAFE } else { theme::WARN }),
        ),
    ]));

    // Show firewall rules as a checklist
    let visible_rules = (inner_chunks[1].height as usize).saturating_sub(1);
    for rule in app.firewall_rules.iter().take(visible_rules) {
        let action_icon = match rule.action {
            crate::data::FirewallAction::Allow => ("\u{2713}", theme::SAFE),    // checkmark
            crate::data::FirewallAction::Deny => ("\u{2717}", theme::DANGER),   // cross
            crate::data::FirewallAction::Reject => ("\u{25CB}", theme::WARN),   // circle
        };

        let port_str = rule.port.map(|p| format!(":{}", p)).unwrap_or_else(|| "*".into());
        let dir_str = match rule.direction {
            crate::data::FirewallDirection::In => "IN ",
            crate::data::FirewallDirection::Out => "OUT",
            crate::data::FirewallDirection::Both => "ALL",
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", action_icon.0),
                Style::default().fg(action_icon.1),
            ),
            Span::styled(
                format!("{} {} ", dir_str, port_str),
                Style::default().fg(theme::TEXT),
            ),
            Span::styled(
                rule.comment.clone(),
                Style::default().fg(theme::TEXT_DIM),
            ),
            Span::styled(
                format!("  ({} hits)", rule.hits),
                Style::default().fg(theme::TEXT_MUTED),
            ),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " No firewall rules detected",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner_chunks[1]);
}

fn draw_port_map(f: &mut Frame, app: &App, area: Rect) {
    if app.ports.is_empty() {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
            .title(Span::styled(
                " Port Map ",
                Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(theme::BG));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let msg = Paragraph::new(Line::from(Span::styled(
            "No listening ports detected",
            Style::default().fg(theme::TEXT_DIM),
        )))
        .style(Style::default().bg(theme::BG));
        f.render_widget(msg, inner);
        return;
    }

    // Each port_flow needs 3 rows (1 border top + 1 content + 1 border bottom)
    let row_height = 3u16;
    let visible_count = (area.height / row_height).max(1) as usize;
    let skip = app.scroll_offset.min(app.ports.len().saturating_sub(visible_count));

    let constraints: Vec<Constraint> = app
        .ports
        .iter()
        .skip(skip)
        .take(visible_count)
        .map(|_| Constraint::Length(row_height))
        .collect();

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    for (i, port) in app.ports.iter().skip(skip).take(visible_count).enumerate() {
        if i < rows.len() {
            port_flow::draw_port_flow(f, rows[i], port, port.risk, port.auth);
        }
    }
}
