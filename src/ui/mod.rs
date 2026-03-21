pub mod header;
pub mod tab_bar;
pub mod status_bar;
pub mod command_center;
pub mod attack_radar;
pub mod alerts_view;
pub mod doors;
pub mod network_pulse;
pub mod geography;
pub mod topology;
pub mod system_vitals;
pub mod outbound;
pub mod wire;

use ratatui::layout::{Constraint, Layout, Direction};
use ratatui::Frame;

use crate::app::{App, View};

/// Master draw function — lays out the four horizontal strips and dispatches
/// the main content area to the active view's renderer.
pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // header
            Constraint::Length(1),  // tab bar
            Constraint::Min(10),   // main content
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    header::draw(f, app, chunks[0]);
    tab_bar::draw(f, app, chunks[1]);

    match app.view {
        View::CommandCenter => command_center::draw(f, app, chunks[2]),
        View::AttackRadar  => attack_radar::draw(f, app, chunks[2]),
        View::Alerts       => alerts_view::draw(f, app, chunks[2]),
        View::Doors        => doors::draw(f, app, chunks[2]),
        View::NetworkPulse => network_pulse::draw(f, app, chunks[2]),
        View::Geography    => geography::draw(f, app, chunks[2]),
        View::Topology     => topology::draw(f, app, chunks[2]),
        View::SystemVitals => system_vitals::draw(f, app, chunks[2]),
        View::Outbound     => outbound::draw(f, app, chunks[2]),
        View::Wire         => wire::draw(f, app, chunks[2]),
    }

    status_bar::draw(f, app, chunks[3]);

    if app.show_help {
        draw_help_overlay(f, area);
    }
}

fn draw_help_overlay(f: &mut Frame, area: ratatui::layout::Rect) {
    use ratatui::widgets::{Block, Borders, BorderType, Clear, Paragraph};
    use ratatui::style::{Color, Style, Modifier};
    use ratatui::text::{Line, Span};
    let w = 44u16.min(area.width.saturating_sub(4));
    let h = 14u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let popup = ratatui::layout::Rect::new(x, y, w, h);
    f.render_widget(Clear, popup);
    let gold = Style::default().fg(Color::Rgb(255,200,80)).add_modifier(Modifier::BOLD);
    let text = Style::default().fg(Color::Rgb(180,190,210));
    let dim = Style::default().fg(Color::Rgb(80,90,110));
    let lines = vec![
        Line::from(vec![Span::styled("  1-0   ", gold), Span::styled("Switch views (0=Wire)", text)]),
        Line::from(vec![Span::styled("  Tab   ", gold), Span::styled("Next view", text)]),
        Line::from(vec![Span::styled("  j/k   ", gold), Span::styled("Scroll up/down", text)]),
        Line::from(vec![Span::styled("  z     ", gold), Span::styled("Pause/resume", text)]),
        Line::from(vec![Span::styled("  a     ", gold), Span::styled("Mark alerts read", text)]),
        Line::from(vec![Span::styled("  ?     ", gold), Span::styled("Toggle help", text)]),
        Line::from(vec![Span::styled("  q     ", gold), Span::styled("Quit", text)]),
        Line::from(""),
        Line::from(Span::styled("  Press ? or Esc to close", dim)),
    ];
    let block = Block::default()
        .title(Span::styled(" VIGIL Help ", Style::default().fg(Color::Rgb(160,180,220)).add_modifier(Modifier::BOLD)))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Rgb(60,140,255)))
        .style(Style::default().bg(Color::Rgb(12,18,35)));
    f.render_widget(Paragraph::new(lines).block(block), popup);
}
