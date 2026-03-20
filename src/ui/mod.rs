pub mod header;
pub mod tab_bar;
pub mod status_bar;
pub mod command_center;
pub mod attack_radar;
pub mod doors;
pub mod network_pulse;
pub mod geography;
pub mod system_vitals;

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
        View::Doors        => doors::draw(f, app, chunks[2]),
        View::NetworkPulse => network_pulse::draw(f, app, chunks[2]),
        View::Geography    => geography::draw(f, app, chunks[2]),
        View::SystemVitals => system_vitals::draw(f, app, chunks[2]),
    }

    status_bar::draw(f, app, chunks[3]);
}
