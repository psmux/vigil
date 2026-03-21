use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};

use crate::app::{App, View};
use crate::widgets::terminal_map::{self, MapCmd};

/// Returns true if the current view has an interactive map.
fn view_has_map(view: View) -> bool {
    matches!(view, View::CommandCenter | View::AttackRadar | View::Geography | View::Outbound)
}

/// Master keyboard dispatcher — three layers:
/// 1. Global keys (quit, view switch, tab, help) — always work
/// 2. Map keys (zoom, pan, labels, tours) — only on map views
/// 3. View keys (scroll, wire select, alerts) — fallback
pub fn handle_input(app: &mut App, key: KeyEvent) {
    // ── Layer 1: Global keys ────────────────────────────────────
    match key.code {
        KeyCode::Char('q') => { app.should_quit = true; return; }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true; return;
        }

        // View switching — always works
        KeyCode::Char('1') => { app.view = View::CommandCenter; return; }
        KeyCode::Char('2') => { app.view = View::AttackRadar; return; }
        KeyCode::Char('3') => { app.view = View::Alerts; return; }
        KeyCode::Char('4') => { app.view = View::Doors; return; }
        KeyCode::Char('5') => { app.view = View::NetworkPulse; return; }
        KeyCode::Char('6') => { app.view = View::Geography; return; }
        KeyCode::Char('7') => { app.view = View::Topology; return; }
        KeyCode::Char('8') => { app.view = View::SystemVitals; return; }
        KeyCode::Char('9') => { app.view = View::Outbound; return; }
        KeyCode::Char('0') => { app.view = View::Wire; return; }

        KeyCode::Tab => { app.view = app.view.next(); app.scroll_offset = 0; return; }
        KeyCode::BackTab => { app.view = app.view.prev(); app.scroll_offset = 0; return; }

        KeyCode::Char('?') => { app.show_help = !app.show_help; return; }
        KeyCode::Esc => { if app.show_help { app.show_help = false; return; } }

        // Pause — 'p' globally (not 'z', which is zoom-out on map views)
        KeyCode::Char('p') => { app.paused = !app.paused; return; }

        _ => {}
    }

    // ── Layer 2: Map keys (when on a map view) ──────────────────
    if view_has_map(app.view) {
        if handle_map_key(key) { return; }
    }

    // ── Layer 3: View-specific keys ─────────────────────────────
    handle_view_key(app, key);
}

/// Route map keys to the background thread. Returns true if consumed.
fn handle_map_key(key: KeyEvent) -> bool {
    let cmd = match key.code {
        KeyCode::Char('a') | KeyCode::Char('+') | KeyCode::Char('=') => MapCmd::ZoomIn,
        KeyCode::Char('z') | KeyCode::Char('-') => MapCmd::ZoomOut,
        KeyCode::Left  | KeyCode::Char('h') => MapCmd::PanLeft,
        KeyCode::Right | KeyCode::Char('l') => MapCmd::PanRight,
        KeyCode::Up    | KeyCode::Char('k') => MapCmd::PanUp,
        KeyCode::Down  | KeyCode::Char('j') => MapCmd::PanDown,
        KeyCode::Char('c') => MapCmd::ToggleBraille,
        KeyCode::Char('n') => MapCmd::ToggleLabels,
        KeyCode::Char('w') => MapCmd::FitWorld,
        KeyCode::Char('g') => MapCmd::ToggleSmartTour,
        KeyCode::Char('t') => MapCmd::ToggleMarkerTour,
        _ => return false,
    };
    terminal_map::send_map_cmd(cmd);
    true
}

/// Handle non-map view keys (Wire, scroll, etc.)
fn handle_view_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => {
            if app.view == View::Wire {
                let total = app.wire_tracker.events().len();
                if total > 0 {
                    app.wire_selected = (app.wire_selected + 1).min(total - 1);
                    app.wire_auto_scroll = app.wire_selected == 0;
                }
            } else {
                app.scroll_offset = app.scroll_offset.saturating_add(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if app.view == View::Wire {
                if app.wire_selected > 0 { app.wire_selected -= 1; }
                app.wire_auto_scroll = false;
            } else {
                app.scroll_offset = app.scroll_offset.saturating_sub(1);
            }
        }
        KeyCode::Char('G') | KeyCode::Char('g') if app.view == View::Wire => {
            app.wire_selected = 0;
            app.wire_auto_scroll = true;
        }
        KeyCode::Enter if app.view == View::Wire => {
            app.wire_detail_expanded = !app.wire_detail_expanded;
        }
        KeyCode::Char('r') => {} // refresh automatic
        KeyCode::Char('a') => { app.mark_alerts_read(); }
        _ => {}
    }
}

/// Handle mouse events — scroll zooms on map views.
pub fn handle_mouse(app: &App, mouse: MouseEvent) {
    if view_has_map(app.view) {
        match mouse.kind {
            MouseEventKind::ScrollUp => terminal_map::send_map_cmd(MapCmd::ZoomIn),
            MouseEventKind::ScrollDown => terminal_map::send_map_cmd(MapCmd::ZoomOut),
            _ => {}
        }
    }
}
