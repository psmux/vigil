use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, View};

/// Master keyboard dispatcher.
pub fn handle_input(app: &mut App, key: KeyEvent) {
    match key.code {
        // Quit
        KeyCode::Char('q') => {
            app.should_quit = true;
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }

        // Jump to view by number
        KeyCode::Char('1') => app.view = View::CommandCenter,
        KeyCode::Char('2') => app.view = View::AttackRadar,
        KeyCode::Char('3') => app.view = View::Alerts,
        KeyCode::Char('4') => app.view = View::Doors,
        KeyCode::Char('5') => app.view = View::NetworkPulse,
        KeyCode::Char('6') => app.view = View::Geography,
        KeyCode::Char('7') => app.view = View::Topology,
        KeyCode::Char('8') => app.view = View::SystemVitals,
        KeyCode::Char('9') => app.view = View::Outbound,
        KeyCode::Char('0') => app.view = View::Wire,

        // Tab cycling
        KeyCode::Tab => {
            app.view = app.view.next();
            app.scroll_offset = 0;
        }
        KeyCode::BackTab => {
            app.view = app.view.prev();
            app.scroll_offset = 0;
        }

        // Scrolling / selection — Wire view uses its own selection cursor
        KeyCode::Char('j') | KeyCode::Down => {
            if app.view == View::Wire {
                let total = app.wire_tracker.events().len();
                if total > 0 {
                    app.wire_selected = (app.wire_selected + 1).min(total - 1);
                    // If user scrolls down past end, re-enable auto-scroll
                    if app.wire_selected == 0 {
                        app.wire_auto_scroll = true;
                    } else {
                        app.wire_auto_scroll = false;
                    }
                }
            } else {
                app.scroll_offset = app.scroll_offset.saturating_add(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if app.view == View::Wire {
                if app.wire_selected > 0 {
                    app.wire_selected -= 1;
                }
                app.wire_auto_scroll = false;
            } else {
                app.scroll_offset = app.scroll_offset.saturating_sub(1);
            }
        }

        // Wire: G = jump to latest / resume auto-scroll
        KeyCode::Char('G') | KeyCode::Char('g') if app.view == View::Wire => {
            app.wire_selected = 0;
            app.wire_auto_scroll = true;
        }

        // Wire: Enter = select (no-op, selection already works via j/k)
        KeyCode::Enter if app.view == View::Wire => {}

        // Refresh (no-op — refresh is automatic)
        KeyCode::Char('r') => {}

        // Pause / unpause data collection
        KeyCode::Char('z') => {
            app.paused = !app.paused;
        }

        // Help overlay toggle
        KeyCode::Char('?') => {
            app.show_help = !app.show_help;
        }

        // Mark all alerts as read
        KeyCode::Char('a') => {
            app.mark_alerts_read();
        }

        _ => {}
    }
}
