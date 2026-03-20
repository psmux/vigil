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
        KeyCode::Char('3') => app.view = View::Doors,
        KeyCode::Char('4') => app.view = View::NetworkPulse,
        KeyCode::Char('5') => app.view = View::Geography,
        KeyCode::Char('6') => app.view = View::SystemVitals,

        // Tab cycling
        KeyCode::Tab => {
            app.view = app.view.next();
            app.scroll_offset = 0;
        }
        KeyCode::BackTab => {
            app.view = app.view.prev();
            app.scroll_offset = 0;
        }

        // Scrolling
        KeyCode::Char('j') | KeyCode::Down => {
            app.scroll_offset = app.scroll_offset.saturating_add(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.scroll_offset = app.scroll_offset.saturating_sub(1);
        }

        // Refresh (no-op — refresh is automatic)
        KeyCode::Char('r') => {}

        // Pause / unpause data collection
        KeyCode::Char('z') => {
            app.paused = !app.paused;
        }

        // Help overlay (TODO)
        KeyCode::Char('?') => {}

        _ => {}
    }
}
