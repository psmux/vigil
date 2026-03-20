mod app;
mod config;
mod data;
mod format;
mod input;
mod score;
mod theme;
mod ui;
mod widgets;

use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use app::App;
use config::VigilConfig;
use data::DataUpdate;

fn main() -> anyhow::Result<()> {
    let config = config::load();

    // Install panic hook to restore terminal before printing panic info
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = restore_terminal();
        original_hook(panic_info);
    }));

    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state and data channel
    let mut app = App::new();
    let (tx, rx) = mpsc::channel::<DataUpdate>();

    // Spawn placeholder background threads
    // Each thread will eventually collect real data; for now they just sleep.
    spawn_placeholder_threads(tx, &config);

    // Main event loop
    let tick_rate = Duration::from_millis(config.tick_rate_ms);
    let mut last_tick = Instant::now();

    loop {
        // Draw
        terminal.draw(|f| ui::draw(f, &app))?;

        // Poll for events with a 50ms timeout
        let timeout = Duration::from_millis(50);
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                input::handle_input(&mut app, key);
            }
        }

        // Check if we should quit
        if app.should_quit {
            break;
        }

        // Tick processing at the configured interval
        if last_tick.elapsed() >= tick_rate {
            if !app.paused {
                app.apply_updates(&rx);
            }
            app.tick();
            last_tick = Instant::now();
        }
    }

    // Teardown
    restore_terminal()?;
    Ok(())
}

/// Restore the terminal to its original state.
fn restore_terminal() -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(
        io::stdout(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    Ok(())
}

/// Spawn placeholder background data-collection threads.
fn spawn_placeholder_threads(_tx: mpsc::Sender<DataUpdate>, _config: &VigilConfig) {
    // Connection collector (placeholder)
    {
        let _tx = _tx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(2));
            // TODO: parse /proc/net/tcp and send DataUpdate::Connections
        });
    }

    // Bandwidth monitor (placeholder)
    {
        let _tx = _tx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            // TODO: read /proc/net/dev deltas and send DataUpdate::Bandwidth
        });
    }

    // Attack log watcher (placeholder)
    {
        let _tx = _tx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            // TODO: tail auth.log and send DataUpdate::Attack
        });
    }

    // Firewall rules poller (placeholder)
    {
        let _tx = _tx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(30));
            // TODO: parse ufw/iptables and send DataUpdate::FirewallRules
        });
    }

    // Fail2ban / banned IPs poller (placeholder)
    {
        #[allow(clippy::redundant_clone)]
        let _tx = _tx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(10));
            // TODO: query fail2ban-client and send DataUpdate::BannedIps
        });
    }
}
