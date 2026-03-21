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
use std::net::IpAddr;
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

/// Global sender for DNS resolution requests — populated by spawn_data_threads().
pub(crate) static DNS_SENDER: std::sync::LazyLock<Mutex<Option<mpsc::Sender<IpAddr>>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

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

    // Spawn real background data-collection threads
    spawn_data_threads(tx, &config);

    // Main event loop
    let tick_rate = Duration::from_millis(config.tick_rate_ms);
    let mut last_tick = Instant::now();

    loop {
        // Draw
        terminal.draw(|f| ui::draw(f, &app))?;

        // Flush TerminalMap ANSI writes AFTER ratatui's buffer flush
        widgets::terminal_map::flush_pending_maps();

        // Poll for events with a 50ms timeout
        let timeout = Duration::from_millis(50);
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => input::handle_input(&mut app, key),
                Event::Mouse(mouse) => input::handle_mouse(&app, mouse),
                Event::Resize(_, _) => {} // ratatui + map thread handle this
                _ => {}
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

/// Spawn real background data-collection threads.
fn spawn_data_threads(tx: mpsc::Sender<DataUpdate>, _config: &VigilConfig) {
    // 1. Connection collector — every 2s parses /proc/net/tcp* and /proc/net/udp*
    {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            let conns = data::connections::collect_connections();
            let _ = tx.send(DataUpdate::Connections(conns));
            std::thread::sleep(Duration::from_secs(2));
        });
    }

    // 2. Bandwidth monitor — every 1s samples /proc/net/dev for rx/tx bps
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut tracker = data::bandwidth::BandwidthTracker::new();
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let (rx_bps, tx_bps) = tracker.sample();
                let _ = tx.send(DataUpdate::Bandwidth { rx_bps, tx_bps });
            }
        });
    }

    // 3. Attack log watcher — tails auth.log / journalctl for SSH brute-force events
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            data::attacks::attack_monitor_thread(tx);
        });
    }

    // 4. Firewall rules poller — every 30s queries ufw/iptables
    {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            let (rules, default_deny, _active) = data::firewall::collect_firewall_info();
            let _ = tx.send(DataUpdate::FirewallRules(rules, default_deny));
            std::thread::sleep(Duration::from_secs(30));
        });
    }

    // 5. Fail2ban monitor — polls fail2ban-client for banned IPs
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            data::fail2ban::fail2ban_monitor_thread(tx);
        });
    }

    // 6. DNS resolver — reverse-lookups for remote IPs via dedicated channel
    {
        let tx = tx.clone();
        let (dns_tx, dns_rx) = mpsc::channel::<std::net::IpAddr>();
        // Store the dns sender in a global so tick() can send IPs to resolve
        DNS_SENDER.lock().unwrap().replace(dns_tx);
        std::thread::spawn(move || {
            use std::collections::HashSet;
            use std::net::IpAddr;
            let mut resolved: HashSet<IpAddr> = HashSet::new();
            loop {
                // Drain all pending IPs from the channel
                while let Ok(ip) = dns_rx.try_recv() {
                    if !resolved.contains(&ip) {
                        if let Ok(hostname) = dns_lookup::lookup_addr(&ip) {
                            if hostname != ip.to_string() {
                                let _ = tx.send(DataUpdate::DnsResolved(ip, hostname));
                            }
                        }
                        resolved.insert(ip);
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
    }

    // 7. Topology/discovery — services, interfaces, gateway, DNS servers, neighbors every 30s
    {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            let gateway = data::discovery::get_gateway();
            let dns_servers = data::discovery::get_dns_servers();
            let neighbors = data::discovery::discover_neighbors();
            let services = data::system::collect_services();
            let interfaces = data::system::collect_interfaces();
            let _ = tx.send(DataUpdate::Topology {
                gateway,
                dns_servers,
                neighbors,
                services,
                interfaces,
            });
            std::thread::sleep(Duration::from_secs(30));
        });
    }
}
