//! TerminalMap integration — renders OSM vector tile maps by writing
//! the ANSI frame directly to the terminal (same as TerminalMap standalone),
//! bypassing ratatui's widget system for the map area to avoid conversion loss.

use std::io::Write;
use std::sync::{Arc, Mutex, LazyLock};
use std::thread;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::theme;

// ─── MapDot ─────────────────────────────────────────────────────────

pub struct MapDot {
    pub lat: f64,
    pub lon: f64,
    pub color: Color,
    pub pulsing: bool,
    pub radius: u8,
    pub jitter_seed: u32,
}

// ─── Country Center Coordinates ─────────────────────────────────────

pub const COUNTRY_COORDS: &[(&str, f64, f64)] = &[
    ("US", -98.0, 38.0),   ("CA", -106.0, 56.0),  ("MX", -102.0, 23.0),
    ("BR", -51.0, -10.0),  ("AR", -64.0, -34.0),  ("CO", -72.0, 4.0),
    ("GB", -2.0, 54.0),    ("FR", 2.0, 46.0),     ("DE", 10.0, 51.0),
    ("NL", 5.0, 52.0),     ("ES", -3.0, 40.0),    ("IT", 12.0, 42.0),
    ("SE", 15.0, 62.0),    ("NO", 10.0, 62.0),    ("FI", 26.0, 64.0),
    ("PL", 20.0, 52.0),    ("UA", 32.0, 49.0),    ("RO", 25.0, 46.0),
    ("RU", 50.0, 55.0),    ("TR", 35.0, 39.0),    ("SA", 45.0, 24.0),
    ("IR", 53.0, 32.0),    ("IN", 79.0, 21.0),    ("PK", 69.0, 30.0),
    ("BD", 90.0, 24.0),    ("CN", 105.0, 35.0),   ("JP", 138.0, 36.0),
    ("KR", 128.0, 36.0),   ("TW", 121.0, 24.0),   ("VN", 106.0, 16.0),
    ("TH", 101.0, 15.0),   ("SG", 104.0, 1.3),    ("ID", 118.0, -2.0),
    ("MY", 102.0, 4.0),    ("PH", 122.0, 13.0),   ("AU", 134.0, -25.0),
    ("NZ", 172.0, -41.0),  ("ZA", 25.0, -29.0),   ("NG", 8.0, 10.0),
    ("EG", 30.0, 27.0),    ("KE", 38.0, -1.0),    ("IL", 35.0, 31.0),
    ("AE", 54.0, 24.0),    ("CL", -71.0, -33.0),  ("PE", -76.0, -10.0),
];

pub fn country_center(iso2: &str) -> Option<(f64, f64)> {
    COUNTRY_COORDS
        .iter()
        .find(|(code, _, _)| *code == iso2)
        .map(|(_, lon, lat)| (*lon, *lat))
}

// ─── Cached ANSI Frame ──────────────────────────────────────────────

struct CachedFrame {
    cols: u16,
    rows: u16,
    ansi: String,
    footer: String,
}

static MAP_FRAME: LazyLock<Arc<Mutex<Option<CachedFrame>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

static MAP_TX: LazyLock<Arc<Mutex<Option<std::sync::mpsc::Sender<MapCmd>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

static MAP_STARTED: LazyLock<Arc<std::sync::atomic::AtomicBool>> =
    LazyLock::new(|| Arc::new(std::sync::atomic::AtomicBool::new(false)));

enum MapCmd {
    Resize(u16, u16),
    UpdateMarkers(Vec<(f64, f64, u8, bool)>), // lat, lon, color, pulsing
}

// ─── Background Renderer ────────────────────────────────────────────

fn ensure_started() {
    if MAP_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }

    let frame_out = Arc::clone(&*MAP_FRAME);
    let (tx, rx) = std::sync::mpsc::channel::<MapCmd>();
    *MAP_TX.lock().unwrap() = Some(tx);

    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async move {
            let config = terminalmap::config::MapConfig {
                initial_lat: 20.0,
                initial_lon: 0.0,
                initial_zoom: None,
                show_labels: true,
                persist_downloaded_tiles: true,
                ..terminalmap::config::MapConfig::default()
            };

            let mut map = match terminalmap::widget::MapState::new(config).await {
                Ok(m) => m,
                Err(_) => return,
            };

            let mut cur_cols: u16 = 120;
            let mut cur_rows: u16 = 30;
            map.set_size(cur_cols as usize * 2, cur_rows as usize * 4);
            map.fit_world();

            // Initial render
            do_render(&map, cur_cols, cur_rows, &frame_out).await;

            loop {
                let mut needs_render = false;

                while let Ok(cmd) = rx.try_recv() {
                    match cmd {
                        MapCmd::Resize(c, r) => {
                            if c != cur_cols || r != cur_rows {
                                cur_cols = c;
                                cur_rows = r;
                                map.set_size(c as usize * 2, r as usize * 4);
                                map.fit_world();
                                needs_render = true;
                            }
                        }
                        MapCmd::UpdateMarkers(markers) => {
                            map.clear_markers();
                            for (lat, lon, color, pulsing) in &markers {
                                let anim = if *pulsing {
                                    terminalmap::marker::MarkerAnimation::Pulse
                                } else {
                                    terminalmap::marker::MarkerAnimation::None
                                };
                                map.add_marker(
                                    terminalmap::marker::MapMarker::dot(*lat, *lon, *color)
                                        .with_animation(anim),
                                );
                            }
                            needs_render = true;
                        }
                    }
                }

                // Advance tick for animations
                map.advance_tick();
                let camera_moved = map.update_camera();
                if map.needs_animation_redraw() || camera_moved {
                    needs_render = true;
                }

                if needs_render {
                    do_render(&map, cur_cols, cur_rows, &frame_out).await;
                }

                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
    });
}

async fn do_render(
    map: &terminalmap::widget::MapState,
    cols: u16,
    rows: u16,
    out: &Arc<Mutex<Option<CachedFrame>>>,
) {
    if let Ok(ansi) = map.render().await {
        let footer = map.footer();
        if let Ok(mut guard) = out.lock() {
            *guard = Some(CachedFrame { cols, rows, ansi, footer });
        }
    }
}

fn send_cmd(cmd: MapCmd) {
    if let Ok(guard) = MAP_TX.lock() {
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(cmd);
        }
    }
}

// ─── Public Draw Function ───────────────────────────────────────────

/// Draw the TerminalMap. Writes the ANSI frame directly to stdout
/// at the correct position (same technique as TerminalMap standalone),
/// then renders the border/title/footer via ratatui.
pub fn draw_terminal_map(
    f: &mut Frame,
    area: Rect,
    dots: &[MapDot],
    _animation_frame: u8,
    title: &str,
) {
    ensure_started();

    // Draw the border via ratatui
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Line::from(Span::styled(
            format!(" {} ", title),
            Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 4 || inner.height < 2 {
        return;
    }

    // Send resize + markers to background thread
    // Reserve 1 row at bottom for the footer/status
    let map_rows = inner.height.saturating_sub(1);
    send_cmd(MapCmd::Resize(inner.width, map_rows));

    if !dots.is_empty() {
        let markers: Vec<(f64, f64, u8, bool)> = dots
            .iter()
            .take(150)
            .map(|d| {
                let color = if d.pulsing { 196u8 } else { 48u8 };
                (d.lat, d.lon, color, d.pulsing)
            })
            .collect();
        send_cmd(MapCmd::UpdateMarkers(markers));
    }

    // Get cached frame
    let cached = MAP_FRAME.lock().ok().and_then(|guard| {
        guard.as_ref().map(|cf| (cf.ansi.clone(), cf.footer.clone()))
    });

    match cached {
        Some((ansi, footer)) => {
            // Write the ANSI map frame directly to stdout at the inner area position.
            // This bypasses ratatui for the map content — same as TerminalMap standalone.
            let mut stdout = std::io::stdout();
            let origin_x = inner.x;
            let origin_y = inner.y;

            // Split ANSI frame into lines and write each at the correct row
            for (row_idx, line) in ansi.split('\n').enumerate() {
                let line = line.trim_end_matches('\r');
                if row_idx >= map_rows as usize {
                    break;
                }
                let _ = crossterm::execute!(
                    stdout,
                    crossterm::cursor::MoveTo(origin_x, origin_y + row_idx as u16)
                );
                let _ = write!(stdout, "{}", line);
            }

            // Footer line at the bottom of the inner area
            let footer_y = origin_y + map_rows;
            let _ = crossterm::execute!(
                stdout,
                crossterm::cursor::MoveTo(origin_x, footer_y)
            );
            // Dim footer
            let _ = write!(stdout, "\x1B[38;5;243m{}\x1B[0m", &footer[..footer.len().min(inner.width as usize)]);
            let _ = stdout.flush();
        }
        None => {
            // Loading state via ratatui
            let loading = Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  \u{231B} Loading TerminalMap...",
                    Style::default().fg(theme::TEXT_DIM),
                )),
                Line::from(Span::styled(
                    "  Initializing OSM vector tiles",
                    Style::default().fg(theme::TEXT_MUTED),
                )),
            ]).style(Style::default().bg(theme::BG));
            f.render_widget(loading, inner);
        }
    }
}
