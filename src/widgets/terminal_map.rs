//! TerminalMap integration — interactive OSM vector tile map with zoom, pan,
//! labels, tours, mouse scroll. Renders ANSI directly after ratatui flush.

use std::io::Write;
use std::sync::{Arc, Mutex, LazyLock};
use std::thread;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::theme;
use crate::widgets::braille_map::MapDot;

// ─── Map Commands (sent from input.rs) ──────────────────────────────

pub enum MapCmd {
    Resize(u16, u16),
    UpdateMarkers(Vec<(f64, f64, u8, bool)>),
    ZoomIn,
    ZoomOut,
    PanLeft,
    PanRight,
    PanUp,
    PanDown,
    ToggleBraille,
    ToggleLabels,
    FitWorld,
    /// 'g' key: if markers exist, tours markers; otherwise globe tour
    ToggleSmartTour,
    ToggleGlobeTour,
    ToggleMarkerTour,
}

/// Send a command to the map background thread. Called from input.rs.
pub fn send_map_cmd(cmd: MapCmd) {
    if let Ok(guard) = MAP_TX.lock() {
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(cmd);
        }
    }
}

// ─── Pending ANSI Writes ────────────────────────────────────────────

struct PendingMapWrite {
    origin_x: u16,
    origin_y: u16,
    map_rows: u16,
    map_cols: u16,
    ansi: String,
    help_line: String,
    status_line: String,
}

static PENDING_WRITES: LazyLock<Mutex<Vec<PendingMapWrite>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Call AFTER terminal.draw(). If `render` is true, writes ANSI to stdout.
/// If false, just drains the queue (prevents stale writes on view switch).
pub fn flush_pending_maps(render: bool) {
    let writes = {
        let mut guard = match PENDING_WRITES.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        std::mem::take(&mut *guard)
    };
    if writes.is_empty() || !render { return; }

    let mut stdout = std::io::stdout();
    for pw in &writes {
        let max_col = pw.map_cols as usize;

        // Write each line of the ANSI map frame — strictly clipped to widget width
        for (i, line) in pw.ansi.split('\n').enumerate() {
            let line = line.trim_end_matches('\r');
            if i >= pw.map_rows as usize { break; }
            let _ = crossterm::execute!(stdout, crossterm::cursor::MoveTo(pw.origin_x, pw.origin_y + i as u16));
            // Truncate to widget width to prevent overflow into adjacent panels
            let clipped = strip_ansi_truncate(line, max_col);
            let _ = write!(stdout, "{}\x1B[0m", clipped);
        }

        // Status bar disabled — can re-enable later if needed
    }
    let _ = stdout.flush();
}

/// Truncate an ANSI string to approximately max_visible visible characters.
/// Passes through escape sequences without counting them toward the limit.
fn strip_ansi_truncate(s: &str, max_visible: usize) -> String {
    let mut result = String::with_capacity(s.len());
    let mut visible = 0usize;
    let mut in_escape = false;

    for ch in s.chars() {
        if in_escape {
            result.push(ch);
            if ch.is_ascii_alphabetic() { in_escape = false; }
        } else if ch == '\x1B' {
            in_escape = true;
            result.push(ch);
        } else {
            if visible >= max_visible { break; }
            result.push(ch);
            visible += 1;
        }
    }
    result
}

// ─── Cached Frame ───────────────────────────────────────────────────

struct CachedFrame {
    ansi: String,
    footer: String,
    camera_label: Option<String>,
    camera_active: bool,
}

static MAP_FRAME: LazyLock<Arc<Mutex<Option<CachedFrame>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));
static MAP_TX: LazyLock<Arc<Mutex<Option<std::sync::mpsc::Sender<MapCmd>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));
static MAP_STARTED: LazyLock<Arc<std::sync::atomic::AtomicBool>> =
    LazyLock::new(|| Arc::new(std::sync::atomic::AtomicBool::new(false)));

// ─── Background Thread ─────────────────────────────────────────────

fn ensure_started() {
    if MAP_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) { return; }

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

            let mut cur_c: u16 = 120;
            let mut cur_r: u16 = 30;
            map.set_size(cur_c as usize * 2, cur_r as usize * 4);
            map.fit_world();

            // Auto-start globe tour immediately — no need to press 'g'
            map.start_globe_tour_at(0.5);

            do_render(&map, &frame_out).await;

            loop {
                let mut needs_render = false;

                while let Ok(cmd) = rx.try_recv() {
                    match cmd {
                        MapCmd::Resize(c, r) => {
                            if c != cur_c || r != cur_r {
                                cur_c = c; cur_r = r;
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
                                // Ring(3) with pulse — visible pulsing circles like a radar
                                map.add_marker(
                                    terminalmap::marker::MapMarker::dot(*lat, *lon, *color)
                                        .with_shape(terminalmap::marker::MarkerShape::Ring(3))
                                        .with_animation(anim),
                                );
                            }
                            needs_render = true;
                        }
                        MapCmd::ZoomIn => { map.zoom_by(map.config.zoom_step); needs_render = true; }
                        MapCmd::ZoomOut => { map.zoom_by(-map.config.zoom_step); needs_render = true; }
                        MapCmd::PanLeft => { map.move_by(0.0, -8.0 / 2.0_f64.powf(map.zoom)); needs_render = true; }
                        MapCmd::PanRight => { map.move_by(0.0, 8.0 / 2.0_f64.powf(map.zoom)); needs_render = true; }
                        MapCmd::PanUp => { map.move_by(6.0 / 2.0_f64.powf(map.zoom), 0.0); needs_render = true; }
                        MapCmd::PanDown => { map.move_by(-6.0 / 2.0_f64.powf(map.zoom), 0.0); needs_render = true; }
                        MapCmd::ToggleBraille => { map.toggle_braille(); needs_render = true; }
                        MapCmd::ToggleLabels => { map.toggle_labels(); needs_render = true; }
                        MapCmd::FitWorld => { map.fit_world(); needs_render = true; }
                        MapCmd::ToggleSmartTour => {
                            if map.camera().is_active() {
                                map.camera_mut().stop();
                            } else if !map.markers().is_empty() {
                                // Tour markers — pan to where connections are
                                map.start_marker_tour(1.0);
                            } else {
                                // No markers — globe tour at continent level
                                map.start_globe_tour_at(0.5);
                            }
                            needs_render = true;
                        }
                        MapCmd::ToggleGlobeTour => {
                            if map.camera().is_active() { map.camera_mut().stop(); }
                            else {
                                map.start_globe_tour_at(0.5);
                            }
                            needs_render = true;
                        }
                        MapCmd::ToggleMarkerTour => {
                            if map.camera().is_active() { map.camera_mut().stop(); }
                            else {
                                // Zoom 2.0 = regional level, centers on where markers are
                                map.start_marker_tour(1.0);
                            }
                            needs_render = true;
                        }
                    }
                }

                map.advance_tick();
                let cam = map.update_camera();
                if map.needs_animation_redraw() || cam { needs_render = true; }
                if needs_render { do_render(&map, &frame_out).await; }

                // 50ms for responsive interaction (matches standalone)
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
    });
}

async fn do_render(map: &terminalmap::widget::MapState, out: &Arc<Mutex<Option<CachedFrame>>>) {
    if let Ok(ansi) = map.render().await {
        let footer = map.footer();
        let camera_label = map.camera().current_label().map(|s| s.to_string());
        let camera_active = map.camera().is_active();
        if let Ok(mut guard) = out.lock() {
            *guard = Some(CachedFrame { ansi, footer, camera_label, camera_active });
        }
    }
}

// ─── Public Draw Function ───────────────────────────────────────────

pub fn draw_terminal_map(
    f: &mut Frame,
    area: Rect,
    dots: &[MapDot],
    _animation_frame: u8,
    title: &str,
) {
    ensure_started();

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
    if inner.width < 4 || inner.height < 4 { return; }

    // Reserve 2 rows for footer (help + status), like standalone
    let map_rows = inner.height;

    send_map_cmd(MapCmd::Resize(inner.width, map_rows));

    if !dots.is_empty() {
        let markers: Vec<(f64, f64, u8, bool)> = dots.iter().take(150).map(|d| {
            let color = if d.pulsing { 196u8 } else { 48u8 };
            (d.lat, d.lon, color, d.pulsing)
        }).collect();
        send_map_cmd(MapCmd::UpdateMarkers(markers));
    }

    // Fill inner area with spaces so ratatui's diff buffer won't overwrite our ANSI
    let blank: Vec<Line> = (0..inner.height)
        .map(|_| Line::from(" ".repeat(inner.width as usize)))
        .collect();
    f.render_widget(Paragraph::new(blank).style(Style::default().bg(theme::BG)), inner);

    // Queue ANSI write for after ratatui flush
    let cached = MAP_FRAME.lock().ok().and_then(|guard| {
        guard.as_ref().map(|cf| (
            cf.ansi.clone(), cf.footer.clone(),
            cf.camera_label.clone(), cf.camera_active,
        ))
    });

    match cached {
        Some((ansi, footer, camera_label, camera_active)) => {
            let help_line = "\x1B[90m hjkl:\x1B[37mPan  \x1B[90ma/z:\x1B[37mZoom  \x1B[90mc:\x1B[37mBraille  \x1B[90mn:\x1B[37mLabels  \x1B[90mw:\x1B[37mWorld  \x1B[90mg:\x1B[37mGlobe  \x1B[90mt:\x1B[37mTour\x1B[0m".to_string();
            let mut status = footer;
            if let Some(label) = camera_label {
                status.push_str(&format!("   >> {}", label));
            }
            if camera_active {
                status.push_str("   [TOUR: g/t to stop]");
            }

            if let Ok(mut pending) = PENDING_WRITES.lock() {
                pending.push(PendingMapWrite {
                    origin_x: inner.x,
                    origin_y: inner.y,
                    map_rows,
                    map_cols: inner.width,
                    ansi,
                    help_line,
                    status_line: status,
                });
            }
        }
        None => {
            let loading = Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled("  \u{231B} Loading TerminalMap...", Style::default().fg(theme::TEXT_DIM))),
            ]).style(Style::default().bg(theme::BG));
            f.render_widget(loading, inner);
        }
    }
}
