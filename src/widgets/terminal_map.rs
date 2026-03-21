//! TerminalMap integration — renders OSM vector tile maps via the
//! terminalmap crate, running the async renderer in a background
//! thread and exposing cached frames for ratatui display.

use std::sync::{Arc, Mutex, LazyLock};
use std::thread;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::theme;
use crate::widgets::braille_map::MapDot;

// ─── Shared State ───────────────────────────────────────────────────

/// Cached rendered map frame: (width, height, lines).
/// Written by background thread, read by UI thread.
static MAP_FRAME: LazyLock<Arc<Mutex<Option<CachedMapFrame>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

/// Request channel: UI thread sends resize/marker updates.
static MAP_REQUEST: LazyLock<Arc<Mutex<Option<std::sync::mpsc::Sender<MapRequest>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

/// Whether the background map thread has been spawned.
static MAP_STARTED: LazyLock<Arc<std::sync::atomic::AtomicBool>> =
    LazyLock::new(|| Arc::new(std::sync::atomic::AtomicBool::new(false)));

struct CachedMapFrame {
    width: u16,
    height: u16,
    ansi: String,
}

enum MapRequest {
    Resize(u16, u16),
    SetMarkers(Vec<(f64, f64, String)>), // (lat, lon, id)
    Render,
}

// ─── Background Thread ──────────────────────────────────────────────

/// Ensure the background map rendering thread is running.
fn ensure_map_thread() {
    if MAP_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return; // Already started
    }

    let frame_store = Arc::clone(&*MAP_FRAME);
    let (tx, rx) = std::sync::mpsc::channel::<MapRequest>();

    // Store the sender for the UI thread to use
    if let Ok(mut guard) = MAP_REQUEST.lock() {
        *guard = Some(tx);
    }

    thread::spawn(move || {
        // Create a tokio runtime for the async terminalmap API
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return,
        };

        rt.block_on(async move {
            let config = terminalmap::config::MapConfig {
                initial_lat: 20.0,
                initial_lon: 0.0,
                initial_zoom: None, // world view
                persist_downloaded_tiles: true,
                show_labels: false, // cleaner for dashboard use
                ..terminalmap::config::MapConfig::default()
            };

            let mut map = match terminalmap::widget::MapState::new(config).await {
                Ok(m) => m,
                Err(_) => return,
            };

            // Default to a reasonable size, will be resized by first request
            map.set_size_from_terminal(120, 30);
            map.fit_world();

            // Initial render
            if let Ok(ansi) = map.render().await {
                if let Ok(mut guard) = frame_store.lock() {
                    *guard = Some(CachedMapFrame {
                        width: 120,
                        height: 30,
                        ansi,
                    });
                }
            }

            // Process requests from the UI thread
            loop {
                // Drain all pending requests
                let mut needs_render = false;
                let mut latest_size: Option<(u16, u16)> = None;

                while let Ok(req) = rx.try_recv() {
                    match req {
                        MapRequest::Resize(w, h) => {
                            latest_size = Some((w, h));
                            needs_render = true;
                        }
                        MapRequest::SetMarkers(markers) => {
                            map.clear_markers();
                            for (lat, lon, id) in markers {
                                map.add_marker(
                                    terminalmap::marker::MapMarker::dot(lat, lon, 48) // xterm green
                                        .with_animation(terminalmap::marker::MarkerAnimation::Pulse)
                                );
                            }
                            needs_render = true;
                        }
                        MapRequest::Render => {
                            needs_render = true;
                        }
                    }
                }

                if let Some((w, h)) = latest_size {
                    map.set_size_from_terminal(w, h);
                    map.fit_world();
                }

                if needs_render {
                    map.advance_tick();
                    if let Ok(ansi) = map.render().await {
                        let (w, h) = latest_size.unwrap_or((map.width as u16, map.height as u16));
                        if let Ok(mut guard) = frame_store.lock() {
                            *guard = Some(CachedMapFrame {
                                width: w,
                                height: h,
                                ansi,
                            });
                        }
                    }
                }

                // Sleep to avoid busy-waiting; UI will send Render requests
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });
    });
}

/// Send a request to the background map thread.
fn send_request(req: MapRequest) {
    if let Ok(guard) = MAP_REQUEST.lock() {
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(req);
        }
    }
}

// ─── ANSI → ratatui Lines Parser ────────────────────────────────────

/// Parse ANSI-colored string into ratatui Lines.
/// Handles basic xterm-256 color escapes: \x1b[38;5;Nm (fg) and \x1b[48;5;Nm (bg).
fn ansi_to_lines(ansi: &str) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut current_spans: Vec<Span<'static>> = Vec::new();
    let mut current_text = String::new();
    let mut fg = Color::White;
    let mut bg = theme::BG;

    let chars: Vec<char> = ansi.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '\n' {
            // Flush current text as span
            if !current_text.is_empty() {
                current_spans.push(Span::styled(
                    std::mem::take(&mut current_text),
                    Style::default().fg(fg).bg(bg),
                ));
            }
            lines.push(Line::from(std::mem::take(&mut current_spans)));
            i += 1;
        } else if chars[i] == '\x1b' && i + 1 < len && chars[i + 1] == '[' {
            // Flush current text
            if !current_text.is_empty() {
                current_spans.push(Span::styled(
                    std::mem::take(&mut current_text),
                    Style::default().fg(fg).bg(bg),
                ));
            }

            // Parse escape sequence
            let start = i + 2;
            let mut end = start;
            while end < len && chars[end] != 'm' && end - start < 20 {
                end += 1;
            }
            if end < len && chars[end] == 'm' {
                let seq: String = chars[start..end].iter().collect();
                parse_sgr(&seq, &mut fg, &mut bg);
                i = end + 1;
            } else {
                current_text.push(chars[i]);
                i += 1;
            }
        } else {
            current_text.push(chars[i]);
            i += 1;
        }
    }

    // Flush remaining
    if !current_text.is_empty() {
        current_spans.push(Span::styled(
            current_text,
            Style::default().fg(fg).bg(bg),
        ));
    }
    if !current_spans.is_empty() {
        lines.push(Line::from(current_spans));
    }

    lines
}

/// Parse SGR (Select Graphic Rendition) parameters.
fn parse_sgr(seq: &str, fg: &mut Color, bg: &mut Color) {
    let parts: Vec<&str> = seq.split(';').collect();
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "0" => {
                *fg = Color::White;
                *bg = theme::BG;
            }
            "38" if i + 2 < parts.len() && parts[i + 1] == "5" => {
                // xterm-256 foreground
                if let Ok(n) = parts[i + 2].parse::<u8>() {
                    *fg = Color::Indexed(n);
                }
                i += 2;
            }
            "48" if i + 2 < parts.len() && parts[i + 1] == "5" => {
                // xterm-256 background
                if let Ok(n) = parts[i + 2].parse::<u8>() {
                    *bg = Color::Indexed(n);
                }
                i += 2;
            }
            _ => {}
        }
        i += 1;
    }
}

// ─── Public Draw Function ───────────────────────────────────────────

/// Draw the TerminalMap world map with connection dots.
/// Falls back to the legacy braille map if TerminalMap isn't ready yet.
pub fn draw_terminal_map(
    f: &mut Frame,
    area: Rect,
    dots: &[MapDot],
    animation_frame: u8,
    title: &str,
) {
    // Ensure background thread is running
    ensure_map_thread();

    // Outer block
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

    // Request resize if needed
    send_request(MapRequest::Resize(inner.width, inner.height));

    // Send markers from dots
    if !dots.is_empty() {
        let markers: Vec<(f64, f64, String)> = dots
            .iter()
            .take(200) // limit markers to avoid overload
            .enumerate()
            .map(|(i, d)| (d.lat, d.lon, format!("dot_{}", i)))
            .collect();
        send_request(MapRequest::SetMarkers(markers));
    }

    // Request a render
    send_request(MapRequest::Render);

    // Try to display cached frame
    let cached = MAP_FRAME.lock().ok().and_then(|guard| {
        guard.as_ref().map(|frame| frame.ansi.clone())
    });

    if let Some(ansi) = cached {
        let lines = ansi_to_lines(&ansi);
        // Truncate to fit inner area
        let visible: Vec<Line> = lines.into_iter().take(inner.height as usize).collect();
        let paragraph = Paragraph::new(visible).style(Style::default().bg(theme::BG));
        f.render_widget(paragraph, inner);
    } else {
        // Fallback: show loading message while TerminalMap initializes
        let loading = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Loading map...",
                Style::default().fg(theme::TEXT_DIM),
            )),
        ];
        let paragraph = Paragraph::new(loading).style(Style::default().bg(theme::BG));
        f.render_widget(paragraph, inner);
    }
}
