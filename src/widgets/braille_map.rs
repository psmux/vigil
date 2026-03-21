use std::sync::{Mutex, OnceLock};

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::theme;

// ─── Braille Dot Mask ───────────────────────────────────────────────

/// Map sub-cell coordinates (cx: 0..2, cy: 0..4) to the braille dot bitmask.
///
/// Braille dot layout per terminal character cell:
/// ```text
///   bit 0  bit 3   (sub-row 0)
///   bit 1  bit 4   (sub-row 1)
///   bit 2  bit 5   (sub-row 2)
///   bit 6  bit 7   (sub-row 3)
/// ```
fn dot_mask(cx: usize, cy: usize) -> u8 {
    match (cx, cy) {
        (0, 0) => 0x01,
        (0, 1) => 0x02,
        (0, 2) => 0x04,
        (1, 0) => 0x08,
        (1, 1) => 0x10,
        (1, 2) => 0x20,
        (0, 3) => 0x40,
        (1, 3) => 0x80,
        _ => 0,
    }
}

// ─── Coastline colors ───────────────────────────────────────────────

/// Primary coastlines: major continental outlines — brighter blue
const COASTLINE_PRIMARY: Color = Color::Rgb(60, 95, 140);
/// Secondary coastlines: island detail, small features — subtler blue
const COASTLINE_SECONDARY: Color = Color::Rgb(40, 70, 110);
/// Country land borders — subtle warm tone distinct from coastlines
const BORDER_COLOR: Color = Color::Rgb(50, 60, 80);
/// Land fill — very subtle shade to distinguish land from ocean
const LAND_FILL_COLOR: Color = Color::Rgb(14, 20, 36);
/// Latitude / longitude grid
const GRID_COLOR: Color = Color::Rgb(18, 25, 42);
/// Continent label text
const LABEL_COLOR: Color = Color::Rgb(25, 35, 55);

// ─── BrailleCanvas ──────────────────────────────────────────────────

/// A 2D canvas where each terminal character cell holds a 2x4 braille dot
/// matrix (Unicode Braille U+2800..U+28FF).
///
/// Each cell tracks a priority value so that higher-priority draws (dots,
/// glows) overwrite lower-priority ones (grid lines, coastlines).
#[derive(Clone)]
pub struct BrailleCanvas {
    width: usize,
    height: usize,
    cells: Vec<Vec<u8>>,
    colors: Vec<Vec<Color>>,
    bg_colors: Vec<Vec<Option<Color>>>,
    priority: Vec<Vec<u8>>,
    /// Text overlay entries: (col, row, char, color, priority).
    text_overlay: Vec<(usize, usize, char, Color, u8)>,
}

impl BrailleCanvas {
    /// Create an empty canvas. `width`/`height` are terminal columns/rows.
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            cells: vec![vec![0u8; width]; height],
            colors: vec![vec![COASTLINE_PRIMARY; width]; height],
            bg_colors: vec![vec![None; width]; height],
            priority: vec![vec![0u8; width]; height],
            text_overlay: Vec::new(),
        }
    }

    /// Set the background color for a terminal cell.
    pub fn set_cell_bg(&mut self, col: usize, row: usize, bg: Color) {
        if col < self.width && row < self.height {
            self.bg_colors[row][col] = Some(bg);
        }
    }

    /// Pixel-space width (each terminal column = 2 braille dots wide).
    pub fn px_width(&self) -> usize {
        self.width * 2
    }

    /// Pixel-space height (each terminal row = 4 braille dots tall).
    pub fn px_height(&self) -> usize {
        self.height * 4
    }

    /// Set a single braille dot at pixel coordinates `(px, py)`.
    /// `px` range: `0..width*2`, `py` range: `0..height*4`.
    pub fn set_dot(&mut self, px: i32, py: i32, color: Color) {
        self.set_dot_pri(px, py, color, 1);
    }

    /// Set a braille dot with a priority level. Higher priority overwrites
    /// lower priority colors in the same cell.
    pub fn set_dot_pri(&mut self, px: i32, py: i32, color: Color, pri: u8) {
        if px < 0 || py < 0 {
            return;
        }
        let px = px as usize;
        let py = py as usize;
        if px >= self.px_width() || py >= self.px_height() {
            return;
        }
        let col = px / 2;
        let row = py / 4;
        let cx = px % 2;
        let cy = py % 4;
        self.cells[row][col] |= dot_mask(cx, cy);
        if pri >= self.priority[row][col] {
            self.colors[row][col] = color;
            self.priority[row][col] = pri;
        }
    }

    /// Draw a line using Bresenham's algorithm in braille pixel space.
    pub fn draw_line(&mut self, x0: i32, y0: i32, x1: i32, y1: i32, color: Color) {
        self.draw_line_pri(x0, y0, x1, y1, color, 1);
    }

    /// Draw a line with a priority level.
    pub fn draw_line_pri(
        &mut self,
        x0: i32,
        y0: i32,
        x1: i32,
        y1: i32,
        color: Color,
        pri: u8,
    ) {
        let mut x0 = x0;
        let mut y0 = y0;
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx: i32 = if x0 < x1 { 1 } else { -1 };
        let sy: i32 = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            self.set_dot_pri(x0, y0, color, pri);
            if x0 == x1 && y0 == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x0 += sx;
            }
            if e2 <= dx {
                err += dx;
                y0 += sy;
            }
        }
    }

    /// Draw a filled circle at braille pixel coordinates.
    pub fn draw_filled_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        self.draw_filled_circle_pri(cx, cy, radius, color, 2);
    }

    /// Draw a filled circle with a priority level.
    pub fn draw_filled_circle_pri(
        &mut self,
        cx: i32,
        cy: i32,
        radius: i32,
        color: Color,
        pri: u8,
    ) {
        let r2 = radius * radius;
        for dy in -radius..=radius {
            for dx in -radius..=radius {
                if dx * dx + dy * dy <= r2 {
                    self.set_dot_pri(cx + dx, cy + dy, color, pri);
                }
            }
        }
    }

    /// Draw a hollow circle outline (ring) using midpoint circle algorithm.
    pub fn draw_circle_outline(&mut self, cx: i32, cy: i32, radius: i32, color: Color, pri: u8) {
        let mut x = radius;
        let mut y = 0i32;
        let mut err = 1 - radius;
        while x >= y {
            self.set_dot_pri(cx + x, cy + y, color, pri);
            self.set_dot_pri(cx - x, cy + y, color, pri);
            self.set_dot_pri(cx + x, cy - y, color, pri);
            self.set_dot_pri(cx - x, cy - y, color, pri);
            self.set_dot_pri(cx + y, cy + x, color, pri);
            self.set_dot_pri(cx - y, cy + x, color, pri);
            self.set_dot_pri(cx + y, cy - x, color, pri);
            self.set_dot_pri(cx - y, cy - x, color, pri);
            y += 1;
            if err < 0 { err += 2 * y + 1; }
            else { x -= 1; err += 2 * (y - x) + 1; }
        }
    }

    /// Place a text label on the canvas. Text characters will replace
    /// braille glyphs at the specified terminal cell positions.
    pub fn place_text(&mut self, col: usize, row: usize, text: &str, color: Color, pri: u8) {
        for (i, ch) in text.chars().enumerate() {
            let c = col + i;
            if c < self.width && row < self.height {
                self.text_overlay.push((c, row, ch, color, pri));
            }
        }
    }

    /// Render the canvas into ratatui `Line`s. Each cell becomes a braille
    /// character `U+2800 + mask`, styled with its foreground color over the
    /// ocean background. Text overlays replace braille glyphs where present.
    pub fn render(&self) -> Vec<Line<'static>> {
        // Build a lookup for text overlays
        let mut text_map: std::collections::HashMap<(usize, usize), (char, Color)> =
            std::collections::HashMap::new();
        for &(c, r, ch, color, _pri) in &self.text_overlay {
            if r < self.height && c < self.width {
                // Only place label if the cell has no braille content (avoid overwriting coastlines)
                if self.cells[r][c] == 0 {
                    text_map.insert((c, r), (ch, color));
                }
            }
        }

        let mut lines = Vec::with_capacity(self.height);
        for row in 0..self.height {
            let mut spans = Vec::with_capacity(self.width);
            for col in 0..self.width {
                let bg = self.bg_colors[row][col].unwrap_or(theme::BG);
                if let Some(&(ch, color)) = text_map.get(&(col, row)) {
                    spans.push(Span::styled(
                        ch.to_string(),
                        Style::default().fg(color).bg(bg),
                    ));
                } else {
                    let mask = self.cells[row][col];
                    let ch = char::from_u32(0x2800 + mask as u32).unwrap_or(' ');
                    let fg = self.colors[row][col];
                    spans.push(Span::styled(
                        ch.to_string(),
                        Style::default().fg(fg).bg(bg),
                    ));
                }
            }
            lines.push(Line::from(spans));
        }
        lines
    }
}

// ─── Mercator Projection ────────────────────────────────────────────

/// Convert (longitude, latitude) to normalized (x, y) in [0..1].
/// Uses standard Web Mercator. `y=0` is north, `y=1` is south.
fn mercator(lon: f64, lat: f64) -> (f64, f64) {
    let x = (lon + 180.0) / 360.0;
    let lat_rad = lat.to_radians();
    let merc_y = ((std::f64::consts::PI / 4.0) + (lat_rad / 2.0)).tan().ln();
    let y = 0.5 - merc_y / (2.0 * std::f64::consts::PI);
    (x, y)
}

/// Visible latitude range for the map.
const LAT_NORTH: f64 = 78.0;
const LAT_SOUTH: f64 = -58.0;

/// Project (lon, lat) to braille pixel coordinates for the given canvas
/// pixel dimensions.
fn project(lon: f64, lat: f64, px_w: usize, px_h: usize) -> (i32, i32) {
    let (mx, my) = mercator(lon, lat);
    let (_, y_north) = mercator(0.0, LAT_NORTH);
    let (_, y_south) = mercator(0.0, LAT_SOUTH);
    let px = (mx * px_w as f64) as i32;
    let py = (((my - y_north) / (y_south - y_north)) * px_h as f64) as i32;
    (px, py)
}

/// Project (lon, lat) to terminal cell coordinates (col, row).
fn project_cell(lon: f64, lat: f64, w: usize, h: usize) -> (usize, usize) {
    let px_w = w * 2;
    let px_h = h * 4;
    let (px, py) = project(lon, lat, px_w, px_h);
    let col = (px / 2).clamp(0, w as i32 - 1) as usize;
    let row = (py / 4).clamp(0, h as i32 - 1) as usize;
    (col, row)
}

// ─── IP Jitter ──────────────────────────────────────────────────────

/// Deterministic per-IP pixel jitter (same approach as psnet).
fn ip_jitter(seed: u32) -> (i32, i32) {
    let x = ((seed.wrapping_mul(2654435761)) >> 24) as i32 % 3 - 1;
    let y = ((seed.wrapping_mul(2246822519)) >> 24) as i32 % 3 - 1;
    (x, y)
}

// ─── MapDot ─────────────────────────────────────────────────────────

/// A single dot to render on the world map.
pub struct MapDot {
    pub lat: f64,
    pub lon: f64,
    pub color: Color,
    pub pulsing: bool,
    /// Radius in braille pixels (1-3).
    pub radius: u8,
    pub jitter_seed: u32,
}

// ─── Country Center Coordinates ─────────────────────────────────────

/// Center coordinates for countries: `(iso2, longitude, latitude)`.
pub const COUNTRY_COORDS: &[(&str, f64, f64)] = &[
    ("US", -98.0, 38.0),
    ("CA", -106.0, 56.0),
    ("MX", -102.0, 23.0),
    ("BR", -51.0, -10.0),
    ("AR", -64.0, -34.0),
    ("CO", -72.0, 4.0),
    ("GB", -2.0, 54.0),
    ("FR", 2.0, 46.0),
    ("DE", 10.0, 51.0),
    ("NL", 5.0, 52.0),
    ("ES", -3.0, 40.0),
    ("IT", 12.0, 42.0),
    ("SE", 15.0, 62.0),
    ("NO", 10.0, 62.0),
    ("FI", 26.0, 64.0),
    ("PL", 20.0, 52.0),
    ("UA", 32.0, 49.0),
    ("RO", 25.0, 46.0),
    ("RU", 50.0, 55.0),
    ("TR", 35.0, 39.0),
    ("SA", 45.0, 24.0),
    ("IR", 53.0, 32.0),
    ("IN", 79.0, 21.0),
    ("PK", 69.0, 30.0),
    ("BD", 90.0, 24.0),
    ("CN", 105.0, 35.0),
    ("JP", 138.0, 36.0),
    ("KR", 128.0, 36.0),
    ("TW", 121.0, 24.0),
    ("VN", 106.0, 16.0),
    ("TH", 101.0, 15.0),
    ("SG", 104.0, 1.3),
    ("ID", 118.0, -2.0),
    ("MY", 102.0, 4.0),
    ("PH", 122.0, 13.0),
    ("AU", 134.0, -25.0),
    ("NZ", 172.0, -41.0),
    ("ZA", 25.0, -29.0),
    ("NG", 8.0, 10.0),
    ("EG", 30.0, 27.0),
    ("KE", 38.0, -1.0),
    ("IL", 35.0, 31.0),
    ("AE", 54.0, 24.0),
    ("CL", -71.0, -33.0),
    ("PE", -76.0, -10.0),
];

/// Look up center coordinates for a country ISO-2 code.
pub fn country_center(iso2: &str) -> Option<(f64, f64)> {
    COUNTRY_COORDS
        .iter()
        .find(|(code, _, _)| *code == iso2)
        .map(|(_, lon, lat)| (*lon, *lat))
}

// ─── Coastline Data ─────────────────────────────────────────────────

/// Parsed coastline data with primary (major), secondary (detail), and border layers.
struct CoastlineData {
    primary: Vec<Vec<(f64, f64)>>,
    secondary: Vec<Vec<(f64, f64)>>,
    borders: Vec<Vec<(f64, f64)>>,
}

/// Load world coastlines from the embedded JSON asset file.
/// Returns two layers: primary (major coastlines) and secondary (detail).
/// Data sourced from Natural Earth 50m coastlines — ~60,000 real geographic points.
fn world_coastlines() -> &'static CoastlineData {
    static COASTLINES: OnceLock<CoastlineData> = OnceLock::new();
    COASTLINES.get_or_init(|| {
        let data = include_str!("../../assets/world.json");

        // Try new layered format: {"primary": [...], "secondary": [...], "borders": [...]}
        if let Ok(layered) = serde_json::from_str::<serde_json::Value>(data) {
            if layered.is_object() && layered.get("primary").is_some() {
                let parse_layer = |val: &serde_json::Value| -> Vec<Vec<(f64, f64)>> {
                    serde_json::from_value::<Vec<Vec<[f64; 2]>>>(val.clone())
                        .unwrap_or_default()
                        .into_iter()
                        .map(|poly| poly.into_iter().map(|p| (p[0], p[1])).collect())
                        .collect()
                };
                let primary = layered
                    .get("primary")
                    .map(|v| parse_layer(v))
                    .unwrap_or_default();
                let secondary = layered
                    .get("secondary")
                    .map(|v| parse_layer(v))
                    .unwrap_or_default();
                let borders = layered
                    .get("borders")
                    .map(|v| parse_layer(v))
                    .unwrap_or_default();
                return CoastlineData { primary, secondary, borders };
            }
        }

        // Fallback: legacy flat array format
        let raw: Vec<Vec<[f64; 2]>> = serde_json::from_str(data).unwrap_or_default();
        let all: Vec<Vec<(f64, f64)>> = raw
            .into_iter()
            .map(|poly| poly.into_iter().map(|p| (p[0], p[1])).collect())
            .collect();
        CoastlineData {
            primary: all,
            secondary: Vec::new(),
            borders: Vec::new(),
        }
    })
}

// ─── Continent Labels ───────────────────────────────────────────────

/// Continent labels with approximate center coordinates (lon, lat).
const CONTINENT_LABELS: &[(&str, f64, f64)] = &[
    ("NA", -100.0, 45.0),
    ("SA", -58.0, -15.0),
    ("EU", 15.0, 52.0),
    ("AF", 20.0, 5.0),
    ("AS", 85.0, 42.0),
    ("AU", 134.0, -25.0),
];

// ─── Color Helpers ──────────────────────────────────────────────────

/// Dim a color by a factor (0.0 = black, 1.0 = unchanged).
fn dim_color(c: Color, factor: f64) -> Color {
    match c {
        Color::Rgb(r, g, b) => Color::Rgb(
            (r as f64 * factor) as u8,
            (g as f64 * factor) as u8,
            (b as f64 * factor) as u8,
        ),
        other => other,
    }
}

/// Brighten a color by a factor (1.0 = unchanged, 2.0 = double brightness).
fn brighten_color(c: Color, factor: f64) -> Color {
    match c {
        Color::Rgb(r, g, b) => Color::Rgb(
            ((r as f64 * factor).min(255.0)) as u8,
            ((g as f64 * factor).min(255.0)) as u8,
            ((b as f64 * factor).min(255.0)) as u8,
        ),
        other => other,
    }
}

// ─── Grid Drawing ───────────────────────────────────────────────────

/// Draw a subtle latitude/longitude grid at 30-degree intervals.
fn draw_grid(canvas: &mut BrailleCanvas, px_w: usize, px_h: usize) {
    // Latitude lines every 30 degrees
    for lat_deg in [-60, -30, 0, 30, 60] {
        let lat = lat_deg as f64;
        if lat < LAT_SOUTH || lat > LAT_NORTH {
            continue;
        }
        let (_, py) = project(0.0, lat, px_w, px_h);
        // Equator gets slightly brighter treatment
        let color = if lat_deg == 0 {
            Color::Rgb(22, 30, 50)
        } else {
            GRID_COLOR
        };
        // Draw dotted horizontal line
        let mut x = 0i32;
        while x < px_w as i32 {
            canvas.set_dot_pri(x, py, color, 0);
            x += 3;
        }
    }

    // Longitude lines every 30 degrees
    for lon_deg in (-180..=180).step_by(30) {
        let lon = lon_deg as f64;
        let (px_top, py_top) = project(lon, LAT_NORTH, px_w, px_h);
        let (_, py_bot) = project(lon, LAT_SOUTH, px_w, px_h);
        // Prime meridian gets slightly brighter
        let color = if lon_deg == 0 {
            Color::Rgb(22, 30, 50)
        } else {
            GRID_COLOR
        };
        let mut y = py_top;
        while y < py_bot {
            canvas.set_dot_pri(px_top, y, color, 0);
            y += 3;
        }
    }
}

// ─── Coastline Drawing ─────────────────────────────────────────────

/// Draw a set of polylines onto the canvas with the given color and priority.
fn draw_coastline_layer(
    canvas: &mut BrailleCanvas,
    polylines: &[Vec<(f64, f64)>],
    color: Color,
    pri: u8,
    px_w: usize,
    px_h: usize,
) {
    for polyline in polylines.iter() {
        if polyline.len() < 2 {
            continue;
        }
        let mut prev = project(polyline[0].0, polyline[0].1, px_w, px_h);
        for &(lon, lat) in &polyline[1..] {
            let cur = project(lon, lat, px_w, px_h);
            // Skip wrap-around artifacts: if projected distance is too large
            let dx = (cur.0 - prev.0).abs() as f64;
            let dy = (cur.1 - prev.1).abs() as f64;
            if dx / (px_w as f64) < 0.4 && dy / (px_h as f64) < 0.4 {
                canvas.draw_line_pri(prev.0, prev.1, cur.0, cur.1, color, pri);
            }
            prev = cur;
        }
    }
}

// ─── Land Fill ──────────────────────────────────────────────────────

/// Simple land fill: for each row, find cells that have coastline/border
/// dots and flood-fill between them with a subtle background.
/// This is a simplified scanline approach — it won't be perfect but gives
/// a visual hint of land vs ocean.
fn apply_land_fill(canvas: &mut BrailleCanvas) {
    // For each row, identify cells that have any drawn content (coastline/border dots).
    // Between pairs of "boundary" cells, apply a subtle background tint.
    for row in 0..canvas.height {
        let mut boundary_cols: Vec<usize> = Vec::new();
        for col in 0..canvas.width {
            if canvas.cells[row][col] != 0 {
                boundary_cols.push(col);
            }
        }

        // Fill between adjacent boundary cells that are close together
        // (within ~60% of width to avoid ocean fills across the whole map)
        let max_gap = canvas.width / 3;
        for window in boundary_cols.windows(2) {
            let (a, b) = (window[0], window[1]);
            let gap = b - a;
            if gap > 1 && gap < max_gap {
                for col in (a + 1)..b {
                    if canvas.bg_colors[row][col].is_none() {
                        canvas.set_cell_bg(col, row, LAND_FILL_COLOR);
                    }
                }
            }
        }
    }
}

// ─── Base Map Cache ────────────────────────────────────────────────
//
// The base map (grid, coastlines, borders, land fill, labels) is 100%
// static — it only depends on the terminal dimensions (w, h). Drawing
// 3700+ polylines with Bresenham every frame is the #1 rendering
// bottleneck. Cache the base canvas and clone it per frame, only
// adding the dynamic dots to the clone.

/// Cached base map: (width, height, canvas).
static BASE_MAP_CACHE: Mutex<Option<(usize, usize, BrailleCanvas)>> = Mutex::new(None);

/// Get or create the cached base map canvas for the given dimensions.
fn get_base_map(w: usize, h: usize) -> BrailleCanvas {
    let mut cache = BASE_MAP_CACHE.lock().unwrap();

    // Return cached version if dimensions match
    if let Some((cw, ch, ref canvas)) = *cache {
        if cw == w && ch == h {
            return canvas.clone();
        }
    }

    // Build new base map — this is expensive but only happens on resize
    let mut canvas = BrailleCanvas::new(w, h);
    let px_w = canvas.px_width();
    let px_h = canvas.px_height();

    // Grid
    draw_grid(&mut canvas, px_w, px_h);

    // Coastlines and borders
    let coastlines = world_coastlines();

    if !coastlines.borders.is_empty() {
        draw_coastline_layer(&mut canvas, &coastlines.borders, BORDER_COLOR, 1, px_w, px_h);
    }
    draw_coastline_layer(&mut canvas, &coastlines.secondary, COASTLINE_SECONDARY, 2, px_w, px_h);
    draw_coastline_layer(&mut canvas, &coastlines.primary, COASTLINE_PRIMARY, 2, px_w, px_h);

    // Land fill
    apply_land_fill(&mut canvas);

    // Continent labels
    for &(label, lon, lat) in CONTINENT_LABELS {
        let (col, row) = project_cell(lon, lat, w, h);
        let offset = label.len() / 2;
        let col = col.saturating_sub(offset);
        canvas.place_text(col, row, label, LABEL_COLOR, 0);
    }

    // Store in cache
    *cache = Some((w, h, canvas.clone()));
    canvas
}

// ─── Main Draw Function ─────────────────────────────────────────────

/// Draw a full world map with Mercator projection, coastlines, and
/// animated dots inside a bordered widget.
pub fn draw_world_map(
    f: &mut Frame,
    area: Rect,
    dots: &[MapDot],
    animation_frame: u8,
    title: &str,
) {
    // Outer block with border
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG))
        .title(Line::from(Span::styled(
            format!(" {} ", title),
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(theme::BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 4 || inner.height < 2 {
        return;
    }

    let w = inner.width as usize;
    let h = inner.height as usize;

    // Get cached base map (grid + coastlines + borders + labels)
    // This avoids redrawing 3700+ polylines every frame
    let mut canvas = get_base_map(w, h);
    let px_w = canvas.px_width();
    let px_h = canvas.px_height();

    // Only the dots are dynamic — draw them on the cloned canvas
    for dot in dots {
        let (px, py) = project(dot.lon, dot.lat, px_w, px_h);
        let (jx, jy) = ip_jitter(dot.jitter_seed);
        let fx = (px + jx).clamp(0, px_w as i32 - 1);
        let fy = (py + jy).clamp(0, px_h as i32 - 1);

        let color = if dot.pulsing {
            match animation_frame % 4 {
                0 => Color::Rgb(255, 80, 80),
                1 => Color::Rgb(200, 50, 50),
                2 => Color::Rgb(130, 30, 30),
                _ => Color::Rgb(200, 50, 50),
            }
        } else {
            dot.color
        };

        canvas.set_dot_pri(fx, fy, color, 4);
    }

    // Render
    let lines = canvas.render();
    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
