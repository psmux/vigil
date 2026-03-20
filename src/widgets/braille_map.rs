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

// ─── Coastline color ────────────────────────────────────────────────

const COASTLINE: Color = Color::Rgb(30, 55, 85);

// ─── BrailleCanvas ──────────────────────────────────────────────────

/// A 2D canvas where each terminal character cell holds a 2x4 braille dot
/// matrix (Unicode Braille U+2800..U+28FF).
pub struct BrailleCanvas {
    width: usize,
    height: usize,
    cells: Vec<Vec<u8>>,
    colors: Vec<Vec<Color>>,
}

impl BrailleCanvas {
    /// Create an empty canvas. `width`/`height` are terminal columns/rows.
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            cells: vec![vec![0u8; width]; height],
            colors: vec![vec![COASTLINE; width]; height],
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
        self.colors[row][col] = color;
    }

    /// Draw a line using Bresenham's algorithm in braille pixel space.
    pub fn draw_line(&mut self, x0: i32, y0: i32, x1: i32, y1: i32, color: Color) {
        let mut x0 = x0;
        let mut y0 = y0;
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx: i32 = if x0 < x1 { 1 } else { -1 };
        let sy: i32 = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            self.set_dot(x0, y0, color);
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
        let r2 = radius * radius;
        for dy in -radius..=radius {
            for dx in -radius..=radius {
                if dx * dx + dy * dy <= r2 {
                    self.set_dot(cx + dx, cy + dy, color);
                }
            }
        }
    }

    /// Render the canvas into ratatui `Line`s. Each cell becomes a braille
    /// character `U+2800 + mask`, styled with its foreground color over the
    /// ocean background.
    pub fn render(&self) -> Vec<Line<'static>> {
        let mut lines = Vec::with_capacity(self.height);
        for row in 0..self.height {
            let mut spans = Vec::with_capacity(self.width);
            for col in 0..self.width {
                let mask = self.cells[row][col];
                let ch = char::from_u32(0x2800 + mask as u32).unwrap_or(' ');
                let fg = self.colors[row][col];
                spans.push(Span::styled(
                    ch.to_string(),
                    Style::default().fg(fg).bg(theme::BG),
                ));
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

// ─── IP Jitter ──────────────────────────────────────────────────────

/// Deterministic per-IP pixel jitter (same approach as psnet).
fn ip_jitter(seed: u32) -> (i32, i32) {
    let x = ((seed.wrapping_mul(2654435761)) >> 24) as i32 % 7 - 3;
    let y = ((seed.wrapping_mul(2246822519)) >> 24) as i32 % 5 - 2;
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

/// Return hardcoded world coastlines as polylines of (lon, lat) pairs.
/// Simplified to ~310 points for a recognizable world outline.
fn world_coastlines() -> Vec<Vec<(f64, f64)>> {
    vec![
        // ── North America: Pacific coast ────────────────────────
        vec![
            // Alaska
            (-168.0, 65.0), (-162.0, 63.5), (-153.0, 60.0), (-149.0, 61.0),
            (-140.0, 60.0),
            // Western Canada / US Pacific coast
            (-137.0, 59.0), (-135.0, 57.0), (-130.0, 54.0), (-126.0, 49.0),
            (-124.0, 46.0), (-124.0, 42.0), (-120.0, 35.0), (-117.0, 32.5),
            // Baja & Mexico Pacific
            (-115.0, 30.0), (-112.0, 26.0), (-106.0, 23.0), (-105.0, 20.0),
            // Central America
            (-97.0, 16.0), (-92.0, 15.0), (-88.0, 14.0), (-83.0, 10.0),
            (-80.0, 8.0), (-77.0, 8.5),
            // Colombia / Venezuela coast
            (-75.0, 10.0), (-72.0, 12.0), (-68.0, 12.0), (-66.0, 11.0),
            (-62.0, 10.5),
            // Caribbean coast
            (-61.0, 10.0), (-60.0, 11.0),
        ],
        // ── North America: Gulf of Mexico ───────────────────────
        vec![
            (-81.0, 25.0), (-82.0, 27.0), (-84.0, 30.0), (-88.0, 30.0),
            (-90.0, 29.0), (-94.0, 29.5), (-97.0, 26.0),
        ],
        // ── North America: East coast & Arctic ──────────────────
        vec![
            // US East Coast
            (-80.0, 25.0), (-80.0, 27.0), (-81.0, 31.0), (-78.0, 34.0),
            (-76.0, 36.0), (-75.0, 38.0), (-74.0, 40.0), (-72.0, 41.0),
            (-70.0, 42.0), (-67.0, 45.0), (-66.0, 44.5),
            // Maritime Canada
            (-64.0, 46.0), (-61.0, 46.0), (-60.0, 47.0), (-59.0, 47.5),
            (-56.0, 47.5), (-53.0, 47.0), (-52.5, 47.5),
            // Newfoundland / Labrador
            (-55.0, 50.0), (-57.0, 52.0), (-59.0, 54.0), (-62.0, 56.0),
            (-64.0, 58.0), (-64.0, 60.0), (-68.0, 62.0),
            // Hudson Bay / Arctic coast
            (-72.0, 63.0), (-78.0, 63.0), (-82.0, 62.0), (-85.0, 60.0),
            (-88.0, 58.0), (-90.0, 57.0), (-95.0, 57.0), (-96.0, 60.0),
            (-94.0, 63.0), (-88.0, 67.0), (-85.0, 69.0), (-80.0, 70.0),
            (-75.0, 72.0), (-70.0, 73.0), (-65.0, 73.0),
        ],
        // ── South America ───────────────────────────────────────
        vec![
            // Colombia coast → Brazil → Argentina → Chile → back
            (-77.0, 8.5), (-75.0, 6.0), (-73.0, 4.0), (-70.0, 2.0),
            (-65.0, 1.0), (-60.0, 2.0), (-52.0, 4.0), (-50.0, 2.0),
            (-48.0, -1.0), (-44.0, -2.5), (-40.0, -4.0), (-38.0, -5.0),
            (-35.0, -7.0), (-35.0, -10.0), (-37.0, -12.0), (-39.0, -15.0),
            (-40.0, -20.0), (-41.0, -22.0), (-44.0, -23.0), (-47.0, -25.0),
            (-48.0, -28.0),
            // Uruguay / Argentina
            (-50.0, -30.0), (-52.0, -33.0), (-55.0, -34.5), (-57.0, -35.0),
            (-58.5, -36.0), (-59.0, -38.0), (-62.0, -39.0), (-63.0, -41.0),
            (-65.0, -43.0), (-66.0, -45.0), (-67.0, -47.0), (-66.0, -49.0),
            (-68.0, -51.0), (-69.0, -53.0), (-70.0, -54.0),
            // Tierra del Fuego → Chile Pacific coast
            (-72.0, -53.0), (-73.0, -50.0), (-75.0, -47.0), (-74.0, -44.0),
            (-73.0, -40.0), (-72.0, -37.0), (-71.0, -33.0), (-72.0, -30.0),
            (-71.0, -27.0), (-70.0, -23.0), (-70.0, -18.0), (-71.0, -15.0),
            (-75.0, -12.0), (-77.0, -10.0), (-80.0, -5.0), (-81.0, -2.0),
            (-80.0, 0.0), (-78.0, 2.0), (-77.0, 4.0), (-77.0, 8.5),
        ],
        // ── Europe: Scandinavia & Baltic ────────────────────────
        vec![
            // Northern Norway → west coast → Denmark → Sweden → Finland
            (28.0, 71.0), (25.0, 71.0), (20.0, 70.0), (16.0, 69.0),
            (14.0, 68.0), (12.0, 66.0), (10.0, 63.0), (8.0, 61.0),
            (5.0, 60.0), (5.0, 58.0), (7.0, 57.5),
            // Denmark / Jutland
            (8.0, 57.0), (10.0, 57.5), (10.0, 56.0), (12.0, 56.0),
            (12.0, 58.0), (14.0, 58.0),
            // Sweden east coast → Finland
            (16.0, 57.0), (18.0, 59.0), (18.0, 60.0), (20.0, 60.0),
            (22.0, 60.0), (24.0, 60.0), (25.0, 61.0), (26.0, 64.0),
            (28.0, 66.0), (29.0, 68.0), (28.0, 71.0),
        ],
        // ── Europe: Western & Mediterranean ─────────────────────
        vec![
            // Netherlands → France → Iberia → Mediterranean
            (5.0, 53.0), (4.0, 52.0), (3.5, 51.5), (2.0, 51.0),
            (1.0, 50.5), (-1.0, 49.0), (-3.0, 48.5), (-5.0, 48.5),
            (-4.0, 47.5), (-2.0, 47.0), (-1.0, 46.5), (-2.0, 44.0),
            (-1.5, 43.5),
            // Spain
            (-2.0, 43.5), (-5.0, 43.5), (-8.0, 43.5), (-9.5, 42.0),
            (-9.0, 39.0), (-7.5, 37.0), (-6.0, 36.5),
            // Strait of Gibraltar → Med Spain
            (-5.5, 36.0), (-4.0, 36.5), (-2.0, 37.0), (0.0, 38.0),
            (1.0, 39.0), (2.0, 41.5), (3.0, 43.0),
            // French Riviera → Italy
            (5.0, 43.5), (7.5, 44.0), (9.0, 44.0), (10.0, 44.0),
            // Italy boot
            (12.0, 44.0), (13.5, 43.5), (14.0, 42.0), (15.5, 41.0),
            (16.0, 40.0), (16.0, 39.0), (15.5, 38.0), (16.0, 37.5),
            // Sicily tip
            (15.0, 37.0), (13.0, 37.0), (12.5, 38.0),
        ],
        // ── Europe: Balkans / Eastern Mediterranean ─────────────
        vec![
            (14.0, 45.5), (16.0, 45.0), (18.0, 43.0), (19.0, 42.0),
            (20.0, 40.0), (20.0, 39.0), (23.0, 38.0), (24.0, 37.0),
            (26.0, 38.0), (28.0, 37.0), (26.0, 40.0), (29.0, 41.0),
        ],
        // ── Europe: Black Sea coast ─────────────────────────────
        vec![
            (29.0, 41.0), (31.0, 42.0), (33.0, 42.0), (36.0, 42.5),
            (38.0, 42.0), (40.0, 43.0), (41.0, 42.0), (40.0, 41.0),
            (37.0, 41.5), (36.0, 41.5), (34.0, 42.0), (33.0, 44.0),
            (31.0, 46.0), (30.0, 46.5),
        ],
        // ── Africa: West coast ──────────────────────────────────
        vec![
            // Morocco → around the continent
            (-6.0, 35.5), (-6.0, 34.0), (-8.0, 32.0), (-10.0, 30.0),
            (-13.0, 27.5), (-16.0, 24.0), (-17.0, 21.0), (-16.0, 18.0),
            (-16.0, 15.0), (-17.0, 13.0), (-15.0, 11.0), (-13.0, 9.0),
            (-11.0, 7.0), (-8.0, 5.0), (-5.0, 5.0), (-3.0, 5.0),
            (1.0, 6.0), (3.0, 6.5), (5.0, 4.5), (7.0, 4.5),
            (9.0, 4.0), (10.0, 2.0), (9.5, 1.0), (9.0, 4.0),
            (10.0, 6.0), (12.0, 4.0), (14.0, 3.0), (16.0, 2.0),
            // Central / East Africa coast
            (18.0, -3.0), (20.0, -5.0), (25.0, -8.0), (30.0, -10.0),
            (33.0, -12.0), (35.0, -14.0), (37.0, -16.0), (40.0, -18.0),
            (41.0, -20.0),
            // Southeast Africa
            (36.0, -22.0), (35.0, -24.0), (33.0, -26.0), (32.0, -28.0),
            (30.0, -30.0), (28.0, -32.0), (27.0, -33.5),
            // South Africa → West coast return
            (25.0, -34.0), (22.0, -34.5), (19.0, -34.5), (18.0, -33.5),
            (17.0, -32.0), (16.0, -29.0), (15.0, -27.0), (13.0, -23.0),
            (12.0, -18.0), (12.0, -13.0), (11.0, -8.0), (12.0, -5.0),
            (10.0, -2.0), (9.5, 1.0),
        ],
        // ── Africa: East coast / Horn ───────────────────────────
        vec![
            // Red Sea → Horn of Africa → down to Mozambique
            (33.0, 30.0), (34.0, 28.0), (35.0, 25.0), (36.0, 22.0),
            (38.0, 18.0), (40.0, 15.0), (42.0, 13.0), (44.0, 11.0),
            (47.0, 9.0), (49.0, 8.0), (51.0, 11.0), (50.0, 5.0),
            (48.0, 2.0), (44.0, -1.0), (42.0, -2.0), (41.0, -5.0),
            (40.0, -10.0), (40.0, -15.0),
        ],
        // ── Asia: Turkey → Levant → Arabia ──────────────────────
        vec![
            (29.0, 41.0), (32.0, 40.0), (35.0, 39.0), (36.0, 37.0),
            (36.0, 35.0), (35.0, 33.0), (35.0, 31.0),
            // Sinai / Arabia west
            (34.0, 29.0), (33.0, 28.0), (34.0, 26.0), (38.0, 22.0),
            (42.0, 17.0), (43.0, 15.0), (44.0, 13.5),
        ],
        // ── Asia: Arabian Peninsula east → Iran → India ─────────
        vec![
            (44.0, 13.5), (46.0, 13.0), (48.0, 14.0), (52.0, 17.0),
            (55.0, 20.0), (56.0, 22.0), (56.5, 24.0), (56.0, 26.0),
            (51.0, 27.0), (50.0, 29.0), (48.0, 30.0), (48.0, 31.0),
            (50.0, 30.0), (52.0, 28.0), (54.0, 26.5), (57.0, 25.0),
            // Iran / Pakistan coast
            (58.0, 25.5), (60.0, 25.0), (62.0, 25.0), (65.0, 25.5),
            (67.0, 24.5), (68.0, 23.0),
            // India west coast
            (70.0, 22.0), (72.0, 20.0), (73.0, 17.0), (74.0, 14.0),
            (74.5, 12.0), (76.0, 10.0), (77.0, 8.0),
            // Sri Lanka tip → India east coast → Bangladesh
            (78.0, 8.5), (80.0, 7.0), (80.0, 9.0), (80.0, 12.0),
            (81.0, 14.0), (82.0, 16.0), (83.0, 18.0), (85.0, 20.0),
            (87.0, 22.0), (89.0, 22.0), (90.0, 22.0), (92.0, 21.0),
        ],
        // ── Asia: Southeast Asia mainland ───────────────────────
        vec![
            // Myanmar → Thailand → Malay Peninsula
            (92.0, 21.0), (95.0, 18.0), (97.0, 16.0), (98.0, 13.0),
            (99.0, 10.0), (100.0, 7.0), (101.0, 4.0), (103.0, 1.5),
            (104.0, 1.3),
        ],
        // ── Asia: Vietnam / China coast ─────────────────────────
        vec![
            (103.0, 10.0), (106.0, 11.0), (108.0, 12.0), (109.0, 14.0),
            (108.0, 16.0), (107.0, 18.0), (107.0, 20.0), (108.0, 21.5),
            (110.0, 21.0), (111.0, 20.0),
            // China coast north
            (113.0, 22.0), (114.0, 23.0), (117.0, 24.0), (118.0, 25.0),
            (120.0, 26.0), (121.0, 28.0), (122.0, 30.0), (121.0, 31.0),
            (122.0, 33.0), (120.0, 35.0), (119.0, 36.0), (121.0, 37.0),
            (122.0, 38.0), (121.0, 39.0), (118.0, 40.0),
            // NE China → Korea
            (120.0, 41.0), (122.0, 40.0), (124.0, 40.0), (126.0, 38.0),
            (127.0, 36.0), (127.0, 34.0), (129.0, 35.0), (130.0, 36.0),
        ],
        // ── Asia: Russian Far East ──────────────────────────────
        vec![
            (131.0, 43.0), (133.0, 43.5), (135.0, 45.0), (137.0, 47.0),
            (139.0, 48.0), (141.0, 47.0), (142.0, 50.0), (143.0, 52.0),
            (144.0, 55.0), (145.0, 58.0), (150.0, 59.0), (155.0, 58.0),
            (160.0, 60.0), (163.0, 62.0), (168.0, 64.0), (170.0, 65.0),
            (172.0, 65.0),
        ],
        // ── Japan ───────────────────────────────────────────────
        vec![
            // Kyushu → Honshu → Hokkaido
            (130.0, 32.0), (131.0, 33.0), (132.0, 34.0), (134.0, 34.0),
            (135.0, 35.0), (137.0, 35.0), (138.0, 35.5), (140.0, 36.0),
            (141.0, 38.0), (141.0, 40.0), (140.0, 41.0), (141.0, 42.0),
            (143.0, 43.0), (145.0, 44.0), (145.0, 45.0),
        ],
        // ── Australia ───────────────────────────────────────────
        vec![
            // Clockwise from NW
            (114.0, -22.0), (118.0, -20.0), (121.0, -18.0), (127.0, -14.0),
            (131.0, -12.0), (136.0, -12.0), (137.0, -14.0), (136.0, -16.0),
            (141.0, -13.0), (145.0, -15.0), (146.0, -18.0), (149.0, -21.0),
            (151.0, -24.0), (153.0, -27.0), (153.0, -30.0), (151.0, -33.0),
            (150.0, -36.0), (147.0, -38.0), (144.0, -38.5),
            // South coast
            (142.0, -38.0), (139.0, -37.0), (137.0, -35.5), (136.0, -35.0),
            (135.0, -35.5), (134.0, -34.0), (131.0, -32.0), (129.0, -32.0),
            (126.0, -33.0), (122.0, -34.0), (118.0, -34.5), (115.0, -34.0),
            (114.5, -32.0), (113.5, -28.0), (113.5, -25.0), (114.0, -22.0),
        ],
        // ── British Isles ───────────────────────────────────────
        vec![
            (-5.0, 50.0), (-5.5, 51.5), (-4.0, 53.0), (-3.0, 54.0),
            (-5.0, 55.0), (-5.5, 56.0), (-6.0, 57.5), (-5.0, 58.5),
            (-3.0, 58.5), (-2.0, 57.0), (-1.0, 55.0), (0.0, 53.0),
            (1.5, 52.0), (1.0, 51.0), (0.0, 51.0), (-1.0, 50.5),
            (-3.0, 50.5), (-5.0, 50.0),
        ],
        // ── Ireland ─────────────────────────────────────────────
        vec![
            (-6.5, 52.0), (-8.0, 51.5), (-10.0, 52.0), (-10.0, 53.5),
            (-9.5, 54.5), (-8.0, 55.0), (-7.0, 55.5), (-6.0, 54.5),
            (-6.0, 53.0), (-6.5, 52.0),
        ],
        // ── Greenland ───────────────────────────────────────────
        vec![
            (-50.0, 60.5), (-45.0, 60.0), (-42.0, 62.0), (-40.0, 64.0),
            (-35.0, 66.0), (-25.0, 70.0), (-20.0, 73.0), (-18.0, 76.0),
            (-22.0, 77.0), (-30.0, 77.5), (-40.0, 77.0), (-50.0, 76.0),
            (-55.0, 74.0), (-56.0, 70.0), (-55.0, 67.0), (-52.0, 63.0),
            (-50.0, 60.5),
        ],
        // ── Iceland ─────────────────────────────────────────────
        vec![
            (-22.0, 64.0), (-20.0, 63.5), (-16.0, 64.0), (-14.0, 65.0),
            (-14.0, 66.0), (-18.0, 66.5), (-22.0, 66.0), (-24.0, 65.0),
            (-22.0, 64.0),
        ],
        // ── Borneo ──────────────────────────────────────────────
        vec![
            (109.0, 1.0), (110.0, 2.0), (112.0, 2.5), (115.0, 4.5),
            (117.0, 6.5), (118.0, 5.0), (118.5, 2.0), (117.0, 0.5),
            (115.0, -1.0), (112.0, -2.0), (110.0, -1.5), (109.0, 1.0),
        ],
        // ── Sumatra ─────────────────────────────────────────────
        vec![
            (95.0, 5.5), (98.0, 4.0), (101.0, 1.0), (104.0, -1.5),
            (106.0, -5.0), (105.0, -6.0), (103.0, -4.0), (100.0, -1.0),
            (97.0, 2.0), (95.0, 5.5),
        ],
        // ── Java ────────────────────────────────────────────────
        vec![
            (106.0, -6.0), (108.0, -6.5), (110.0, -7.0), (112.0, -7.5),
            (114.0, -8.0), (114.0, -8.5), (112.0, -8.0), (110.0, -7.5),
            (108.0, -7.0), (106.0, -6.5),
        ],
        // ── New Zealand: North Island ───────────────────────────
        vec![
            (173.0, -35.0), (176.0, -37.0), (178.0, -38.5), (177.0, -40.0),
            (175.0, -41.5), (173.0, -40.0), (174.0, -38.0), (173.0, -35.0),
        ],
        // ── New Zealand: South Island ───────────────────────────
        vec![
            (170.0, -42.5), (172.0, -42.0), (173.5, -43.0), (172.0, -44.5),
            (170.0, -45.5), (168.0, -46.5), (167.0, -45.0), (168.0, -43.5),
            (170.0, -42.5),
        ],
        // ── Philippines ─────────────────────────────────────────
        vec![
            (119.0, 17.0), (121.0, 18.5), (122.0, 16.0), (124.0, 13.0),
            (126.0, 10.0), (125.0, 8.0), (123.0, 7.0), (121.0, 10.0),
            (120.0, 12.0), (119.0, 14.0), (119.0, 17.0),
        ],
        // ── Madagascar ──────────────────────────────────────────
        vec![
            (49.0, -12.0), (50.0, -15.0), (49.5, -18.0), (48.0, -21.0),
            (46.0, -24.0), (44.5, -25.0), (44.0, -22.0), (44.5, -18.0),
            (46.0, -15.0), (48.0, -13.0), (49.0, -12.0),
        ],
        // ── Russia: Arctic coast ────────────────────────────────
        vec![
            (28.0, 71.0), (33.0, 69.0), (40.0, 68.0), (44.0, 68.0),
            (50.0, 68.0), (55.0, 68.5), (60.0, 68.0), (65.0, 67.0),
            (70.0, 68.0), (73.0, 69.0), (77.0, 70.0), (80.0, 70.0),
            (85.0, 72.0), (90.0, 72.0), (95.0, 72.0), (100.0, 73.0),
            (105.0, 73.0), (110.0, 73.5), (115.0, 73.0), (120.0, 73.0),
            (125.0, 73.0), (130.0, 73.5), (135.0, 73.0), (140.0, 72.0),
            (150.0, 70.0), (160.0, 69.0), (170.0, 66.0), (172.0, 65.0),
        ],
    ]
}

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

    let mut canvas = BrailleCanvas::new(w, h);
    let px_w = canvas.px_width();
    let px_h = canvas.px_height();

    // ── Draw coastlines ─────────────────────────────────────────
    let coastlines = world_coastlines();
    for polyline in &coastlines {
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
                canvas.draw_line(prev.0, prev.1, cur.0, cur.1, COASTLINE);
            }
            prev = cur;
        }
    }

    // ── Draw dots ───────────────────────────────────────────────
    for dot in dots {
        let (px, py) = project(dot.lon, dot.lat, px_w, px_h);
        let (jx, jy) = ip_jitter(dot.jitter_seed);
        let cx = px + jx;
        let cy = py + jy;
        let r = dot.radius as i32;

        // Determine effective radius (pulsing effect)
        let effective_r = if dot.pulsing && animation_frame % 2 == 0 {
            r + 1
        } else {
            r
        };

        // Glow ring (outer, dimmed)
        let glow_color = dim_color(dot.color, 0.35);
        canvas.draw_filled_circle(cx, cy, effective_r + 1, glow_color);

        // Core circle (full color)
        canvas.draw_filled_circle(cx, cy, effective_r, dot.color);
    }

    // ── Render canvas to paragraph ──────────────────────────────
    let lines = canvas.render();
    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}
