use ratatui::style::{Color, Modifier, Style};

use crate::data::{PortRisk, TcpState};

// ─── Background / Chrome ──────────────────────────────────────────
pub const BG: Color = Color::Rgb(8, 12, 24);
pub const BORDER: Color = Color::Rgb(30, 50, 85);
pub const BORDER_HL: Color = Color::Rgb(50, 80, 130);

// ─── Text ─────────────────────────────────────────────────────────
pub const TEXT: Color = Color::Rgb(180, 190, 210);
pub const TEXT_DIM: Color = Color::Rgb(80, 90, 110);
pub const TEXT_MUTED: Color = Color::Rgb(55, 65, 85);
pub const TITLE: Color = Color::Rgb(160, 180, 220);

// ─── Semantic ─────────────────────────────────────────────────────
pub const SAFE: Color = Color::Rgb(80, 200, 120);
pub const GREEN: Color = Color::Rgb(80, 200, 120);
pub const WARN: Color = Color::Rgb(255, 200, 80);
pub const GOLD: Color = Color::Rgb(255, 200, 80);
pub const DANGER: Color = Color::Rgb(255, 60, 60);
pub const RED: Color = Color::Rgb(255, 60, 60);

// ─── Accent ───────────────────────────────────────────────────────
pub const ACCENT: Color = Color::Rgb(60, 140, 255);
pub const BLUE: Color = Color::Rgb(60, 140, 255);
pub const CYAN: Color = Color::Rgb(80, 200, 255);
pub const PURPLE: Color = Color::Rgb(180, 100, 255);

// ─── Attack ───────────────────────────────────────────────────────
pub const ATTACK: Color = Color::Rgb(255, 40, 40);

// ─── Bandwidth ────────────────────────────────────────────────────
pub const DOWNLOAD: Color = Color::Rgb(60, 140, 255);
pub const UPLOAD: Color = Color::Rgb(40, 200, 80);

// ─── Tabs ─────────────────────────────────────────────────────────
pub const TAB_BG: Color = Color::Rgb(18, 25, 45);
pub const TAB_ACTIVE_BG: Color = Color::Rgb(30, 42, 70);
pub const TAB_ACTIVE_FG: Color = Color::Rgb(255, 220, 120);

// ─── Misc ─────────────────────────────────────────────────────────
pub const SEPARATOR: Color = Color::Rgb(35, 50, 75);

// ─── Helper functions ─────────────────────────────────────────────

/// Map a 0-100 security score to a color.
pub fn score_color(score: u8) -> Color {
    match score {
        80..=100 => SAFE,
        60..=79 => GOLD,
        40..=59 => WARN,
        _ => DANGER,
    }
}

/// Color for a port risk level.
pub fn risk_color(risk: PortRisk) -> Color {
    match risk {
        PortRisk::Safe => SAFE,
        PortRisk::Exposed => WARN,
        PortRisk::Critical => DANGER,
    }
}

/// Color for a TCP connection state.
pub fn state_color(state: TcpState) -> Color {
    match state {
        TcpState::Established => SAFE,
        TcpState::Listen => ACCENT,
        TcpState::SynSent | TcpState::SynRecv => CYAN,
        TcpState::TimeWait | TcpState::FinWait1 | TcpState::FinWait2 => TEXT_DIM,
        TcpState::CloseWait | TcpState::LastAck | TcpState::Closing => GOLD,
        TcpState::Close => TEXT_MUTED,
        TcpState::Unknown => TEXT_DIM,
    }
}

/// Standard block style: dark background + dim border.
pub fn block_style() -> Style {
    Style::default().bg(BG).fg(BORDER)
}

/// Title style: highlighted text, bold.
pub fn title_style() -> Style {
    Style::default().fg(TITLE).add_modifier(Modifier::BOLD)
}
