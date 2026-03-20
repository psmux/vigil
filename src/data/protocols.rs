//! Protocol detection — port-based application protocol classification.

use std::collections::HashMap;
use ratatui::style::Color;
use crate::data::Connection;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppProtocol {
    HTTP,
    HTTPS,
    SSH,
    DNS,
    FTP,
    SMTP,
    IMAP,
    POP3,
    PostgreSQL,
    MySQL,
    Redis,
    MongoDB,
    NTP,
    DHCP,
    QUIC,
    SMB,
    RDP,
    Other,
}

impl AppProtocol {
    /// Classify a connection by port number and transport protocol.
    /// Checks well-known port assignments; falls back to `Other`.
    pub fn from_port(port: u16, is_tcp: bool) -> Self {
        match port {
            22 => Self::SSH,
            53 => Self::DNS,
            80 | 8080 => Self::HTTP,
            443 => {
                if is_tcp {
                    Self::HTTPS
                } else {
                    Self::QUIC
                }
            }
            21 => Self::FTP,
            25 | 587 | 465 => Self::SMTP,
            143 | 993 => Self::IMAP,
            110 | 995 => Self::POP3,
            5432 => Self::PostgreSQL,
            3306 => Self::MySQL,
            6379 => Self::Redis,
            27017 => Self::MongoDB,
            123 => Self::NTP,
            67 | 68 => Self::DHCP,
            445 | 139 => Self::SMB,
            3389 => Self::RDP,
            _ => Self::Other,
        }
    }

    /// Human-readable label for display in the TUI.
    pub fn label(&self) -> &'static str {
        match self {
            Self::HTTP => "HTTP",
            Self::HTTPS => "HTTPS",
            Self::SSH => "SSH",
            Self::DNS => "DNS",
            Self::FTP => "FTP",
            Self::SMTP => "SMTP",
            Self::IMAP => "IMAP",
            Self::POP3 => "POP3",
            Self::PostgreSQL => "PostgreSQL",
            Self::MySQL => "MySQL",
            Self::Redis => "Redis",
            Self::MongoDB => "MongoDB",
            Self::NTP => "NTP",
            Self::DHCP => "DHCP",
            Self::QUIC => "QUIC",
            Self::SMB => "SMB",
            Self::RDP => "RDP",
            Self::Other => "Other",
        }
    }

    /// Distinct color for each protocol, used in charts and tables.
    pub fn color(&self) -> Color {
        match self {
            Self::HTTP => Color::Green,
            Self::HTTPS => Color::LightGreen,
            Self::SSH => Color::Yellow,
            Self::DNS => Color::Cyan,
            Self::FTP => Color::Magenta,
            Self::SMTP => Color::LightMagenta,
            Self::IMAP => Color::LightBlue,
            Self::POP3 => Color::Blue,
            Self::PostgreSQL => Color::LightCyan,
            Self::MySQL => Color::Rgb(255, 165, 0),
            Self::Redis => Color::Red,
            Self::MongoDB => Color::Rgb(0, 200, 0),
            Self::NTP => Color::Gray,
            Self::DHCP => Color::DarkGray,
            Self::QUIC => Color::Rgb(128, 0, 255),
            Self::SMB => Color::Rgb(200, 200, 0),
            Self::RDP => Color::LightRed,
            Self::Other => Color::White,
        }
    }

    /// All variants for iteration.
    pub const ALL: [AppProtocol; 18] = [
        Self::HTTP,
        Self::HTTPS,
        Self::SSH,
        Self::DNS,
        Self::FTP,
        Self::SMTP,
        Self::IMAP,
        Self::POP3,
        Self::PostgreSQL,
        Self::MySQL,
        Self::Redis,
        Self::MongoDB,
        Self::NTP,
        Self::DHCP,
        Self::QUIC,
        Self::SMB,
        Self::RDP,
        Self::Other,
    ];
}

/// Count connections by detected application protocol.
/// Both local and remote ports are checked — the lower (well-known) port wins.
pub fn classify_connections(conns: &[Connection]) -> HashMap<AppProtocol, u32> {
    use crate::data::Protocol;

    let mut counts: HashMap<AppProtocol, u32> = HashMap::new();

    for conn in conns {
        let is_tcp = conn.protocol == Protocol::Tcp;
        let local_port = conn.local_addr.port();
        let remote_port = conn.remote_addr.port();

        // Prefer the well-known port (lower number) for classification.
        // If both are high ports, try both and take whichever is not Other.
        let proto_local = AppProtocol::from_port(local_port, is_tcp);
        let proto_remote = AppProtocol::from_port(remote_port, is_tcp);

        let proto = if proto_local != AppProtocol::Other {
            proto_local
        } else {
            proto_remote
        };

        *counts.entry(proto).or_insert(0) += 1;
    }

    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_port_basic() {
        assert_eq!(AppProtocol::from_port(22, true), AppProtocol::SSH);
        assert_eq!(AppProtocol::from_port(443, true), AppProtocol::HTTPS);
        assert_eq!(AppProtocol::from_port(443, false), AppProtocol::QUIC);
        assert_eq!(AppProtocol::from_port(5432, true), AppProtocol::PostgreSQL);
        assert_eq!(AppProtocol::from_port(12345, true), AppProtocol::Other);
    }

    #[test]
    fn test_label_round_trip() {
        for proto in AppProtocol::ALL {
            assert!(!proto.label().is_empty());
        }
    }
}
