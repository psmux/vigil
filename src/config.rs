/// Packet capture strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureMode {
    /// Try AF_PACKET first, fall back to /proc polling.
    Auto,
    /// Require AF_PACKET (exit if unavailable).
    PacketCapture,
    /// Force /proc/net polling only.
    ProcOnly,
}

/// Minimal configuration for Vigil.
pub struct VigilConfig {
    pub tick_rate_ms: u64,
    pub auth_log_path: String,
    pub default_view: u8,
    pub capture_mode: CaptureMode,
    pub capture_interface: Option<String>,
}

impl Default for VigilConfig {
    fn default() -> Self {
        Self {
            tick_rate_ms: 1000,
            auth_log_path: "/var/log/auth.log".into(),
            default_view: 0,
            capture_mode: CaptureMode::Auto,
            capture_interface: None,
        }
    }
}

/// Load configuration. Returns defaults for now.
pub fn load() -> VigilConfig {
    VigilConfig::default()
}
