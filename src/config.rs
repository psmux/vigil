/// Minimal configuration for Vigil.
pub struct VigilConfig {
    pub tick_rate_ms: u64,
    pub auth_log_path: String,
    pub default_view: u8,
}

impl Default for VigilConfig {
    fn default() -> Self {
        Self {
            tick_rate_ms: 1000,
            auth_log_path: "/var/log/auth.log".into(),
            default_view: 0,
        }
    }
}

/// Load configuration. Returns defaults for now.
pub fn load() -> VigilConfig {
    VigilConfig::default()
}
