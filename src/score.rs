use crate::app::App;
use crate::data::PortRisk;

/// A single factor contributing to the security score.
pub struct ScoreFactor {
    pub name: &'static str,
    pub max_points: u8,
    pub actual_points: u8,
    pub detail: String,
}

/// Compute the overall security score (0-100) and individual factor breakdown.
///
/// Starts at 100 and applies deductions, then adds earned points from
/// positive factors, clamped to 0-100.
pub fn compute_score(app: &App) -> (u8, Vec<ScoreFactor>) {
    let mut factors: Vec<ScoreFactor> = Vec::new();

    // ── Dangerous ports: -25 each (up to -100) ───────────────────
    let dangerous = [21, 23, 3389, 5900, 1433, 3306];
    let dangerous_open: Vec<u16> = app
        .ports
        .iter()
        .filter(|p| dangerous.contains(&p.port) && p.risk == PortRisk::Critical)
        .map(|p| p.port)
        .collect();
    let dangerous_deduction = (dangerous_open.len() as u8).saturating_mul(25).min(100);
    factors.push(ScoreFactor {
        name: "dangerous_ports",
        max_points: 0, // deduction factor
        actual_points: dangerous_deduction,
        detail: if dangerous_open.is_empty() {
            "No dangerous ports exposed".into()
        } else {
            format!("Dangerous ports open: {:?}", dangerous_open)
        },
    });

    // ── Firewall: +20 if active with default deny ────────────────
    let firewall_pts = if app.firewall_active && app.firewall_default_deny {
        20
    } else if app.firewall_active {
        10
    } else {
        0
    };
    factors.push(ScoreFactor {
        name: "firewall",
        max_points: 20,
        actual_points: firewall_pts,
        detail: if !app.firewall_active {
            "No firewall detected".into()
        } else if app.firewall_default_deny {
            "Firewall active, default deny".into()
        } else {
            "Firewall active but default allow".into()
        },
    });

    // ── SSH hardening: +15 if SSH uses key auth, not password ────
    let ssh_port = app.ports.iter().find(|p| p.port == 22);
    let ssh_pts = match ssh_port {
        Some(p) => {
            use crate::data::AuthMethod;
            match p.auth {
                AuthMethod::KeyAuth => 15,
                AuthMethod::PasswordAuth => 5,
                _ => 8,
            }
        }
        None => 15, // no SSH exposed = safe
    };
    factors.push(ScoreFactor {
        name: "ssh_hardening",
        max_points: 15,
        actual_points: ssh_pts,
        detail: match ssh_port {
            Some(p) => format!("SSH auth: {}", p.auth.label()),
            None => "SSH not exposed".into(),
        },
    });

    // ── Exposure: -3 per 0.0.0.0 listening port ─────────────────
    let wildcard_count = app
        .ports
        .iter()
        .filter(|p| p.bind_addr.is_unspecified())
        .count();
    let exposure_deduction = (wildcard_count as u8).saturating_mul(3).min(30);
    factors.push(ScoreFactor {
        name: "exposure",
        max_points: 0,
        actual_points: exposure_deduction,
        detail: format!("{} port(s) bound to 0.0.0.0", wildcard_count),
    });

    // ── Threat connections: -2 each ──────────────────────────────
    let threat_count = app.connections.iter().filter(|c| c.is_threat).count();
    let threat_deduction = (threat_count as u8).saturating_mul(2).min(30);
    factors.push(ScoreFactor {
        name: "threat_conns",
        max_points: 0,
        actual_points: threat_deduction,
        detail: format!("{} active threat connection(s)", threat_count),
    });

    // ── Root services: -2 each ───────────────────────────────────
    let root_count = app
        .ports
        .iter()
        .filter(|p| p.user == "root")
        .count();
    let root_deduction = (root_count as u8).saturating_mul(2).min(20);
    factors.push(ScoreFactor {
        name: "root_services",
        max_points: 0,
        actual_points: root_deduction,
        detail: format!("{} service(s) running as root", root_count),
    });

    // ── Auth coverage: +5 if all ports have known auth ───────────
    let all_have_auth = !app.ports.is_empty()
        && app.ports.iter().all(|p| {
            !matches!(p.auth, crate::data::AuthMethod::NoAuth | crate::data::AuthMethod::Unknown)
        });
    let auth_pts = if all_have_auth { 5 } else { 0 };
    factors.push(ScoreFactor {
        name: "auth_coverage",
        max_points: 5,
        actual_points: auth_pts,
        detail: if all_have_auth {
            "All ports have authentication".into()
        } else {
            "Some ports lack authentication".into()
        },
    });

    // ── Tally ────────────────────────────────────────────────────
    // Start at 100, add earned points from positive factors, subtract deductions.
    // Positive factors: firewall(20) + ssh(15) + auth(5) = 40
    // We start at a base of 60, then add positive points, subtract deductions.
    let base: i16 = 60;
    let earned: i16 = (firewall_pts + ssh_pts + auth_pts) as i16;
    let deductions: i16 =
        (dangerous_deduction + exposure_deduction + threat_deduction + root_deduction) as i16;

    let score = (base + earned - deductions).clamp(0, 100) as u8;

    (score, factors)
}
