pub mod procfs;
pub mod bandwidth;
pub mod connections;
pub mod ports;
pub mod processes;
pub mod attacks;
pub mod firewall;
pub mod fail2ban;
pub mod geoip;
pub mod threat;
pub mod system;
pub mod alerts;
pub mod protocols;
pub mod servers;
pub mod discovery;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use chrono::{DateTime, Utc};

// ─── Channel message type ──────────────────────────────────────────
/// All background threads send data to the main loop via this enum.
pub enum DataUpdate {
    Connections(Vec<Connection>),
    Bandwidth { rx_bps: f64, tx_bps: f64 },
    Attack(AttackEvent),
    BannedIps(HashSet<IpAddr>),
    FirewallRules(Vec<FirewallRule>, bool), // rules + default_deny
    DnsResolved(IpAddr, String),
}

// ─── Connection ────────────────────────────────────────────────────
#[derive(Clone, Debug)]
pub struct Connection {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: TcpState,
    pub protocol: Protocol,
    pub inode: u64,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub user: Option<String>,
    pub geo: Option<GeoLocation>,
    pub is_threat: bool,
    pub direction: Direction,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

impl TcpState {
    pub fn from_u8(n: u8) -> Self {
        match n {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            _ => Self::Unknown,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Established => "ESTABLISHED",
            Self::SynSent => "SYN_SENT",
            Self::SynRecv => "SYN_RECV",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::TimeWait => "TIME_WAIT",
            Self::Close => "CLOSE",
            Self::CloseWait => "CLOSE_WAIT",
            Self::LastAck => "LAST_ACK",
            Self::Listen => "LISTEN",
            Self::Closing => "CLOSING",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol { Tcp, Udp }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction { Inbound, Outbound, Local, Unknown }

// ─── Listening port ────────────────────────────────────────────────
#[derive(Clone, Debug)]
pub struct ListeningPort {
    pub port: u16,
    pub bind_addr: IpAddr,
    pub protocol: Protocol,
    pub pid: u32,
    pub process_name: String,
    pub user: String,
    pub conn_count: u32,
    pub bandwidth_bps: f64,
    pub risk: PortRisk,
    pub auth: AuthMethod,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortRisk { Safe, Exposed, Critical }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod { KeyAuth, PasswordAuth, JwtAuth, TokenAuth, NoAuth, Unknown }

impl AuthMethod {
    pub fn label(&self) -> &'static str {
        match self {
            Self::KeyAuth => "KEY",
            Self::PasswordAuth => "PASS",
            Self::JwtAuth => "JWT",
            Self::TokenAuth => "TOKEN",
            Self::NoAuth => "NONE",
            Self::Unknown => "?",
        }
    }
}

impl PortRisk {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Safe => "SAFE",
            Self::Exposed => "EXPOSED",
            Self::Critical => "CRITICAL",
        }
    }
}

// ─── Attacks ───────────────────────────────────────────────────────
#[derive(Clone, Debug)]
pub struct AttackEvent {
    pub timestamp: DateTime<Utc>,
    pub source_ip: IpAddr,
    pub attack_type: AttackType,
    pub target_port: Option<u16>,
    pub username: Option<String>,
    pub count: u32, // aggregated attempt count
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttackType {
    SshBrute,
    PortScan,
    HttpProbe,
    SmtpProbe,
    Other,
}

impl AttackType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SshBrute => "SSH Brute",
            Self::PortScan => "Port Scan",
            Self::HttpProbe => "HTTP Probe",
            Self::SmtpProbe => "SMTP Probe",
            Self::Other => "Other",
        }
    }
}

// ─── GeoIP ─────────────────────────────────────────────────────────
#[derive(Clone, Debug, Default)]
pub struct GeoLocation {
    pub country_code: String,
    pub country_name: String,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
}

// ─── Firewall ──────────────────────────────────────────────────────
#[derive(Clone, Debug)]
pub struct FirewallRule {
    pub index: usize,
    pub action: FirewallAction,
    pub direction: FirewallDirection,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub source: Option<String>,
    pub comment: String,
    pub hits: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallAction { Allow, Deny, Reject }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallDirection { In, Out, Both }

// ─── System info ───────────────────────────────────────────────────
#[derive(Clone, Debug, Default)]
pub struct CpuInfo {
    pub cores: Vec<CpuCore>,
    pub load_avg: (f64, f64, f64),
}

#[derive(Clone, Debug, Default)]
pub struct CpuCore {
    pub id: usize,
    pub usage_percent: f32,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryInfo {
    pub total: u64,
    pub used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
}

#[derive(Clone, Debug)]
pub struct DiskInfo {
    pub mount: String,
    pub total: u64,
    pub used: u64,
}

#[derive(Clone, Debug)]
pub struct ServiceStatus {
    pub name: String,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub speed_mbps: Option<u64>,
    pub up: bool,
}

// ─── Ring buffer for sparklines/charts ─────────────────────────────
#[derive(Clone, Debug)]
pub struct RingBuffer<T: Clone + Default> {
    buf: Vec<T>,
    capacity: usize,
    head: usize,
    len: usize,
}

impl<T: Clone + Default> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![T::default(); capacity],
            capacity,
            head: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, item: T) {
        self.buf[self.head] = item;
        self.head = (self.head + 1) % self.capacity;
        if self.len < self.capacity {
            self.len += 1;
        }
    }

    /// Returns items oldest-first
    pub fn as_slice_ordered(&self) -> Vec<&T> {
        let start = if self.len < self.capacity {
            0
        } else {
            self.head
        };
        let mut result = Vec::with_capacity(self.len);
        for i in 0..self.len {
            let idx = (start + i) % self.capacity;
            result.push(&self.buf[idx]);
        }
        result
    }

    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
    pub fn capacity(&self) -> usize { self.capacity }

    pub fn last(&self) -> Option<&T> {
        if self.len == 0 { return None; }
        let idx = if self.head == 0 { self.capacity - 1 } else { self.head - 1 };
        Some(&self.buf[idx])
    }
}
