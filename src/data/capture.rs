//! AF_PACKET capture engine — real packet-level capture for accurate
//! per-connection bandwidth, true direction detection, and consistent data.
//!
//! On Linux with root/CAP_NET_RAW: uses AF_PACKET for real-time packet capture.
//! On non-Linux or without permissions: falls back to /proc/net polling.
//!
//! The output is always `Vec<Connection>` via the same `DataUpdate::Connections`
//! channel — downstream code (WireTracker, SignalTracker, etc.) doesn't care
//! which capture method produced the data. The difference is data quality:
//! packet capture provides real per-flow bandwidth and SYN-based direction,
//! while /proc provides only estimates.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::data::{CaptureSource, Connection, DataUpdate, Direction, Protocol, TcpState};

// ─── TCP flag constants ──────────────────────────────────────────

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

// ─── Packet stats (sent via DataUpdate channel) ──────────────────

/// Capture engine statistics for the status bar and diagnostics.
#[derive(Clone, Debug, Default)]
pub struct PacketStats {
    /// Whether AF_PACKET capture is active (vs /proc-only fallback).
    pub capture_active: bool,
    /// Total packets captured since engine start.
    pub packets_captured: u64,
    /// Packets dropped by kernel (socket buffer overflow).
    pub packets_dropped: u64,
    /// Number of active flows being tracked.
    pub flows_active: usize,
}

// ─── Parsed packet (intermediate representation) ─────────────────

struct ParsedPacket {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: Protocol,
    tcp_flags: u8,
    payload_len: u32,
}

// ─── Packet parsing ─────────────────────────────────────────────
//
// Parses raw Ethernet frames into structured packet data.
// Handles IPv4, IPv6, VLAN tagging (802.1Q/802.1AD), TCP, UDP, ICMP.
// Returns None for unparseable or non-IP frames (ARP, etc.).

fn parse_packet(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 14 {
        return None;
    }

    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);

    // Skip VLAN tags (802.1Q = 0x8100, 802.1AD = 0x88A8)
    while (ethertype == 0x8100 || ethertype == 0x88A8) && data.len() >= offset + 4 {
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    match ethertype {
        0x0800 => parse_ipv4(data.get(offset..)?),
        0x86DD => parse_ipv6(data.get(offset..)?),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 20 {
        return None;
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }

    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let ip_proto = data[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

    let ip_payload_len = total_len.saturating_sub(ihl);
    parse_transport(data.get(ihl..)?, ip_proto, src_ip, dst_ip, ip_payload_len)
}

fn parse_ipv6(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 40 {
        return None;
    }

    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let next_header = data[6];

    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    dst_bytes.copy_from_slice(&data[24..40]);

    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    // Simplified: treats next_header as transport protocol directly.
    // Does not chase IPv6 extension headers — acceptable for TCP/UDP/ICMP.
    parse_transport(data.get(40..)?, next_header, src_ip, dst_ip, payload_len)
}

fn parse_transport(
    data: &[u8],
    ip_proto: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_payload_len: usize,
) -> Option<ParsedPacket> {
    match ip_proto {
        6 => parse_tcp(data, src_ip, dst_ip, ip_payload_len),
        17 => parse_udp(data, src_ip, dst_ip, ip_payload_len),
        1 | 58 => parse_icmp(src_ip, dst_ip, ip_payload_len),
        _ => Some(ParsedPacket {
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Raw,
            tcp_flags: 0,
            payload_len: ip_payload_len as u32,
        }),
    }
}

fn parse_tcp(
    data: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_payload_len: usize,
) -> Option<ParsedPacket> {
    if data.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let data_offset = ((data[12] >> 4) & 0x0F) as usize * 4;
    let tcp_flags = data[13];
    let payload_len = ip_payload_len.saturating_sub(data_offset);

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: Protocol::Tcp,
        tcp_flags,
        payload_len: payload_len as u32,
    })
}

fn parse_udp(
    data: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_payload_len: usize,
) -> Option<ParsedPacket> {
    if data.len() < 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let payload_len = ip_payload_len.saturating_sub(8);

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: Protocol::Udp,
        tcp_flags: 0,
        payload_len: payload_len as u32,
    })
}

fn parse_icmp(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_payload_len: usize,
) -> Option<ParsedPacket> {
    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port: 0,
        dst_port: 0,
        protocol: Protocol::Icmp,
        tcp_flags: 0,
        payload_len: ip_payload_len as u32,
    })
}

// ─── Flow tracking ──────────────────────────────────────────────
//
// Aggregates raw packets into bidirectional flows keyed by a canonical
// 5-tuple (endpoints sorted for direction-independence). Each flow tracks
// byte counts in both directions, packet counts, and SYN source for
// accurate TCP direction detection.

/// Deterministic ordering key for SocketAddr (SocketAddr doesn't impl Ord).
fn addr_ord(a: &SocketAddr) -> (u128, u16) {
    match a {
        SocketAddr::V4(v4) => (u32::from(*v4.ip()) as u128, v4.port()),
        SocketAddr::V6(v6) => (u128::from(*v6.ip()), v6.port()),
    }
}

/// Canonical 5-tuple flow key — endpoints sorted so both directions
/// of the same connection map to the same key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    /// "Lower" endpoint (by addr_ord).
    ep_a: SocketAddr,
    /// "Higher" endpoint.
    ep_b: SocketAddr,
    protocol: Protocol,
}

impl FlowKey {
    fn new(src: SocketAddr, dst: SocketAddr, proto: Protocol) -> Self {
        if addr_ord(&src) <= addr_ord(&dst) {
            Self {
                ep_a: src,
                ep_b: dst,
                protocol: proto,
            }
        } else {
            Self {
                ep_a: dst,
                ep_b: src,
                protocol: proto,
            }
        }
    }
}

/// Per-flow byte and packet counters.
struct FlowEntry {
    /// Bytes from ep_a → ep_b in current interval.
    bytes_a_to_b: u64,
    /// Bytes from ep_b → ep_a in current interval.
    bytes_b_to_a: u64,
    /// Total bytes ep_a → ep_b since flow started.
    total_bytes_a_to_b: u64,
    /// Total bytes ep_b → ep_a since flow started.
    total_bytes_b_to_a: u64,
    /// Total packets since flow started.
    total_packets: u32,
    /// Who sent the first SYN (TCP only — for direction detection).
    syn_source: Option<SocketAddr>,
    /// Last packet timestamp (for stale-flow eviction).
    last_seen: Instant,
}

/// Snapshot emitted at each interval for merging with procfs data.
struct FlowSnapshot {
    key: FlowKey,
    bps_a_to_b: f64,
    bps_b_to_a: f64,
    total_bytes_a_to_b: u64,
    total_bytes_b_to_a: u64,
    packet_count: u32,
    syn_source: Option<SocketAddr>,
}

/// Aggregates raw packets into bidirectional flows.
struct FlowTable {
    flows: HashMap<FlowKey, FlowEntry>,
    packets_captured: u64,
}

impl FlowTable {
    fn new() -> Self {
        Self {
            flows: HashMap::with_capacity(1024),
            packets_captured: 0,
        }
    }

    /// Process a single parsed packet into the flow table.
    fn process(&mut self, pkt: &ParsedPacket) {
        self.packets_captured += 1;

        let src = SocketAddr::new(pkt.src_ip, pkt.src_port);
        let dst = SocketAddr::new(pkt.dst_ip, pkt.dst_port);
        let key = FlowKey::new(src, dst, pkt.protocol);

        // Determine direction relative to canonical key ordering
        let is_a_to_b = addr_ord(&src) <= addr_ord(&dst);

        let now = Instant::now();
        let entry = self.flows.entry(key).or_insert_with(|| FlowEntry {
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            total_bytes_a_to_b: 0,
            total_bytes_b_to_a: 0,
            total_packets: 0,
            syn_source: None,
            last_seen: now,
        });

        let bytes = pkt.payload_len as u64;
        if is_a_to_b {
            entry.bytes_a_to_b += bytes;
            entry.total_bytes_a_to_b += bytes;
        } else {
            entry.bytes_b_to_a += bytes;
            entry.total_bytes_b_to_a += bytes;
        }

        entry.total_packets += 1;
        entry.last_seen = now;

        // Record who sent the first SYN (pure SYN, not SYN-ACK)
        if pkt.tcp_flags & TCP_SYN != 0 && pkt.tcp_flags & TCP_ACK == 0 {
            if entry.syn_source.is_none() {
                entry.syn_source = Some(src);
            }
        }
    }

    /// Snapshot all flows, reset interval counters, evict stale flows.
    fn snapshot_and_reset(&mut self, elapsed_secs: f64) -> Vec<FlowSnapshot> {
        // Evict flows with no activity for 5 minutes
        let stale = Duration::from_secs(300);
        self.flows.retain(|_, e| e.last_seen.elapsed() < stale);

        let mut snaps = Vec::with_capacity(self.flows.len());
        for (key, entry) in &mut self.flows {
            snaps.push(FlowSnapshot {
                key: key.clone(),
                bps_a_to_b: entry.bytes_a_to_b as f64 / elapsed_secs,
                bps_b_to_a: entry.bytes_b_to_a as f64 / elapsed_secs,
                total_bytes_a_to_b: entry.total_bytes_a_to_b,
                total_bytes_b_to_a: entry.total_bytes_b_to_a,
                packet_count: entry.total_packets,
                syn_source: entry.syn_source,
            });
            // Reset interval counters (totals persist)
            entry.bytes_a_to_b = 0;
            entry.bytes_b_to_a = 0;
        }
        snaps
    }
}

// ─── Merge: flow table + procfs → enriched connections ──────────
//
// The key insight: we call the existing `collect_connections()` to get
// the full connection list with PIDs, GeoIP, threat flags, etc.
// Then we overlay real bandwidth data from the flow table.
// This avoids re-implementing the entire enrichment pipeline.

/// Collect local IPs from the current connection table for direction detection.
fn collect_local_ips(connections: &[Connection]) -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    for conn in connections {
        let ip = conn.local_addr.ip();
        if !ip.is_unspecified() {
            ips.insert(ip);
        }
    }
    ips
}

/// Merge flow table snapshots onto procfs-based connections.
/// Provides real per-connection bandwidth and SYN-based direction.
fn merge_connections(
    connections: &mut [Connection],
    snapshots: &[FlowSnapshot],
    local_ips: &HashSet<IpAddr>,
) {
    // Build lookup: FlowKey → snapshot
    let flow_map: HashMap<&FlowKey, &FlowSnapshot> =
        snapshots.iter().map(|s| (&s.key, s)).collect();

    for conn in connections.iter_mut() {
        let key = FlowKey::new(conn.local_addr, conn.remote_addr, conn.protocol);
        if let Some(snap) = flow_map.get(&key) {
            // Determine which canonical endpoint is "local"
            let local_is_a = addr_ord(&conn.local_addr) <= addr_ord(&conn.remote_addr);

            if local_is_a {
                // local = ep_a, remote = ep_b
                conn.rx_bps = snap.bps_b_to_a; // remote→local = receive
                conn.tx_bps = snap.bps_a_to_b; // local→remote = transmit
                conn.rx_bytes_total = snap.total_bytes_b_to_a;
                conn.tx_bytes_total = snap.total_bytes_a_to_b;
            } else {
                // local = ep_b, remote = ep_a
                conn.rx_bps = snap.bps_a_to_b;
                conn.tx_bps = snap.bps_b_to_a;
                conn.rx_bytes_total = snap.total_bytes_a_to_b;
                conn.tx_bytes_total = snap.total_bytes_b_to_a;
            }

            conn.packet_count = snap.packet_count;
            conn.capture_source = CaptureSource::PacketCapture;

            // Override direction with SYN-based detection when available
            if let Some(syn_src) = snap.syn_source {
                let remote_ip = conn.remote_addr.ip();
                if !remote_ip.is_unspecified()
                    && !remote_ip.is_loopback()
                    && conn.state != TcpState::Listen
                {
                    if local_ips.contains(&syn_src.ip()) {
                        conn.direction = Direction::Outbound;
                    } else {
                        conn.direction = Direction::Inbound;
                    }
                }
            }
        }
    }
}

// ─── AF_PACKET capture engine (Linux only) ──────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

    const ETH_P_ALL: u16 = 0x0003;
    const EMIT_INTERVAL: Duration = Duration::from_secs(2);
    const RECV_BUF_SIZE: usize = 65536;
    const SOCKET_BUF_BYTES: libc::c_int = 4 * 1024 * 1024; // 4 MB receive buffer

    /// Try to open an AF_PACKET raw socket.
    /// Returns None if permissions are insufficient or AF_PACKET unavailable.
    pub fn try_open(interface: Option<&str>) -> Option<OwnedFd> {
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                (ETH_P_ALL).to_be() as libc::c_int,
            )
        };

        if raw_fd < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("vigil: cannot open AF_PACKET socket: {}", err);
            return None;
        }

        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // Increase receive buffer to handle bursts during emit phase
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &SOCKET_BUF_BYTES as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // Bind to specific interface if requested
        if let Some(iface) = interface {
            let ifindex = unsafe {
                let c_name = std::ffi::CString::new(iface).ok()?;
                libc::if_nametoindex(c_name.as_ptr())
            };
            if ifindex == 0 {
                eprintln!("vigil: unknown interface '{}'", iface);
                return None;
            }

            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = (ETH_P_ALL).to_be();
            sll.sll_ifindex = ifindex as i32;

            let ret = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("vigil: cannot bind to '{}': {}", iface, err);
                return None;
            }
        }

        Some(fd)
    }

    /// Run the capture loop. This function never returns.
    pub fn run(fd: OwnedFd, tx: mpsc::Sender<DataUpdate>) -> ! {
        let raw_fd = fd.as_raw_fd();
        let mut flow_table = FlowTable::new();
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        let mut last_emit = Instant::now();

        eprintln!("vigil: AF_PACKET capture active");

        // Signal capture mode to the app
        let _ = tx.send(DataUpdate::PacketStats(PacketStats {
            capture_active: true,
            ..Default::default()
        }));

        loop {
            // Calculate poll timeout — time until next emission
            let elapsed = last_emit.elapsed();
            let timeout_ms = if elapsed >= EMIT_INTERVAL {
                0
            } else {
                (EMIT_INTERVAL - elapsed).as_millis() as libc::c_int
            };

            // Wait for packets or timeout
            let mut pfd = libc::pollfd {
                fd: raw_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms.max(1)) };

            // Drain all available packets from the socket
            if poll_ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
                loop {
                    let n = unsafe {
                        libc::recv(
                            raw_fd,
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                            0,
                        )
                    };
                    if n <= 0 {
                        break; // EAGAIN (non-blocking, no more data) or error
                    }
                    if let Some(pkt) = parse_packet(&buf[..n as usize]) {
                        flow_table.process(&pkt);
                    }
                }
            }

            // Emit enriched connections on interval
            if last_emit.elapsed() >= EMIT_INTERVAL {
                let elapsed_secs = last_emit.elapsed().as_secs_f64().max(0.001);
                let snapshots = flow_table.snapshot_and_reset(elapsed_secs);

                // Get base connections from /proc (PIDs, GeoIP, threats, etc.)
                let mut connections = crate::data::connections::collect_connections();
                let local_ips = collect_local_ips(&connections);

                // Overlay real bandwidth and direction from packet capture
                merge_connections(&mut connections, &snapshots, &local_ips);

                let stats = PacketStats {
                    capture_active: true,
                    packets_captured: flow_table.packets_captured,
                    packets_dropped: 0,
                    flows_active: flow_table.flows.len(),
                };

                let _ = tx.send(DataUpdate::Connections(connections));
                let _ = tx.send(DataUpdate::PacketStats(stats));

                last_emit = Instant::now();
            }
        }
    }
}

// ─── Fallback: /proc-only polling ───────────────────────────────

fn run_procfs_fallback(tx: mpsc::Sender<DataUpdate>) -> ! {
    loop {
        let conns = crate::data::connections::collect_connections();
        let _ = tx.send(DataUpdate::Connections(conns));
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ─── Public entry point ─────────────────────────────────────────

/// Run the capture thread. On Linux with sufficient permissions, uses
/// AF_PACKET for real packet capture. Otherwise falls back to /proc polling.
/// This function never returns — it runs an infinite capture/poll loop.
pub fn run_capture_thread(
    tx: mpsc::Sender<DataUpdate>,
    _interface: Option<&str>,
) {
    #[cfg(target_os = "linux")]
    {
        if let Some(fd) = linux::try_open(_interface) {
            linux::run(fd, tx); // never returns
        }
        eprintln!("vigil: falling back to /proc/net polling");
    }

    run_procfs_fallback(tx);
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_tcp_syn() {
        // Ethernet + IPv4 + TCP SYN packet
        // Dst MAC: ff:ff:ff:ff:ff:ff, Src MAC: 00:00:00:00:00:00
        // EtherType: 0x0800 (IPv4)
        // IPv4: 192.168.1.100:12345 → 93.184.216.34:443, TCP SYN
        #[rustfmt::skip]
        let pkt: Vec<u8> = vec![
            // Ethernet header (14 bytes)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src mac
            0x08, 0x00,                         // ethertype: IPv4
            // IPv4 header (20 bytes, IHL=5)
            0x45, 0x00, 0x00, 0x28,             // ver/ihl, tos, total_len=40
            0x00, 0x01, 0x00, 0x00,             // id, flags/frag
            0x40, 0x06, 0x00, 0x00,             // ttl=64, proto=TCP, checksum
            0xc0, 0xa8, 0x01, 0x64,             // src: 192.168.1.100
            0x5d, 0xb8, 0xd8, 0x22,             // dst: 93.184.216.34
            // TCP header (20 bytes)
            0x30, 0x39, 0x01, 0xBB,             // src_port=12345, dst_port=443
            0x00, 0x00, 0x00, 0x01,             // seq=1
            0x00, 0x00, 0x00, 0x00,             // ack=0
            0x50, 0x02, 0xFF, 0xFF,             // data_offset=5, flags=SYN, window
            0x00, 0x00, 0x00, 0x00,             // checksum, urgent
        ];

        let parsed = parse_packet(&pkt).expect("should parse");
        assert_eq!(
            parsed.src_ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
        );
        assert_eq!(
            parsed.dst_ip,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.protocol, Protocol::Tcp);
        assert_ne!(parsed.tcp_flags & TCP_SYN, 0);
        assert_eq!(parsed.tcp_flags & TCP_ACK, 0); // pure SYN, not SYN-ACK
    }

    #[test]
    fn test_parse_udp() {
        #[rustfmt::skip]
        let pkt: Vec<u8> = vec![
            // Ethernet
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00,
            // IPv4 (IHL=5, total_len=28, proto=UDP)
            0x45, 0x00, 0x00, 0x1C,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00,             // proto=17=UDP
            0x0A, 0x00, 0x00, 0x01,             // 10.0.0.1
            0x08, 0x08, 0x08, 0x08,             // 8.8.8.8
            // UDP (8 bytes)
            0xC0, 0x00, 0x00, 0x35,             // src=49152, dst=53
            0x00, 0x08, 0x00, 0x00,             // len=8, checksum
        ];

        let parsed = parse_packet(&pkt).expect("should parse UDP");
        assert_eq!(parsed.protocol, Protocol::Udp);
        assert_eq!(parsed.src_port, 49152);
        assert_eq!(parsed.dst_port, 53);
    }

    #[test]
    fn test_parse_vlan_tagged() {
        #[rustfmt::skip]
        let pkt: Vec<u8> = vec![
            // Ethernet with VLAN tag
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x81, 0x00,                         // 802.1Q VLAN tag
            0x00, 0x64,                         // VLAN ID=100
            0x08, 0x00,                         // real ethertype: IPv4
            // IPv4 (20 bytes, proto=UDP)
            0x45, 0x00, 0x00, 0x1C,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00,
            0x0A, 0x00, 0x00, 0x01,
            0x08, 0x08, 0x08, 0x08,
            // UDP
            0xC0, 0x00, 0x00, 0x35,
            0x00, 0x08, 0x00, 0x00,
        ];

        let parsed = parse_packet(&pkt).expect("should parse VLAN-tagged");
        assert_eq!(parsed.protocol, Protocol::Udp);
        assert_eq!(parsed.src_port, 49152);
        assert_eq!(parsed.dst_port, 53);
    }

    #[test]
    fn test_flow_table_bidirectional() {
        let mut ft = FlowTable::new();

        // Packet: A → B
        ft.process(&ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            tcp_flags: TCP_SYN,
            payload_len: 100,
        });

        // Packet: B → A (response)
        ft.process(&ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 80,
            dst_port: 12345,
            protocol: Protocol::Tcp,
            tcp_flags: TCP_SYN | TCP_ACK,
            payload_len: 200,
        });

        assert_eq!(ft.flows.len(), 1, "both directions should be one flow");
        assert_eq!(ft.packets_captured, 2);

        let snaps = ft.snapshot_and_reset(1.0);
        assert_eq!(snaps.len(), 1);
        let snap = &snaps[0];
        // 10.0.0.1:12345 < 10.0.0.2:80, so ep_a=10.0.0.1:12345
        assert_eq!(snap.bps_a_to_b, 100.0); // A→B
        assert_eq!(snap.bps_b_to_a, 200.0); // B→A
        assert!(snap.syn_source.is_some());
        assert_eq!(
            snap.syn_source.unwrap().ip(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn test_flow_key_canonical() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000);

        let key1 = FlowKey::new(a, b, Protocol::Tcp);
        let key2 = FlowKey::new(b, a, Protocol::Tcp);
        assert_eq!(key1, key2, "canonical key should be direction-independent");
    }

    #[test]
    fn test_merge_connections() {
        // Use 10.x local IP so that local < remote by addr_ord (local = ep_a)
        let local_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let remote_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let local_addr = SocketAddr::new(local_ip, 12345);
        let remote_addr = SocketAddr::new(remote_ip, 443);

        let mut connections = vec![Connection {
            local_addr,
            remote_addr,
            state: TcpState::Established,
            protocol: Protocol::Tcp,
            inode: 0,
            pid: Some(1234),
            process_name: Some("curl".into()),
            user: None,
            geo: None,
            is_threat: false,
            direction: Direction::Outbound,
            rx_bps: 0.0,
            tx_bps: 0.0,
            tx_queue: 0,
            rx_queue: 0,
            retransmits: 0,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            packet_count: 0,
            capture_source: CaptureSource::ProcFs,
        }];

        // local_addr < remote_addr by addr_ord, so local = ep_a
        let key = FlowKey::new(local_addr, remote_addr, Protocol::Tcp);
        let snapshots = vec![FlowSnapshot {
            key,
            bps_a_to_b: 500.0,  // local→remote = tx
            bps_b_to_a: 1500.0, // remote→local = rx
            total_bytes_a_to_b: 1000,
            total_bytes_b_to_a: 3000,
            packet_count: 42,
            syn_source: Some(local_addr), // we initiated
        }];

        let local_ips = {
            let mut s = HashSet::new();
            s.insert(local_ip);
            s
        };

        merge_connections(&mut connections, &snapshots, &local_ips);

        let c = &connections[0];
        assert_eq!(c.tx_bps, 500.0);
        assert_eq!(c.rx_bps, 1500.0);
        assert_eq!(c.tx_bytes_total, 1000);
        assert_eq!(c.rx_bytes_total, 3000);
        assert_eq!(c.packet_count, 42);
        assert_eq!(c.capture_source, CaptureSource::PacketCapture);
        assert_eq!(c.direction, Direction::Outbound);
    }
}
