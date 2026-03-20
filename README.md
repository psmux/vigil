<p align="center">
  <br>
  <img width="120" src="https://raw.githubusercontent.com/psmux/vigil/main/.github/vigil-logo.svg" alt="Vigil">
  <br>
  <br>
</p>

<h1 align="center">Vigil</h1>

<p align="center">
  <b>Real-time Linux server security dashboard</b>
  <br>
  <i>See every attack, every open door, every connection — at a glance</i>
</p>

<p align="center">
  <a href="https://crates.io/crates/vigil"><img src="https://img.shields.io/crates/v/vigil.svg" alt="crates.io"></a>
  <a href="https://github.com/psmux/vigil/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <a href="https://github.com/psmux/vigil/releases"><img src="https://img.shields.io/github/v/release/psmux/vigil" alt="Release"></a>
</p>

<br>

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║ VIGIL ── my-server ── 14:32:07 UTC ── ↓2.4MB/s ↑890KB/s ── 47 conns ── Score:72║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║  ┌─ SECURITY SCORE ──┐   ┌─ LIVE ATTACK MAP ────────────────────────────────┐   ║
║  │   ╭────────────╮   │   │     ·  *    · ·    ·  ·                          │   ║
║  │   │    72      │   │   │   · ·   · ·    ·    ·    · ·                     │   ║
║  │   │   /100     │   │   │  ─── WORLD MAP (braille) ────                    │   ║
║  │   ╰────────────╯   │   │   · ·   · *  ·  ·  ·  ·  · ·                    │   ║
║  │  ▲ +3 from 1h ago │   │         ·           ·       * = attack            │   ║
║  └────────────────────┘   └──────────────────────────────────────────────────┘   ║
║  ╔═══════════╗  ╔═══════════╗  ╔═══════════╗  ╔═══════════╗  ╔═══════════╗     ║
║  ║  ATTACKS  ║  ║   DOORS   ║  ║   CONNS   ║  ║  BLOCKED  ║  ║  BANNED   ║     ║
║  ║   847     ║  ║    3/5    ║  ║    47     ║  ║  2,341    ║  ║    12     ║     ║
║  ║  /24h  ▲  ║  ║  exposed  ║  ║  active   ║  ║  /hour    ║  ║  IPs now  ║     ║
║  ╚═══════════╝  ╚═══════════╝  ╚═══════════╝  ╚═══════════╝  ╚═══════════╝     ║
║  ┌─ BANDWIDTH ──────────────────┐  ┌─ TOP ATTACKERS ───────────────────────┐    ║
║  │ ↓ ▁▂▃▅▇█▇▅▃▂▁▁▂▃▅▇█  2.4MB │  │ CN ████████████████████  312          │    ║
║  │ ↑ ▁▁▂▂▃▃▂▂▁▁▁▂▂▃▃▂▂  890KB │  │ RU ██████████████       189          │    ║
║  └──────────────────────────────┘  │ US ██████████           134          │    ║
║  ┌─ DOORS ──────────────────────────────────────────────────────────────────┐   ║
║  │  ● :22 0.0.0.0 SSH KEY │ ● :4000 127.0.0.1 API SAFE │ Exposed:3 Safe:2│   ║
║  └──────────────────────────────────────────────────────────────────────────┘   ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

<br>

## What is Vigil?

**Vigil** is a beautiful TUI security dashboard for Linux servers — built in Rust, inspired by [psnet](https://github.com/psmux/psnet). Single binary, zero config, zero dependencies.

Where `htop` shows you system resources and `psnet` shows you network connections, **Vigil shows you who's attacking your server right now** and which doors you left open.

### The Problem

Your server is under attack right now. SSH brute-force bots scan every IP on the internet 24/7. One misconfiguration — an open port, a service without auth, a missing firewall rule — and you're compromised before you even notice.

Log files won't save you. Nobody reads 10,000 lines of `auth.log`. Nobody runs `ss -tlnp` and checks if Redis is on `0.0.0.0`. Nobody watches `iptables` counters.

### The Solution

Vigil turns all of that into a **single dashboard you can read in 2 seconds**:

- **Security Score (0-100)** — Are you safe? Green/yellow/red gauge, updated live.
- **Attack Map** — Animated braille-character world map. Red pulsing dots = active attacks.
- **KPI Badges** — Attacks/24h, doors exposed, connections, packets blocked, IPs banned.
- **Doors View** — Every listening port, its bind address, auth status, risk level. The "how many doors are open?" view that no other tool gives you.
- **Attack Radar** — 24-hour heatmap of attack intensity. Top attackers by country. fail2ban integration.

> **If it looks like `netstat`, `tcpdump`, or `iptables` output — it's wrong.**
>
> Every pixel is a visual widget: gauges, sparklines, maps, heatmaps, bar charts. Vigil is a cockpit, not a terminal dump.

<br>

## Features

### 6 Views

| Key | View | What You See |
|-----|------|-------------|
| `1` | **Command Center** | Security score gauge, live attack map, KPI strip, bandwidth sparklines, exposure summary |
| `2` | **Attack Radar** | 24h attack heatmap, attack type bars, origin map, top attackers with intensity bars |
| `3` | **Doors** | Exposure donut, firewall coverage gauge, port flow diagrams with risk badges |
| `4` | **Network Pulse** | Throughput line chart, connection flow KPIs, top destinations & processes |
| `5` | **Geography** | Full-width braille world map, country & city bar charts with threat indicators |
| `6` | **System** | CPU/memory/disk gauges, network interfaces, service status grid |

### Visual Widgets

All hand-crafted with Unicode characters — no raw data dumps:

- **Braille World Map** — Sub-cell resolution using U+2800-U+28FF. Mercator projection. Pulsing dots for attacks, steady dots for connections. IP-hash jitter to spread overlapping markers.
- **Sparklines** — Animated bandwidth graphs using ▁▂▃▄▅▆▇█ block characters.
- **Bar Gauges** — ████████░░░░ with color gradients (green → yellow → red).
- **KPI Badges** — Big bold numbers with trend arrows. Color-coded severity.
- **Heatmaps** — 24-hour attack intensity using ░▒▓█ with color gradient.
- **Horizontal Bar Charts** — Countries, attack types, processes, destinations.
- **Donut Charts** — Port exposure ratio (safe/exposed/critical).
- **Line Charts** — Multi-series throughput with braille-resolution curves.
- **Port Flow Diagrams** — Visual pipeline: port → process → bind → auth → risk.

### Security Score (0-100)

Real-time composite score computed from:

| Factor | Weight | What It Checks |
|--------|--------|----------------|
| Dangerous ports | 25 | Redis/Memcached/MongoDB on 0.0.0.0 without auth |
| Firewall | 20 | UFW/iptables active with default deny |
| SSH hardening | 15 | Key auth + fail2ban |
| Port exposure | 15 | How many ports bind to 0.0.0.0 |
| Threat connections | 10 | Active connections to known-bad IPs |
| Root services | 10 | Unnecessary services running as root |
| Auth coverage | 5 | All public services require authentication |

### Data Sources

All native Linux — no pcap, no kernel modules, no agents:

| Source | Data |
|--------|------|
| `/proc/net/tcp{,6}` | Active connections |
| `/proc/net/udp{,6}` | UDP sockets |
| `/proc/{pid}/fd` | Process → connection mapping |
| `/proc/net/dev` | Bandwidth counters |
| `auth.log` / `journalctl` | SSH attack attempts |
| fail2ban | Banned IPs |
| UFW / iptables / nftables | Firewall rules |
| Embedded MaxMind DB | GeoIP (country, city, lat/lon) |
| Embedded threat lists | Known-bad IP detection |

<br>

## Install

```bash
# From crates.io
cargo install vigil

# Or download pre-built binary
curl -fsSL https://github.com/psmux/vigil/releases/latest/download/vigil-linux-amd64 \
  -o /usr/local/bin/vigil && chmod +x /usr/local/bin/vigil

# Run (basic monitoring — no root needed)
vigil

# Run with full features (firewall details, fail2ban, attack detection)
sudo vigil
```

### Requirements

- **Linux** (Ubuntu, Debian, Fedora, Arch, Alpine, etc.)
- Terminal with Unicode support (any modern terminal)
- 256-color or truecolor support recommended
- No root required for basic views; root for firewall/fail2ban/attack detection

<br>

## Keyboard Controls

| Key | Action |
|-----|--------|
| `1`-`6` | Jump to view |
| `Tab` | Next view |
| `Shift+Tab` | Previous view |
| `j`/`k` or `↑`/`↓` | Scroll |
| `z` | Pause live updates |
| `r` | Force refresh |
| `?` | Help |
| `q` | Quit |

<br>

## Comparison

| | psnet | vigil |
|---|---|---|
| **Platform** | Windows | Linux |
| **Focus** | Network monitoring | Security monitoring |
| **Attack viz** | Alert list | Live attack map + heatmap + radar |
| **Exposure** | Server list | Full risk-scored "Doors" view |
| **Firewall** | Windows Firewall | UFW / iptables / nftables |
| **IDS** | — | fail2ban integration |
| **Score** | Health gauge | Security score (0-100) |
| **World map** | Connection map | Attack origin map |
| **Binary** | ~12 MB | ~12 MB |
| **Dependencies** | Zero | Zero |

<br>

## Part of the psmux Family

| Tool | Platform | What |
|------|----------|------|
| [**psmux**](https://github.com/psmux/psmux) | Windows | tmux for PowerShell |
| [**psnet**](https://github.com/psmux/psnet) | Windows | Network monitor TUI |
| [**pstop**](https://github.com/psmux/pstop) | Windows | htop for Windows |
| **vigil** | Linux | Security dashboard TUI |

<br>

## Tech Stack

- **Rust** — Performance, safety, single static binary
- **[ratatui](https://ratatui.rs/)** — TUI framework (same as psnet)
- **crossterm** — Terminal backend
- **maxminddb** — GeoIP lookups
- **sysinfo** — CPU/memory/disk metrics

<br>

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/psmux/vigil
cd vigil
cargo build
cargo run
```

<br>

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Stop reading logs. Start seeing threats.</b>
  <br><br>
  <a href="https://github.com/psmux/vigil">GitHub</a> · <a href="https://crates.io/crates/vigil">crates.io</a> · <a href="https://github.com/psmux/vigil/issues">Issues</a>
</p>
