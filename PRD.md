# Vigil — Real-Time Linux Server Security Dashboard

**A stunning Rust TUI that visualizes your server's security posture, live attacks, and network health — at a glance. No log dumps. No raw data. Just beautiful, actionable visuals.**

Inspired by [psnet](https://github.com/psmux/psnet)'s gorgeous aesthetic. Built for Linux servers. Security-first.

---

## Design Philosophy

> **If it looks like netstat, tcpdump, or iptables output — it's wrong.**

Every pixel on screen must be a **visual widget**: a gauge, a sparkline, a map, a heatmap, a bar chart, a KPI badge. Vigil is a cockpit dashboard, not a terminal log. The user should understand their server's security posture in under 2 seconds.

**Principles:**
1. **KPIs over tables** — Show "847 attacks blocked" as a big colored number, not 847 log lines
2. **Charts over lists** — Show attack origins as a heatmap, not a country list
3. **Gauges over text** — Show bandwidth as sparklines, not bytes-per-second text
4. **Color is data** — Green = safe, yellow = warning, red = danger, pulsing = live event
5. **Animate everything** — Sparklines scroll, map dots pulse, gauges sweep, numbers tick up

---

## The Six Views

Fewer tabs than psnet, but each one is a **dense, visual cockpit panel**. No filler tabs.

---

### View 1 — COMMAND CENTER (Home)

*2-second answer: "Is my server safe right now?"*

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║ VIGIL ── my-server ── 14:32:07 UTC ──── ↓2.4MB/s ↑890KB/s ──── uptime 12d 4h    ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  ┌─ SECURITY SCORE ──┐   ┌─ LIVE ATTACK MAP ────────────────────────────────────┐   ║
║  │                    │   │         ·  ·      ·                                  │   ║
║  │   ╭────────────╮   │   │     ·  *    · ·    ·  ·                              │   ║
║  │   │            │   │   │   · ·   · ·    ·    ·    · ·                         │   ║
║  │   │    72      │   │   │  ─── WORLD MAP (braille dots) ────                   │   ║
║  │   │   /100     │   │   │   · ·   · *  ·  ·  ·  ·  · ·                        │   ║
║  │   │            │   │   │     ·       ·      ·                                 │   ║
║  │   ╰────────────╯   │   │         ·           ·       * = attack (pulsing red) │   ║
║  │                    │   │                              · = connection (green)   │   ║
║  │  ▲ +3 from 1h ago │   └──────────────────────────────────────────────────────┘   ║
║  └────────────────────┘                                                              ║
║                                                                                      ║
║  ┌─ KPI STRIP ──────────────────────────────────────────────────────────────────┐   ║
║  │                                                                               │   ║
║  │  ╔═══════════╗  ╔═══════════╗  ╔═══════════╗  ╔═══════════╗  ╔═══════════╗  │   ║
║  │  ║  ATTACKS  ║  ║   DOORS   ║  ║   CONNS   ║  ║  BLOCKED  ║  ║  BANNED   ║  │   ║
║  │  ║   847     ║  ║    3/5    ║  ║    47     ║  ║  2,341    ║  ║    12     ║  │   ║
║  │  ║  /24h  ▲  ║  ║  exposed  ║  ║  active   ║  ║  /hour    ║  ║  IPs now  ║  │   ║
║  │  ╚═══════════╝  ╚═══════════╝  ╚═══════════╝  ╚═══════════╝  ╚═══════════╝  │   ║
║  └───────────────────────────────────────────────────────────────────────────────┘   ║
║                                                                                      ║
║  ┌─ BANDWIDTH ──────────────────────┐  ┌─ TOP ATTACKERS ───────────────────────┐   ║
║  │ ↓ ▁▂▃▅▇█▇▅▃▂▁▁▂▃▅▇█  2.4 MB/s  │  │ CN ████████████████████  312          │   ║
║  │ ↑ ▁▁▂▂▃▃▂▂▁▁▁▂▂▃▃▂▂  890 KB/s  │  │ RU ██████████████       189          │   ║
║  │                                   │  │ US ██████████           134          │   ║
║  │ ▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▂▃▄▅  24h trend │  │ DE █████████            112          │   ║
║  └───────────────────────────────────┘  │ NL ██████               78           │   ║
║                                          └─────────────────────────────────────┘   ║
║                                                                                      ║
║  ┌─ DOORS (Exposure) ──────────────────────────────────────────────────────────┐    ║
║  │  ● :22   0.0.0.0  SSH     ██ KEY   │  ● :4000 127.0.0.1 API    SAFE       │    ║
║  │  ● :3000 0.0.0.0  Next.js ██ OPEN  │  ● :5432 127.0.0.1 PgSQL  SAFE       │    ║
║  │  ● :8080 0.0.0.0  Caddy   ██ OPEN  │                                       │    ║
║  │                                      │  Exposed: 3  │  Safe: 2  │  Risk: 0  │    ║
║  └──────────────────────────────────────────────────────────────────────────────┘    ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

**Every element is a visual widget:**
- **Security Score**: Large circular gauge (0-100), color gradient green→yellow→red, delta from 1h ago
- **Attack Map**: Animated Braille-character world map. Red pulsing dots = active attacks. Green dots = normal connections. Dots fade over time. Just like psnet's map.
- **KPI Strip**: Five big-number badges, color-coded. Tick up in real-time. Arrow indicators for trend.
- **Bandwidth**: Animated sparklines (matching psnet's speed section). 24h trend line below.
- **Top Attackers**: Horizontal bar chart by country. Updates live. Bars grow as attacks come in.
- **Doors**: Visual port exposure strip. Each port is a colored dot: green (localhost), yellow (public+auth), red (public+no auth). Instant at-a-glance.

---

### View 2 — ATTACK RADAR

*"Who's attacking, from where, how hard?"*

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║  ATTACK RADAR ─── 847 attacks / 24h ─── 23 attackers ─── 12 banned ────────────────║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  ┌─ ATTACK HEATMAP (24h) ────────────────────────────────────────────────────────┐  ║
║  │                                                                                │  ║
║  │  ░░▒▒▓▓██▓▓▒▒░░░░▒▒▓▓████▓▓▒▒░░░░░░▒▒▓▓██████▓▓▒▒░░░░░░▒▒▓▓████████▓▓▒▒░  │  ║
║  │  00   02   04   06   08   10   12   14   16   18   20   22   24              │  ║
║  │                              ▲ now                                             │  ║
║  │  Peak: 14:00 (127 attacks/hr)  │  Quiet: 04:00 (3 attacks/hr)                │  ║
║  └────────────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                      ║
║  ┌─ ATTACK TYPES ──────────────┐  ┌─ ATTACK ORIGINS MAP ─────────────────────────┐  ║
║  │                              │  │                                               │  ║
║  │  SSH Brute  ████████████ 634 │  │     ·  ·      ·            ·                  │  ║
║  │  Port Scan  ████         203 │  │   ·  * ·  · ·    ·  ·                         │  ║
║  │  HTTP Probe ██            47 │  │  · ·   · ·    ·    ·    · ·                   │  ║
║  │  SMTP Probe █             12 │  │  ─── (zoomed to attack sources) ───           │  ║
║  │                              │  │  · ·   · *  ·  ·  ·  ·  · ·                   │  ║
║  │  ○ SSH Brute                 │  │     ·       ·      ·                           │  ║
║  │    ╰ 634 attempts            │  │         ·           ·                          │  ║
║  │    ╰ 8 unique IPs            │  │                                               │  ║
║  │    ╰ 5 banned by fail2ban    │  │  * = high intensity   · = low intensity       │  ║
║  └──────────────────────────────┘  └───────────────────────────────────────────────┘  ║
║                                                                                      ║
║  ┌─ TOP ATTACKERS ───────────────────────────────────────────────────────────────┐  ║
║  │  IP              │ Country │ Attempts │ Intensity      │ Status  │ Since      │  ║
║  │  103.245.xx.xx   │ CN 🔴   │ 312      │ ████████████   │ BANNED  │ 2h ago     │  ║
║  │  185.220.xx.xx   │ DE 🟡   │ 189      │ █████████      │ BANNED  │ 45m ago    │  ║
║  │  45.134.xx.xx    │ RU 🔴   │ 134      │ ██████         │ BANNED  │ 3h ago     │  ║
║  │  92.255.xx.xx    │ RU 🟡   │ 89       │ ████           │ ACTIVE  │ 12m ago    │  ║
║  │  5.188.xx.xx     │ NL 🟢   │ 23       │ █             │ ACTIVE  │ 5m ago     │  ║
║  └───────────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

**Visual elements:**
- **Attack Heatmap**: Full-width, 24-hour heat strip using block characters (░▒▓█). Shows attack intensity over time. The "now" marker moves. Instantly shows when attacks peak.
- **Attack Types**: Horizontal bar chart. Not a table of log lines — aggregated visual bars.
- **Origins Map**: Same Braille world map but zoomed/filtered to only attack sources. Dot intensity = attack frequency.
- **Top Attackers**: Minimal table, but the key column is the **intensity bar** — visual, not a number dump. Status is color-coded (red BANNED, yellow ACTIVE). Max 5-10 rows visible, not hundreds.

**What this is NOT:**
- NOT a scrolling log of every SSH attempt
- NOT raw auth.log output
- NOT fail2ban-client status dump

---

### View 3 — DOORS & EXPOSURE

*"How many doors are open? Should they be?"*

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║  DOORS ─── 5 listening ─── 3 exposed ─── 0 critical ───────────────────────────────║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  ┌─ EXPOSURE RING ─────────────────────────┐  ┌─ FIREWALL COVERAGE ──────────────┐  ║
║  │                                          │  │                                   │  ║
║  │         ╭──── 5 ports ────╮              │  │   ╭─────────────────────╮         │  ║
║  │        ╱   ╭──────╮        ╲             │  │   │                     │         │  ║
║  │       │   │ 2     │         │            │  │   │    COVERAGE: 80%    │         │  ║
║  │       │   │ safe  │  3      │            │  │   │                     │         │  ║
║  │       │   │       │ exposed │            │  │   ╰─────────────────────╯         │  ║
║  │        ╲   ╰──────╯        ╱             │  │                                   │  ║
║  │         ╰─────────────────╯              │  │   ✓ Default: DENY incoming       │  ║
║  │                                          │  │   ✓ SSH: allowed + fail2ban       │  ║
║  │   ■ Safe (localhost)  ■ Exposed  ■ Crit  │  │   ✓ 3000,4000,8080: allowed      │  ║
║  └──────────────────────────────────────────┘  │   ○ 4001: no explicit rule        │  ║
║                                                 └───────────────────────────────────┘  ║
║                                                                                      ║
║  ┌─ PORT MAP ────────────────────────────────────────────────────────────────────┐  ║
║  │                                                                                │  ║
║  │   :22 ──── sshd ──── 0.0.0.0 ──── KEY AUTH ──── 3 conns ────── [██ EXPOSED]  │  ║
║  │     │      └ root     └ public      └ safe        └ ↓12KB/s                    │  ║
║  │                                                                                │  ║
║  │  :3000 ── next.js ── 0.0.0.0 ──── NO AUTH ──── 12 conns ───── [██ EXPOSED]   │  ║
║  │     │      └ root     └ public      └ via tunnel   └ ↓1.2MB/s                  │  ║
║  │                                                                                │  ║
║  │  :4000 ── node ───── 127.0.0.1 ── JWT AUTH ──── 0 conns ────── [■  SAFE   ]  │  ║
║  │     │      └ root     └ local       └ safe        └ idle                        │  ║
║  │                                                                                │  ║
║  │  :5432 ── postgres ─ 127.0.0.1 ── PASSWORD ──── 3 conns ────── [■  SAFE   ]  │  ║
║  │     │      └ postgres  └ local      └ safe        └ ↓89KB/s                     │  ║
║  │                                                                                │  ║
║  │  :8080 ── caddy ──── 0.0.0.0 ──── NO AUTH ──── 2 conns ────── [██ EXPOSED]   │  ║
║  │     │      └ caddy    └ public      └ static      └ ↓340KB/s                   │  ║
║  │                                                                                │  ║
║  └────────────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

**Visual elements:**
- **Exposure Ring**: Donut chart — safe vs exposed vs critical. One glance.
- **Firewall Coverage**: Percentage gauge + checklist with ✓/○ indicators. Not raw iptables dump.
- **Port Map**: Visual flow diagram per port. Each port is a horizontal pipeline showing: port → process → bind address → auth status → connections → risk badge. Color-coded end-to-end. NOT a table — a visual flow.

---

### View 4 — NETWORK PULSE

*"How much is flowing, and where to?"*

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║  NETWORK PULSE ─── eth0 ─── ↓2.4MB/s ↑890KB/s ─── 47 active connections ──────────║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  ┌─ THROUGHPUT (5 min) ──────────────────────────────────────────────────────────┐  ║
║  │                                                                                │  ║
║  │  3MB ┤                    ╭─╮                                                  │  ║
║  │      ┤        ╭──╮      ╭╯ ╰╮     ╭─╮                    ╭──╮                │  ║
║  │  2MB ┤   ╭──╮╭╯  ╰╮ ╭──╯   ╰─╮  ╭╯ ╰╮  ╭╮   ╭─╮   ╭──╯  ╰──╮            │  ║
║  │      ┤╭─╯  ╰╯    ╰─╯        ╰──╯   ╰──╯╰╮╭─╯ ╰╮ ╭╯        ╰──╮         │  ║
║  │  1MB ┤╯                                     ╰╯    ╰─╯            ╰──╮      │  ║
║  │      ┤                                                                 ╰─── │  ║
║  │    0 ┤───────────────────────────────────────────────────────────────────────│  ║
║  │       14:27    14:28    14:29    14:30    14:31    14:32                 now  │  ║
║  │                                                                                │  ║
║  │       ── Download (blue)    ── Upload (green)                                 │  ║
║  └────────────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                      ║
║  ┌─ CONNECTIONS FLOW ───────────────────┐  ┌─ TOP DESTINATIONS ──────────────────┐  ║
║  │                                       │  │                                     │  ║
║  │       INBOUND         OUTBOUND        │  │  Cloudflare  ████████████  1.8MB/s │  ║
║  │     ╭────────╮      ╭────────╮        │  │  GitHub      ████          340KB/s │  ║
║  │     │   23   │      │   24   │        │  │  Google DNS  ██            89KB/s  │  ║
║  │     │  ↓in   │      │  ↑out  │        │  │  npm CDN     █             45KB/s  │  ║
║  │     ╰────────╯      ╰────────╯        │  │  Stripe API  ░             12KB/s  │  ║
║  │                                       │  │                                     │  ║
║  │  ── by state ──                       │  └─────────────────────────────────────┘  ║
║  │  ESTABLISHED ████████████████  38     │                                           ║
║  │  TIME_WAIT   ████              7      │  ┌─ BY PROCESS ──────────────────────┐   ║
║  │  SYN_SENT    █                 2      │  │  cloudflared ████████████ 1.5MB/s │   ║
║  │  CLOSE_WAIT  ░                 0      │  │  node (next) ██████       890KB/s │   ║
║  │                                       │  │  node (api)  ███          340KB/s │   ║
║  └───────────────────────────────────────┘  │  postgres    █             89KB/s │   ║
║                                              └──────────────────────────────────┘   ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

**Visual elements:**
- **Throughput Graph**: Proper line chart with filled area (like psnet's speed graph). Scrolling time axis. Two colors for up/down.
- **Connections Flow**: Two big KPI boxes — inbound count vs outbound count. Below: connection state bar chart.
- **Top Destinations**: Horizontal bar chart with bandwidth. Not IP addresses — resolved hostnames.
- **By Process**: Which processes consume bandwidth. Bars, not tables.

---

### View 5 — GEOGRAPHY

*"Where in the world are connections coming from?"*

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║  GEOGRAPHY ─── 14 countries ─── 23 cities ─── 47 connections ──────────────────────║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  ┌─ CONNECTION MAP ──────────────────────────────────────────────────────────────┐  ║
║  │                                                                                │  ║
║  │              ⠁⠂⠄⡀⠁⠂⠄      ⡀⠁⠂⠄⡀                                              │  ║
║  │         ⠁⠂⠄  *⠁ ⠂⠄⡀⠁⠂  ⡀⠁⠂⠄  ⡀⠁⠂⠄                                         │  ║
║  │       ⠁⠂⠄⡀⠁  ⠂⠄⡀⠁   ⠂⠄⡀  ⠁⠂⠄     ⡀⠁⠂⠄                                    │  ║
║  │      ⠁⠂⠄⡀  ⠁⠂⠄⡀⠁⠂⠄ ⡀⠁⠂   ⠄⡀⠁⠂⠄⡀  ⠁⠂⠄⡀                                 │  ║
║  │        ⠁⠂  ⠄⡀⠁⠂⠄⡀  ⠁⠂⠄⡀⠁  ⠂⠄⡀  ⠁⠂⠄⡀                                    │  ║
║  │            ⠁⠂⠄    ⡀⠁  ⠂⠄⡀⠁⠂⠄    ⡀⠁⠂⠄                                       │  ║
║  │                  ⠁⠂⠄⡀     ⠁⠂⠄⡀⠁⠂⠄                                             │  ║
║  │                       ⠁⠂⠄⡀  ⠁⠂⠄                                                │  ║
║  │                            ⠁⠂⠄                                                   │  ║
║  │                                                                                │  ║
║  │   ● Normal connection (green)   * Attack origin (pulsing red)                 │  ║
║  │   Lines connect to server location (animated dash pattern)                     │  ║
║  └────────────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                      ║
║  ┌─ COUNTRIES ─────────────────────────┐  ┌─ CITIES ──────────────────────────────┐ ║
║  │ US ██████████████████████  23 │ 5★  │  │ Frankfurt  █████████████  12 │ 2☠    │ ║
║  │ DE ████████████████        15 │ 2☠  │  │ Ashburn    ██████████      8 │       │ ║
║  │ CN ████████████            12 │ 8☠  │  │ Beijing    █████████       9 │ 9☠    │ ║
║  │ RU ████████                 8 │ 8☠  │  │ Moscow     ███████         6 │ 6☠    │ ║
║  │ SG ██████                   5 │ 1★  │  │ Singapore  █████           5 │       │ ║
║  └─────────────────────────────────────┘  └───────────────────────────────────────┘ ║
║                                                                                      ║
║   ★ = legitimate connection    ☠ = attack origin                                    ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

**Visual elements:**
- **Full-width Braille world map**: Just like psnet. Animated connection lines from dots to server location. Red pulsing for attacks. Green steady for normal.
- **Country/City bars**: Bar charts with inline threat indicators (☠). Not raw IP lists.

---

### View 6 — SYSTEM VITALS

*"Is the server healthy?"*

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║  SYSTEM ─── Ubuntu 24.04 ─── Linux 6.8.0 ─── 2 CPU ─── 4GB RAM ──────────────────║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  ┌─ CPU ──────────────────────────┐  ┌─ MEMORY ────────────────────────────────┐   ║
║  │                                 │  │                                          │   ║
║  │  Core 0 [████████░░░░░░░] 54%  │  │  RAM  [████████████░░░░░] 2.1/3.9 GB    │   ║
║  │  Core 1 [██████░░░░░░░░░] 38%  │  │  Swap [██░░░░░░░░░░░░░░]  0.4/2.0 GB   │   ║
║  │                                 │  │                                          │   ║
║  │  Load: 0.82  1.14  0.95        │  │  ▁▂▃▅▃▂▁▂▃▅▇▅▃▂▁▂▃▅▃▂  24h trend      │   ║
║  │  ▁▂▃▅▇█▇▅▃▂▁▂▃▅▇█  5m trend  │  │                                          │   ║
║  └─────────────────────────────────┘  └──────────────────────────────────────────┘   ║
║                                                                                      ║
║  ┌─ DISK ─────────────────────────┐  ┌─ NETWORK INTERFACES ───────────────────┐    ║
║  │                                 │  │                                         │    ║
║  │  /     [██████░░░░░░░░] 7/77G  │  │  eth0    10.116.0.2    1 Gbps  ▲ UP    │    ║
║  │  /tmp  [█░░░░░░░░░░░░░] 45M    │  │  lo      127.0.0.1    -        ▲ UP    │    ║
║  │                                 │  │                                         │    ║
║  └─────────────────────────────────┘  └─────────────────────────────────────────┘    ║
║                                                                                      ║
║  ┌─ SERVICES ────────────────────────────────────────────────────────────────────┐  ║
║  │  ● postgresql  active  │  ● caddy       active  │  ● fail2ban   active       │  ║
║  │  ● cloudflared active  │  ● myapp       active  │  ● sshd       active       │  ║
║  └────────────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

**All gauges and bars. No text dumps.**

---

## Always-Visible Header

Every view shows this header — your constant situational awareness strip:

```
VIGIL ── hostname ── HH:MM:SS ── ↓2.4MB ↑890KB ── 47 conns ── 3 threats ── Score: 72 ── [1:Cmd 2:Atk 3:Door 4:Net 5:Geo 6:Sys]
```

---

## What Vigil Is NOT

| Vigil does NOT... | Instead it... |
|---|---|
| Dump auth.log lines | Shows attack count KPI + heatmap + country bars |
| Print netstat output | Shows port map with visual risk badges |
| Show iptables rules | Shows firewall coverage % gauge + checklist |
| Tail tcpdump packets | Shows bandwidth sparklines + destination bars |
| List every connection | Shows connection count KPIs + state bar chart |
| Display raw IP lists | Shows world map with color-coded dots |

---

## Architecture

### Single Binary, Zero Dependencies

| Component | Size | Purpose |
|-----------|------|---------|
| Binary core | ~3 MB | Rust, statically linked |
| GeoIP DB (MaxMind) | ~7 MB | Country + city for every IP |
| Threat IP lists | ~1 MB | Known-bad IPs (abuse.ch, blocklist.de) |
| OUI database | ~1 MB | MAC vendor lookup |
| **Total** | **~12 MB** | Single file, copy and run |

### Data Sources (all Linux-native)

| Data | Source | Method |
|------|--------|--------|
| Connections | `/proc/net/tcp{,6}`, `/proc/net/udp{,6}` | procfs read |
| Process ownership | `/proc/{pid}/fd/`, `/proc/{pid}/cmdline` | procfs |
| Bandwidth | `/proc/net/dev` | Polled delta |
| Connection events | Netlink `SOCK_DIAG` | Kernel push |
| Attack attempts | `journalctl -u sshd` / `/var/log/auth.log` | Tail + parse |
| Banned IPs | fail2ban Unix socket | Query |
| Firewall rules | Netlink + nftables / iptables | Query |
| Blocked packets | Kernel log (iptables LOG target) | Tail |
| GeoIP | Embedded MaxMind DB | In-memory lookup |
| Threat intel | Embedded IP lists | HashSet lookup |

**No root for basic views.** Root/`CAP_NET_ADMIN` needed for firewall details and fail2ban.

### Tech Stack

| Component | Choice |
|-----------|--------|
| Language | Rust |
| TUI | `ratatui` + `crossterm` |
| Async | `tokio` |
| GeoIP | `maxminddb` |
| DNS | `hickory-resolver` |
| Kernel | Netlink sockets |

---

## Security Score (0-100)

Computed live, shown as the main gauge:

| Factor | Max Points | How |
|--------|-----------|-----|
| No dangerous ports exposed | 25 | -25 per redis/memcached/mongo on 0.0.0.0 without auth |
| Firewall active + default deny | 20 | 20 full, 10 active but no default deny, 0 none |
| SSH hardened | 15 | Key auth + fail2ban = 15, key only = 10, password = 0 |
| Minimal exposure | 15 | -3 per port on 0.0.0.0 |
| No threat connections | 10 | -2 per active connection to known-bad IP |
| Non-root services | 10 | -2 per unnecessary root service |
| Auth on all public services | 5 | -5 per unauthenticated public service |

---

## Development Phases

### Phase 1 — Dashboard Core
- View 1 (Command Center) with security score, KPI strip, exposure summary, bandwidth sparklines
- View 3 (Doors) with port risk analysis
- View 6 (System Vitals) with CPU/memory/disk gauges
- Header bar, tab navigation, keyboard controls

### Phase 2 — Attacks & Geography
- View 2 (Attack Radar) with heatmap, attack type bars, top attackers
- View 5 (Geography) with Braille world map
- GeoIP integration, threat IP lists
- fail2ban + auth.log parsing

### Phase 3 — Network & Polish
- View 4 (Network Pulse) with throughput graphs, destination bars
- Attack map on Command Center
- Animated sparklines, pulsing dots, color transitions
- Adaptive layout for different terminal sizes

### Phase 4 — Release
- Single binary builds (amd64 + arm64)
- `cargo install vigil`
- Config file support
- man page, shell completions

---

## Motivation

Too many production servers get compromised because of a single misconfiguration — an open port, a missing firewall rule, a service with no auth. The breach happens silently, and by the time you notice, it's too late.

Vigil was born so that every open door, every attack, every suspicious connection is **visible at a glance** — not buried in log files that nobody reads.
