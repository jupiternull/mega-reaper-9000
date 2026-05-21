# MEGA REAPER 9000

**Real-Time Security Operations Dashboard**

A network monitoring and security testing platform with live system metrics, LAN topology, GeoIP enrichment, Metasploit RPC integration, IoT device discovery, and integrated offensive security tools. All data is live — zero simulated values.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Flask](https://img.shields.io/badge/Flask-3.0+-green) ![License](https://img.shields.io/badge/License-Educational-red)

---
<img width="1912" height="930" alt="Screenshot from 2026-02-16 22-25-03" src="https://github.com/user-attachments/assets/ef27e941-6996-4838-8bc6-7f536a275dd0" />
<img width="1912" height="912" alt="Screenshot from 2026-02-16 22-25-40" src="https://github.com/user-attachments/assets/52ade503-7f84-418d-8454-5f2ebb3869af" />
<img width="1912" height="912" alt="Screenshot from 2026-02-16 22-26-01" src="https://github.com/user-attachments/assets/96b29a23-123a-4ad5-8cbb-50be58f2bc32" />
<img width="1912" height="912" alt="Screenshot from 2026-02-16 22-26-21" src="https://github.com/user-attachments/assets/3fa86410-3f79-4176-9feb-3250fdd801e1" />


## Features

**Live Dashboard**
- Real-time CPU, memory, bandwidth, and latency via `psutil`
- External connections table — outbound internet connections only, enriched with GeoIP (country, ISP, ASN via ip-api.com)
- Top talkers ranked by connection count with proportional bandwidth estimates
- **Network topology canvas** — animates your actual LAN neighbors from the ARP table, color-coded by device type
- **Connection map canvas** — visualizes active outbound connections
- **Local Exposure panel** — lists every listening port with service name and interface; suspicious ports flagged in red
- Security alerts from `/var/log/auth.log` and system resource thresholds
- System status: uptime, hostname, kernel, attack surface (listening port count)
- SQLite persistence for scan history and alert log

**Authentication**
- Single-operator login via Flask-Login + bcrypt
- Credentials stored in `.env` (never committed) — see `.env.example`
- All API and WebSocket routes protected

**GUI Security Tools**
- **Nmap Scanner** — network discovery with six scan profiles
- **Port Scanner** — fast TCP/UDP enumeration
- **Vulnerability Scanner** — `nmap --script vuln` with real CVSS scores from NVD API v2
- **Packet Capture** — Scapy-based protocol decode (HTTP, DNS, MQTT, SSH, SMTP, MySQL, etc.)
- **DNS Enumeration** — `dig` A/MX/NS/TXT lookups
- **Web Scanner** — `nikto` or header analysis fallback
- **Brute Force** — `hydra` authentication testing
- **Exploit DB** — search and deploy Metasploit modules via RPC
- **IoT Scanner** — ARP table + nmap IoT port probe (RTSP/554, MQTT/1883, CoAP/5683, Telnet/23, IPP/9100, UPnP/49152) + mDNS/Bonjour discovery via `zeroconf`
- **Report Generator** — export assessment reports

**Metasploit Integration (optional)**
- Connects to `msfrpcd` via pymetasploit3 — all features degrade gracefully when MSF is not running
- Module search, session management, handler control, payload generation via `msfvenom`
- 10 payload templates (Windows, Linux, Python, PHP, Android, PowerShell)
- Background poller auto-registers new sessions as compromised hosts and advances kill chain

**Terminal Mode**
- Integrated terminal executing real commands on the host
- Whitelisted command set: nmap, ping, dig, netstat, ss, curl, whois, traceroute, etc.

**Attack Operations**
- Kill chain tracker (Lockheed Martin model, 7 phases)
- Active exploit session registry with Metasploit session merge
- Compromised host registry — populated by real sessions, never mocked

## Requirements

- **OS:** Linux (tested on Ubuntu 24.04)
- **Python:** 3.10+
- **Root/CAP_NET_RAW:** Required for SYN scans and packet capture

### System Tools

```bash
sudo apt install nmap dnsutils tcpdump nikto hydra
```

### Metasploit (optional)

```bash
# Start the RPC daemon before launching mega-reaper
msfrpcd -P yourpassword -S
# Then set MSF_PASSWORD=yourpassword in .env
```

## Quick Start

```bash
git clone https://github.com/jupiternull/mega-reaper-9000.git
cd mega-reaper-9000

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure credentials
cp .env.example .env
# Edit .env — set SECRET_KEY and generate REAPER_PASSWORD_HASH:
python3 scripts/hash_password.py yourpassword

# Launch (sudo for full connection enumeration and packet capture)
sudo ./venv/bin/python3 backend/app.py
```

Open **http://localhost:5000** — log in with the credentials you set in `.env`.

Default if you skip password setup: `admin` / `reaper9000` *(change this)*.

## Architecture

```
mega-reaper-9000/
├── frontend/
│   └── index.html              # Single-page dashboard (vanilla HTML/CSS/JS)
├── backend/
│   ├── app.py                  # Flask + SocketIO server, background tasks
│   ├── auth.py                 # Flask-Login + bcrypt auth
│   ├── database.py             # SQLAlchemy models (ScanResult, AlertLog, ExploitSession, CompromisedHost)
│   ├── routes/
│   │   ├── dashboard.py        # System status & alerts API
│   │   ├── tools.py            # Security tool endpoints (nmap, portscan, vulnscan, etc.)
│   │   ├── exploits.py         # Exploit session + kill chain management
│   │   └── msf.py              # Metasploit RPC routes
│   └── services/
│       ├── network_scanner.py      # psutil connections (external-only filter) + nmap
│       ├── system_monitor.py       # CPU, memory, bandwidth, latency
│       ├── device_identifier.py    # ARP table + MAC OUI lookup (~150 vendors)
│       ├── geoip.py                # ip-api.com batch GeoIP (1hr cache, no key needed)
│       ├── nvd.py                  # NVD REST API v2 CVSS scores (24hr cache)
│       ├── packet_capture.py       # Scapy background sniffer, protocol decode
│       ├── iot_scanner.py          # IoT discovery: ARP + port probe + mDNS/Bonjour
│       ├── msf.py                  # pymetasploit3 RPC client (graceful degradation)
│       ├── payload_generator.py    # msfvenom wrapper, 10 templates
│       └── command_executor.py     # Whitelisted command execution
├── scripts/
│   └── hash_password.py        # Generate bcrypt hash for REAPER_PASSWORD_HASH
├── data/                       # SQLite DB + generated payloads (gitignored)
├── .env.example                # Config template
├── requirements.txt
└── .gitignore
```

### Data Flow

```
psutil / nmap / auth.log / NVD / ip-api.com / msfrpcd / ARP / mDNS
         │
    Flask Backend ──── REST API (/api/*)
         │
    Flask-SocketIO ─── WebSocket broadcasts
         │
    Browser (index.html) ─── Canvas animations + live DOM updates
```

| Data | Interval | Source |
|---|---|---|
| CPU / Memory / Bandwidth | 3s | `psutil` |
| External connections | 3s | `psutil.net_connections()` — public IPs only |
| Top talkers | 3s | Aggregated from connections |
| LAN topology | 30s | ARP table + MAC OUI |
| Local exposure | 30s | `psutil` LISTEN sockets |
| Security alerts | 10s | `/var/log/auth.log` + thresholds |
| System status | 10s | `psutil` + SQLite |
| Metasploit sessions | 5s | `msfrpcd` poll |
| GeoIP | On-demand | ip-api.com (1hr cache) |
| CVSS scores | On-demand | NVD API v2 (24hr cache) |

## WebSocket Events

**Client → Server:**

| Event | Description |
|---|---|
| `request_metrics` | System metrics |
| `request_connections` | External connection table |
| `request_top_talkers` | Top bandwidth consumers |
| `request_alerts` | Security alert feed |
| `request_system_status` | Uptime, hostname, attack surface |
| `request_sessions` | Exploit sessions + kill chain |
| `request_lan_topology` | LAN device list (ARP-based) |
| `request_local_exposure` | Listening ports list |
| `run_iot_scan` | Start full IoT scan (streams progress) |
| `scan_network` | Execute nmap scan |
| `execute_command` | Run terminal command |
| `start_capture` / `stop_capture` | Packet capture control |
| `msf_session_exec` | Execute command in MSF session |

**Server → Client:**

| Event | Description |
|---|---|
| `metrics_update` | CPU, memory, bandwidth, latency |
| `connections_update` | External connection table |
| `top_talkers_update` | Top talkers with GeoIP |
| `alerts_update` | Security alerts |
| `system_status_update` | Uptime, kernel, attack surface |
| `sessions_update` | Sessions + kill chain + compromised hosts |
| `lan_topology_update` | LAN neighbors for topology canvas |
| `local_exposure_update` | Listening ports |
| `iot_scan_progress` | IoT scan progress `{message, percent}` |
| `iot_scan_result` | IoT scan results |
| `capture_stats` | Live packet capture statistics |
| `new_session` | New Metasploit session detected |

## Troubleshooting

**No data on dashboard / metrics show zero:**
Launch with `sudo`. Without root, `psutil.net_connections()` returns limited results and nmap can't do SYN scans.

**Packet capture not working:**
Requires `CAP_NET_RAW`. Run with `sudo` or grant the capability:
```bash
sudo setcap cap_net_raw+eip $(which python3)
```

**WebSocket connects then immediately disconnects:**
Remove `eventlet` if installed — it conflicts with threading mode:
```bash
pip uninstall eventlet -y
```

**Metasploit features show `msf_available: false`:**
Expected when `msfrpcd` isn't running. Start it with `msfrpcd -P yourpassword -S` and set `MSF_PASSWORD` in `.env`.

**IoT scan finds no devices:**
ARP table may be empty on a freshly booted machine. Ping a few LAN hosts first to populate it, or provide the subnet (`192.168.x.0/24`) in the scanner — it will fall back to an nmap ARP ping sweep.

## Security Notice

**This tool is for authorized security testing only.**

- Only use on networks and systems you own or have explicit written permission to test
- Unauthorized scanning, exploitation, or interception is illegal
- Several features require root — understand what you're running
- The terminal executes real commands on your host
- Do not expose to untrusted networks — this runs a development server

## Tech Stack

- **Frontend:** Vanilla HTML/CSS/JavaScript, HTML5 Canvas, Socket.IO client
- **Backend:** Flask 3.x, Flask-SocketIO 5.x, Flask-Login, Flask-SQLAlchemy
- **Database:** SQLite via SQLAlchemy
- **Monitoring:** psutil, subprocess
- **Network:** python-nmap, Scapy, zeroconf (mDNS)
- **Threat Intel:** NVD REST API v2, ip-api.com
- **Offensive:** pymetasploit3, msfvenom
- **Design:** Dark retrofuturism, CRT scan-line aesthetic, HTML5 Canvas node graph

## License

Educational and research use only. See [Security Notice](#security-notice).
