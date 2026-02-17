# MEGA REAPER 9000

**Real-Time Security Operations Dashboard**

A network monitoring and security testing platform with live system metrics, connection tracking, and integrated offensive security tools. All data is real, pulled live from your machine via `psutil`, `nmap`, and system calls. Zero simulated data.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Flask](https://img.shields.io/badge/Flask-3.0+-green) ![License](https://img.shields.io/badge/License-Educational-red)

---
<img width="2400" height="1350" alt="Screenshot from 2026-02-11 22-05-41" src="https://github.com/user-attachments/assets/5f3086c3-2b38-4170-b478-3fb98b4d09d1" />
<img width="2400" height="1350" alt="Screenshot from 2026-02-11 22-06-05" src="https://github.com/user-attachments/assets/46c93048-a9c3-427f-94c5-1be03418bb11" />
<img width="2400" height="1350" alt="Screenshot from 2026-02-11 22-06-18" src="https://github.com/user-attachments/assets/310b9dde-596d-4b59-a879-aa033adc1c45" />


## Features

**Live Dashboard**
- Real-time CPU, memory, bandwidth, and latency metrics
- Active network connections with protocol, state, and remote host info
- Top talkers ranked by connection count with proportional bandwidth estimates
- Animated network topology and connection map
- Security alerts parsed from `/var/log/auth.log` and system state
- System status with uptime, attack surface (listening ports), and kernel info

**GUI Security Tools**
- **Nmap Scanner** — network discovery and port scanning
- **Port Scanner** — fast TCP enumeration
- **Vulnerability Scanner** — `nmap --script vuln` integration
- **DNS Enumeration** — `dig` A/MX/NS/TXT lookups
- **Web Scanner** — `nikto` or header analysis fallback
- **Packet Capture** — `tcpdump` integration
- **Brute Force** — `hydra` authentication testing
- **Exploit DB** — search and track exploit sessions
- **Report Generator** — export assessment reports

**Terminal Mode**
- Integrated terminal that executes real commands on the host
- Whitelisted command set for safety (nmap, ping, dig, netstat, etc.)

**Attack Operations**
- Track active exploit sessions and kill chain progress
- Compromised host registry
- All starts empty — populated only by your actions

## Requirements

- **OS:** Linux (tested on Ubuntu 24.04)
- **Python:** 3.10+
- **Root access:** Required for SYN scans, full connection enumeration, and packet capture

### System Tools

```bash
sudo apt install nmap dnsutils tcpdump nikto hydra
```

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/mega-reaper-9000.git
cd mega-reaper-9000

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Launch with sudo (required for full functionality)
sudo ./venv/bin/python3 backend/app.py
```

Open your browser to **http://localhost:5000**

> **Note:** If `sudo ./venv/bin/python3` gives "command not found", use the full path:
> `sudo /home/YOUR_USER/path/to/mega-reaper-9000/venv/bin/python3 backend/app.py`

## Architecture

```
mega-reaper-9000/
├── frontend/
│   └── index.html          # Single-page dashboard (vanilla HTML/CSS/JS)
├── backend/
│   ├── app.py              # Flask + SocketIO server
│   ├── routes/
│   │   ├── dashboard.py    # System status & alerts API
│   │   ├── tools.py        # Security tool API endpoints
│   │   └── exploits.py     # Exploit session management
│   └── services/
│       ├── network_scanner.py    # psutil connections + nmap integration
│       ├── system_monitor.py     # CPU, memory, bandwidth, latency
│       ├── device_identifier.py  # LAN device identification (MAC OUI + hostname)
│       └── command_executor.py   # Whitelisted command execution
├── requirements.txt
└── .gitignore
```

### How Data Flows

```
psutil / subprocess / nmap
         │
    Flask Backend ──── REST API (/api/*)
         │
    Flask-SocketIO ─── WebSocket broadcasts every 3-10s
         │
    Browser (index.html) ─── Canvas animations + live DOM updates
```

| Data Source | Update Interval | Method |
|---|---|---|
| CPU / Memory / Bandwidth | 3 seconds | WebSocket broadcast |
| Active Connections | 3 seconds | `psutil.net_connections()` |
| Top Talkers | 3 seconds | Aggregated connection counts |
| Security Alerts | 10 seconds | `/var/log/auth.log` + system checks |
| System Status | 10 seconds | `psutil.boot_time()` + listening ports |
| Exploit Sessions | 10 seconds | In-memory state |

## API Reference

### REST Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard/status` | System status (uptime, hostname, attack surface) |
| `GET` | `/api/dashboard/alerts` | Security alerts from auth.log + system state |
| `GET` | `/api/devices/inventory` | Identified LAN devices |
| `POST` | `/api/tools/nmap/scan` | Execute nmap scan |
| `POST` | `/api/tools/portscan` | Port scan |
| `POST` | `/api/tools/vulnscan` | Vulnerability scan |
| `POST` | `/api/tools/dnsenum` | DNS enumeration |
| `POST` | `/api/tools/webscan` | Web application scan |
| `POST` | `/api/tools/capture` | Packet capture |
| `GET` | `/api/exploits/sessions` | Active exploit sessions |
| `POST` | `/api/exploits/launch` | Launch exploit |
| `GET` | `/api/exploits/compromised` | Compromised hosts |
| `GET` | `/api/exploits/killchain` | Kill chain state |

### WebSocket Events

**Client → Server:**
- `request_metrics` — request system metrics
- `request_connections` — request active connections
- `request_top_talkers` — request bandwidth leaders
- `request_alerts` — request security alerts
- `request_system_status` — request system status
- `request_sessions` — request exploit sessions
- `request_devices` — request LAN device inventory
- `scan_network` — execute network scan
- `execute_command` — run terminal command

**Server → Client (broadcasts):**
- `metrics_update` — CPU, memory, bandwidth, latency, host count
- `connections_update` — active connection table
- `top_talkers_update` — top bandwidth consumers
- `alerts_update` — security alert feed
- `system_status_update` — uptime, attack surface, kernel
- `sessions_update` — exploit sessions + kill chain + compromised hosts
- `devices_update` — identified LAN devices

## Troubleshooting

**"command not found" when using sudo:**
The venv Python binary must exist. Run `python3 -m venv venv` first, then use the full path with sudo.

**Dashboard loads but no live data:**
Make sure you launched with `sudo`. Without root, `psutil.net_connections()` can't enumerate all connections and nmap can't do SYN scans.

**WebSocket connects then immediately disconnects:**
If `eventlet` is installed in your venv, remove it: `pip uninstall eventlet -y`. The server uses threading mode which is incompatible with eventlet.

**"Too many packets in payload" error:**
One-time race condition on reconnect. Refresh the browser — it resolves itself.

## Security Notice

⚠️ **This tool is for authorized security testing only.**

- Only use on networks and systems you own or have explicit written permission to test
- Unauthorized scanning or exploitation is illegal under the CFAA and equivalent laws
- Several features require root privileges — understand what you're running
- The terminal executes real commands on your host via a whitelisted set
- This is a development server — do not expose to untrusted networks

## Tech Stack

- **Frontend:** Vanilla HTML/CSS/JavaScript, HTML5 Canvas, Socket.IO client
- **Backend:** Flask 3.x, Flask-SocketIO 5.x, python-socketio (threading mode)
- **Monitoring:** psutil, subprocess
- **Security Tools:** nmap, dig, nikto, hydra, tcpdump
- **Design:** Dark retrofuturism aesthetic, CRT-style animations

## License

Educational and research use only. See [Security Notice](#security-notice).
