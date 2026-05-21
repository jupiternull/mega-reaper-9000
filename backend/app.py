#!/usr/bin/env python3
"""
MEGA REAPER 9000 - Security Operations Center
Main Flask Application with WebSocket Support
"""

import os
import sys
import json
import time as _time

# Load .env before anything else
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, send_from_directory
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_login import login_required

from database import db
from auth import login_manager, bp as auth_bp
from routes import dashboard, tools, exploits, msf as msf_routes
from services.network_scanner import NetworkScanner
from services.system_monitor import SystemMonitor
from services.device_identifier import DeviceIdentifier
from services.geoip import lookup as geoip_lookup, lookup_batch as geoip_batch
from services.packet_capture import capture as packet_capture
from services import msf as msf_service
from services.iot_scanner import IoTScanner

# ── App init ─────────────────────────────────────────────────────────
app = Flask(__name__,
            static_folder='../frontend',
            template_folder='../frontend')

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    f"sqlite:///{os.path.join(os.path.dirname(__file__), '..', 'data', 'reaper.db')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure data directory exists
os.makedirs(os.path.join(os.path.dirname(__file__), '..', 'data'), exist_ok=True)

CORS(app, supports_credentials=True)
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login_page'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── Services ─────────────────────────────────────────────────────────
network_scanner = NetworkScanner()
system_monitor = SystemMonitor()
device_identifier = DeviceIdentifier()
iot_scanner = IoTScanner()

# ── Blueprints ───────────────────────────────────────────────────────
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard.bp)
app.register_blueprint(tools.bp)
app.register_blueprint(exploits.bp)
app.register_blueprint(msf_routes.bp)

# ── Create tables on first run ───────────────────────────────────────
with app.app_context():
    db.create_all()

# ── Frontend ─────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    return send_from_directory('../frontend', 'index.html')

# ── Device inventory API ─────────────────────────────────────────────
@app.route('/api/devices/inventory')
@login_required
def get_device_inventory():
    devices = device_identifier.get_network_inventory()
    return json.dumps(devices)


# ── Scan history API ─────────────────────────────────────────────────
@app.route('/api/history/scans')
@login_required
def get_scan_history():
    from database import ScanResult
    with app.app_context():
        scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).limit(50).all()
        return json.dumps([s.to_dict() for s in scans])


@app.route('/api/history/alerts')
@login_required
def get_alert_history():
    from database import AlertLog
    with app.app_context():
        alerts = AlertLog.query.order_by(AlertLog.timestamp.desc()).limit(200).all()
        return json.dumps([a.to_dict() for a in alerts])


@app.route('/api/geoip/<ip>')
@login_required
def geoip_single(ip):
    return json.dumps(geoip_lookup(ip))


@app.route('/api/geoip/batch', methods=['POST'])
@login_required
def geoip_batch_lookup():
    ips = flask.request.get_json(silent=True) or []
    if not isinstance(ips, list):
        return json.dumps({'error': 'Expected list of IPs'}), 400
    return json.dumps(geoip_batch(ips[:50]))


@app.route('/api/capture/status')
@login_required
def capture_status():
    return json.dumps(packet_capture.get_stats())


@app.route('/api/capture/start', methods=['POST'])
@login_required
def capture_start():
    data = flask.request.get_json(silent=True) or {}
    iface = data.get('interface')
    pkt_filter = data.get('filter', 'ip')
    result = packet_capture.start(interface=iface, packet_filter=pkt_filter)
    return json.dumps(result)


@app.route('/api/capture/stop', methods=['POST'])
@login_required
def capture_stop():
    return json.dumps(packet_capture.stop())


# ── Helpers ──────────────────────────────────────────────────────────
def _get_alerts_data():
    import psutil, subprocess
    alerts = []

    try:
        result = subprocess.run(
            ['bash', '-c', 'grep -i "failed\\|invalid\\|error" /var/log/auth.log 2>/dev/null | tail -5'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                alerts.append({
                    'type': 'auth',
                    'severity': 'warning',
                    'message': line.strip()[:120],
                    'timestamp': _time.strftime('%H:%M:%S')
                })
    except Exception:
        pass

    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory().percent
    if cpu > 80:
        alerts.append({'type': 'resource', 'severity': 'critical', 'message': f'CPU usage critical: {cpu}%', 'timestamp': _time.strftime('%H:%M:%S')})
    if mem > 85:
        alerts.append({'type': 'resource', 'severity': 'critical', 'message': f'Memory usage critical: {mem}%', 'timestamp': _time.strftime('%H:%M:%S')})

    disk = psutil.disk_usage('/').percent
    if disk > 90:
        alerts.append({'type': 'resource', 'severity': 'warning', 'message': f'Disk usage high: {disk}%', 'timestamp': _time.strftime('%H:%M:%S')})

    suspicious = [23, 69, 135, 139, 445, 3389, 5900, 6667]
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN' and conn.laddr and conn.laddr.port in suspicious:
            alerts.append({
                'type': 'network',
                'severity': 'critical',
                'message': f'Suspicious port open: {conn.laddr.port}',
                'timestamp': _time.strftime('%H:%M:%S')
            })

    if not alerts:
        alerts.append({'type': 'info', 'severity': 'info', 'message': 'No security events detected', 'timestamp': _time.strftime('%H:%M:%S')})

    # Persist non-info alerts
    _persist_alerts(alerts)
    return alerts


def _persist_alerts(alerts):
    from database import AlertLog
    try:
        with app.app_context():
            for a in alerts:
                if a.get('severity') != 'info':
                    db.session.add(AlertLog(
                        alert_type=a.get('type'),
                        severity=a.get('severity'),
                        message=a.get('message'),
                        source='sysmon',
                    ))
            db.session.commit()
    except Exception:
        pass


def _get_system_status_data():
    import psutil, subprocess
    uptime_seconds = int(_time.time() - psutil.boot_time())
    h, remainder = divmod(uptime_seconds, 3600)
    m, s = divmod(remainder, 60)

    last_scan = 'Never'
    try:
        from database import ScanResult
        with app.app_context():
            latest = ScanResult.query.order_by(ScanResult.timestamp.desc()).first()
            if latest:
                ago = int(_time.time() - latest.timestamp.timestamp())
                if ago < 60:
                    last_scan = f'{ago}s ago'
                elif ago < 3600:
                    last_scan = f'{ago // 60}m ago'
                else:
                    last_scan = f'{ago // 3600}h ago'
    except Exception:
        pass

    listening = len([c for c in psutil.net_connections(kind='inet') if c.status == 'LISTEN'])
    uname = os.uname()

    return {
        'uptime': f'{h}:{m:02d}:{s:02d}',
        'last_scan': last_scan,
        'attack_surface': listening,
        'hostname': uname.nodename,
        'kernel': uname.release
    }


_SUSPICIOUS_LISTEN = {23, 69, 135, 139, 445, 3389, 4444, 5555, 5900, 6667}
_WELL_KNOWN_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3000: 'HTTP-dev', 3306: 'MySQL', 3389: 'RDP', 5000: 'Flask',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-alt',
    8443: 'HTTPS-alt', 8888: 'HTTP-proxy', 9200: 'Elasticsearch',
    27017: 'MongoDB', 1883: 'MQTT', 554: 'RTSP', 9100: 'IPP/Print',
}


def _get_local_exposure_data():
    import psutil, socket as _socket
    seen = set()
    ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status != 'LISTEN' or not conn.laddr:
            continue
        key = (conn.laddr.ip, conn.laddr.port)
        if key in seen:
            continue
        seen.add(key)
        port = conn.laddr.port
        iface = conn.laddr.ip if conn.laddr.ip not in ('0.0.0.0', '::') else '*'
        service = _WELL_KNOWN_PORTS.get(port)
        if not service:
            try:
                service = _socket.getservbyport(port)
            except Exception:
                service = 'unknown'
        ports.append({
            'port': port,
            'interface': iface,
            'service': service,
            'suspicious': port in _SUSPICIOUS_LISTEN,
        })
    return sorted(ports, key=lambda p: p['port'])


def _get_sessions_data():
    from database import ExploitSession, CompromisedHost
    from routes.exploits import killchain_state

    try:
        with app.app_context():
            sessions = [s.to_dict() for s in ExploitSession.query.filter_by(status='launched').all()]
            hosts = [h.to_dict() for h in CompromisedHost.query.all()]
    except Exception:
        sessions, hosts = [], []

    return {
        'sessions': sessions,
        'compromised': hosts,
        'killchain': killchain_state
    }


# ── WebSocket handlers ───────────────────────────────────────────────
import flask

@socketio.on('connect')
def handle_connect():
    sid = flask.request.sid
    print(f'[+] Client connected: {sid}')
    socketio.emit('connection_response', {'status': 'connected', 'message': 'MEGA REAPER 9000 ONLINE'}, to=sid)

@socketio.on('disconnect')
def handle_disconnect():
    print('[-] Client disconnected')

@socketio.on('request_metrics')
def handle_metrics_request():
    sid = flask.request.sid
    metrics = system_monitor.get_metrics()
    socketio.emit('metrics_update', metrics, to=sid)

@socketio.on('request_connections')
def handle_connections_request():
    sid = flask.request.sid
    connections = network_scanner.get_active_connections()
    socketio.emit('connections_update', connections, to=sid)

@socketio.on('request_top_talkers')
def handle_top_talkers_request():
    sid = flask.request.sid
    talkers = network_scanner.get_top_talkers()
    socketio.emit('top_talkers_update', talkers, to=sid)

@socketio.on('request_alerts')
def handle_alerts_request():
    sid = flask.request.sid
    alerts = _get_alerts_data()
    socketio.emit('alerts_update', alerts, to=sid)

@socketio.on('request_system_status')
def handle_system_status_request():
    sid = flask.request.sid
    status = _get_system_status_data()
    socketio.emit('system_status_update', status, to=sid)

@socketio.on('request_sessions')
def handle_sessions_request():
    sid = flask.request.sid
    data = _get_sessions_data()
    socketio.emit('sessions_update', data, to=sid)

@socketio.on('request_devices')
def handle_devices_request():
    sid = flask.request.sid
    devices = device_identifier.get_network_inventory()
    socketio.emit('devices_update', devices, to=sid)

@socketio.on('request_lan_topology')
def handle_lan_topology_request():
    sid = flask.request.sid
    devices = iot_scanner.get_lan_topology()
    socketio.emit('lan_topology_update', devices, to=sid)

@socketio.on('request_local_exposure')
def handle_local_exposure_request():
    sid = flask.request.sid
    ports = _get_local_exposure_data()
    socketio.emit('local_exposure_update', ports, to=sid)

@socketio.on('run_iot_scan')
def handle_iot_scan(data):
    sid = flask.request.sid
    if iot_scanner.is_scanning:
        socketio.emit('iot_scan_error', {'error': 'Scan already in progress'}, to=sid)
        return
    subnet = (data or {}).get('subnet')

    def _run():
        def _progress(msg, pct):
            socketio.emit('iot_scan_progress', {'message': msg, 'percent': pct}, to=sid)
        results = iot_scanner.scan(subnet=subnet, progress_cb=_progress)
        if isinstance(results, list):
            socketio.emit('iot_scan_result', {'devices': results}, to=sid)
        else:
            socketio.emit('iot_scan_error', results, to=sid)

    socketio.start_background_task(_run)

@socketio.on('scan_network')
def handle_network_scan(data):
    sid = flask.request.sid
    target = data.get('target', '192.168.1.0/24')
    scan_type = data.get('scan_type', 'quick')
    socketio.emit('scan_started', {'message': f'Scanning {target}...'}, to=sid)
    results = network_scanner.scan(target, scan_type)
    # Persist scan result
    try:
        from database import ScanResult
        with app.app_context():
            row = ScanResult(
                target=target,
                scan_type=scan_type,
                hosts_found=len(results.get('hosts', [])),
            )
            row.results = results
            db.session.add(row)
            db.session.commit()
    except Exception:
        pass
    socketio.emit('scan_complete', results, to=sid)

@socketio.on('request_capture_stats')
def handle_capture_stats():
    sid = flask.request.sid
    socketio.emit('capture_stats', packet_capture.get_stats(), to=sid)

@socketio.on('start_capture')
def handle_start_capture(data):
    sid = flask.request.sid
    iface = data.get('interface') if data else None
    pkt_filter = data.get('filter', 'ip') if data else 'ip'
    result = packet_capture.start(interface=iface, packet_filter=pkt_filter)
    socketio.emit('capture_started', result, to=sid)

@socketio.on('stop_capture')
def handle_stop_capture():
    sid = flask.request.sid
    result = packet_capture.stop()
    socketio.emit('capture_stopped', result, to=sid)

@socketio.on('msf_session_exec')
def handle_msf_exec(data):
    sid = flask.request.sid
    session_id = data.get('session_id')
    cmd = data.get('cmd', '').strip()
    if not session_id or not cmd:
        socketio.emit('session_output', {'error': 'session_id and cmd required'}, to=sid)
        return
    result = msf_service.session_exec(session_id, cmd)
    socketio.emit('session_output', result, to=sid)

@socketio.on('msf_status')
def handle_msf_status():
    sid = flask.request.sid
    socketio.emit('msf_status_update', msf_service.status(), to=sid)

@socketio.on('execute_command')
def handle_command(data):
    sid = flask.request.sid
    command = data.get('command', '')
    if not command:
        socketio.emit('command_output', {'output': '[!] No command provided', 'error': True}, to=sid)
        return
    from services.command_executor import CommandExecutor
    executor = CommandExecutor()
    result = executor.execute(command)
    socketio.emit('command_output', result, to=sid)


# ── Background tasks ─────────────────────────────────────────────────
def background_metrics_update():
    while True:
        socketio.sleep(3)
        try:
            metrics = system_monitor.get_metrics()
            connections = network_scanner.get_active_connections()
            talkers = network_scanner.get_top_talkers()
            socketio.emit('metrics_update', metrics)
            socketio.emit('connections_update', connections)
            socketio.emit('top_talkers_update', talkers)
        except Exception as e:
            print(f"[!] Background metrics error: {e}")

def background_msf_poll():
    """
    Poll msfrpcd every 5 seconds for new sessions.
    Auto-registers new sessions as compromised hosts and advances kill chain.
    """
    seen_sessions = set()
    while True:
        socketio.sleep(5)
        try:
            result = msf_service.get_sessions()
            if not result.get('msf_available'):
                continue

            from database import CompromisedHost, db
            from routes.exploits import killchain_state, _advance_killchain

            for session in result.get('sessions', []):
                sid = str(session.get('id', ''))
                if sid in seen_sessions:
                    continue
                seen_sessions.add(sid)

                # Extract target IP from tunnel_peer (format: "IP:PORT")
                tunnel_peer = session.get('tunnel_peer', '')
                target_ip = tunnel_peer.split(':')[0] if ':' in tunnel_peer else tunnel_peer

                if target_ip:
                    with app.app_context():
                        existing = CompromisedHost.query.filter_by(ip=target_ip).first()
                        if not existing:
                            host = CompromisedHost(
                                ip=target_ip,
                                hostname=session.get('info', 'unknown'),
                                os=session.get('platform', 'unknown'),
                                privilege='SYSTEM' if 'SYSTEM' in session.get('info', '').upper() else 'user',
                                shell=session.get('type', 'meterpreter'),
                                loot=0,
                            )
                            db.session.add(host)
                            db.session.commit()
                            print(f'[+] Auto-registered compromised host: {target_ip}')

                # Advance kill chain on real session open
                _advance_killchain('EXPLOIT')
                _advance_killchain('INSTALL')

                # Broadcast new session to all clients
                socketio.emit('new_session', {
                    'session': session,
                    'target_ip': target_ip,
                    'message': f'New {session.get("type","?")} session from {target_ip}',
                })

        except Exception as e:
            print(f'[!] MSF poll error: {e}')


def background_lan_update():
    """Broadcast LAN topology and local exposure every 30 seconds."""
    while True:
        socketio.sleep(30)
        try:
            devices = iot_scanner.get_lan_topology()
            socketio.emit('lan_topology_update', devices)
            ports = _get_local_exposure_data()
            socketio.emit('local_exposure_update', ports)
        except Exception as e:
            print(f"[!] LAN topology error: {e}")


def background_capture_update():
    """Broadcast packet capture stats every 2 seconds when capture is running."""
    while True:
        socketio.sleep(2)
        try:
            stats = packet_capture.get_stats()
            if stats.get('running'):
                socketio.emit('capture_stats', stats)
        except Exception as e:
            print(f"[!] Capture broadcast error: {e}")

def background_alerts_update():
    while True:
        socketio.sleep(10)
        try:
            alerts = _get_alerts_data()
            socketio.emit('alerts_update', alerts)
            status = _get_system_status_data()
            socketio.emit('system_status_update', status)
        except Exception as e:
            print(f"[!] Background alerts error: {e}")
        try:
            data = _get_sessions_data()
            socketio.emit('sessions_update', data)
        except Exception as e:
            print(f"[!] Background sessions error: {e}")


if __name__ == '__main__':
    print("""
    ╔═╗ ╔═╗╔═╗╔═╗  ╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗  ╔═╗╔═╗╔═╗╔═╗
    ║║║ ║╣ ║ ╦╠═╣  ╠╦╝║╣ ╠═╣╠═╝║╣ ╠╦╝  ║ ║║ ║║ ║║ ║
    ╩ ╩ ╚═╝╚═╝╩ ╩  ╩╚═╚═╝╩ ╩╩  ╚═╝╩╚═  ╚═╝╚═╝╚═╝╚═╝

    MEGA REAPER 9000 - Security Operations Center v3.1.0
    Starting server on http://0.0.0.0:5000
    """)
    socketio.start_background_task(background_metrics_update)
    socketio.start_background_task(background_alerts_update)
    socketio.start_background_task(background_capture_update)
    socketio.start_background_task(background_msf_poll)
    socketio.start_background_task(background_lan_update)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
