#!/usr/bin/env python3
"""
MEGA REAPER 9000 - Security Operations Center
Main Flask Application with WebSocket Support
"""

from flask import Flask, send_from_directory
from flask_socketio import SocketIO
from flask_cors import CORS
import os
import sys
import json
import time as _time

# Add backend directory to path
sys.path.insert(0, os.path.dirname(__file__))

from routes import dashboard, tools, exploits
from services.network_scanner import NetworkScanner
from services.system_monitor import SystemMonitor
from services.device_identifier import DeviceIdentifier

# Initialize Flask app
app = Flask(__name__, 
            static_folder='../frontend',
            template_folder='../frontend')

app.config['SECRET_KEY'] = 'mega-reaper-9000-ultra-secure-key'
CORS(app)

# Initialize SocketIO — threading mode, no eventlet needed
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize services
network_scanner = NetworkScanner()
system_monitor = SystemMonitor()
device_identifier = DeviceIdentifier()

# Register blueprints
app.register_blueprint(dashboard.bp)
app.register_blueprint(tools.bp)
app.register_blueprint(exploits.bp)

# Serve frontend
@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

# Network device inventory API
@app.route('/api/devices/inventory')
def get_device_inventory():
    """Return all identified devices on the local network"""
    devices = device_identifier.get_network_inventory()
    return json.dumps(devices)


# ─── Helper: build alerts data without Flask request context ─────────
def _get_alerts_data():
    """Get security alerts using direct system calls instead of route functions"""
    import psutil
    import subprocess
    alerts = []
    
    # Check auth.log for recent failures
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
    
    # Check resource usage
    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory().percent
    if cpu > 80:
        alerts.append({'type': 'resource', 'severity': 'critical', 'message': f'CPU usage critical: {cpu}%', 'timestamp': _time.strftime('%H:%M:%S')})
    if mem > 85:
        alerts.append({'type': 'resource', 'severity': 'critical', 'message': f'Memory usage critical: {mem}%', 'timestamp': _time.strftime('%H:%M:%S')})
    
    # Check disk
    disk = psutil.disk_usage('/').percent
    if disk > 90:
        alerts.append({'type': 'resource', 'severity': 'warning', 'message': f'Disk usage high: {disk}%', 'timestamp': _time.strftime('%H:%M:%S')})
    
    # Check for suspicious listening ports
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
    
    return alerts


def _get_system_status_data():
    """Get system status using direct system calls"""
    import psutil
    import subprocess
    
    uptime_seconds = int(_time.time() - psutil.boot_time())
    h, remainder = divmod(uptime_seconds, 3600)
    m, s = divmod(remainder, 60)
    
    # Last scan
    last_scan = 'Never'
    try:
        result = subprocess.run(
            ['bash', '-c', 'ls -t /tmp/nmap_*.xml 2>/dev/null | head -1'],
            capture_output=True, text=True, timeout=3
        )
        if result.stdout.strip():
            mtime = os.path.getmtime(result.stdout.strip())
            ago = int(_time.time() - mtime)
            if ago < 60:
                last_scan = f'{ago}s ago'
            elif ago < 3600:
                last_scan = f'{ago // 60}m ago'
            else:
                last_scan = f'{ago // 3600}h ago'
    except Exception:
        pass
    
    # Attack surface = listening ports
    listening = len([c for c in psutil.net_connections(kind='inet') if c.status == 'LISTEN'])
    
    uname = os.uname()
    
    return {
        'uptime': f'{h}:{m:02d}:{s:02d}',
        'last_scan': last_scan,
        'attack_surface': listening,
        'hostname': uname.nodename,
        'kernel': uname.release
    }


def _get_sessions_data():
    """Get exploit session state"""
    from routes.exploits import active_sessions, killchain_state, compromised_hosts
    now = _time.time()
    
    sessions = []
    for sid, s in active_sessions.items():
        elapsed = int(now - s.get('_created', now))
        s_copy = dict(s)
        s_copy['last_seen'] = f'{elapsed}s ago' if elapsed < 60 else f'{elapsed // 60}m ago'
        sessions.append(s_copy)
    
    hosts = []
    for ip, h in compromised_hosts.items():
        elapsed = int(now - h.get('_created', now))
        h_copy = dict(h)
        h_copy['last_seen'] = f'{elapsed}s ago' if elapsed < 60 else f'{elapsed // 60}m ago'
        hosts.append(h_copy)
    
    return {
        'sessions': sessions,
        'compromised': hosts,
        'killchain': killchain_state
    }


# ─── WebSocket Event Handlers ────────────────────────────────────────
# Use flask.request.sid (set by Flask-SocketIO during handler execution)
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

@socketio.on('scan_network')
def handle_network_scan(data):
    sid = flask.request.sid
    target = data.get('target', '192.168.1.0/24')
    scan_type = data.get('scan_type', 'quick')
    
    socketio.emit('scan_started', {'message': f'Scanning {target}...'}, to=sid)
    results = network_scanner.scan(target, scan_type)
    socketio.emit('scan_complete', results, to=sid)

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


# ─── Background Tasks ────────────────────────────────────────────────
# socketio.emit() without `to=` broadcasts to all connected clients

def background_metrics_update():
    """Broadcast real-time metrics every 3 seconds"""
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

def background_alerts_update():
    """Broadcast alerts and session state every 10 seconds"""
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
    
    MEGA REAPER 9000 - Security Operations Center v3.0.0
    Starting server on http://0.0.0.0:5000
    """)
    
    # Start background tasks
    socketio.start_background_task(background_metrics_update)
    socketio.start_background_task(background_alerts_update)
    
    # Run server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
