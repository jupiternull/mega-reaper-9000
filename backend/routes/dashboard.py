"""
Dashboard Routes
API endpoints for dashboard functionality — REAL DATA ONLY
"""

from flask import Blueprint, jsonify, request
import psutil
import time
import subprocess
import os
import re
from datetime import datetime

bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')

@bp.route('/status', methods=['GET'])
def get_status():
    """Get real system status"""
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_seconds = int(time.time() - psutil.boot_time())
    h, remainder = divmod(uptime_seconds, 3600)
    m, s = divmod(remainder, 60)
    
    return jsonify({
        'status': 'online',
        'message': 'MEGA REAPER 9000 operational',
        'version': '3.0.0',
        'hostname': os.uname().nodename,
        'uptime': f'{h}:{m:02d}:{s:02d}',
        'boot_time': boot_time.isoformat(),
        'platform': f'{os.uname().sysname} {os.uname().release}'
    })

@bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Get real security-relevant events from system logs and live state"""
    alerts = []
    now = datetime.now()
    
    # Check for failed SSH attempts from auth.log
    try:
        result = subprocess.run(
            ['grep', '-i', 'failed', '/var/log/auth.log'],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout:
            lines = result.stdout.strip().split('\n')[-5:]
            for line in lines:
                alerts.append({
                    'time': _extract_log_time(line),
                    'severity': 'warning',
                    'type': 'Auth Failure',
                    'message': line.strip()[:120],
                    'source': 'auth.log'
                })
    except Exception:
        pass
    
    # Check for listening services on non-standard ports
    try:
        connections = psutil.net_connections(kind='inet')
        listen_ports = set()
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr:
                listen_ports.add(conn.laddr.port)
        
        standard_ports = {22, 53, 80, 443, 5000, 8080, 3306, 5432}
        unusual = listen_ports - standard_ports
        if unusual:
            alerts.append({
                'time': now.strftime('%H:%M:%S'),
                'severity': 'info',
                'type': 'Service Detected',
                'message': f'Non-standard listening ports: {", ".join(str(p) for p in sorted(unusual)[:10])}',
                'source': 'netstat'
            })
    except Exception:
        pass
    
    # Check high resource usage
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        
        if cpu > 80:
            alerts.append({
                'time': now.strftime('%H:%M:%S'),
                'severity': 'critical',
                'type': 'High CPU',
                'message': f'CPU usage critically high: {cpu}%',
                'source': 'sysmon'
            })
        elif cpu > 60:
            alerts.append({
                'time': now.strftime('%H:%M:%S'),
                'severity': 'warning',
                'type': 'Elevated CPU',
                'message': f'CPU usage elevated: {cpu}%',
                'source': 'sysmon'
            })
        
        if mem > 85:
            alerts.append({
                'time': now.strftime('%H:%M:%S'),
                'severity': 'critical',
                'type': 'Memory Pressure',
                'message': f'Memory usage critically high: {mem}%',
                'source': 'sysmon'
            })
    except Exception:
        pass
    
    # Check disk usage
    try:
        disk = psutil.disk_usage('/')
        if disk.percent > 90:
            alerts.append({
                'time': now.strftime('%H:%M:%S'),
                'severity': 'critical',
                'type': 'Disk Full',
                'message': f'Root filesystem {disk.percent}% full ({_format_bytes(disk.free)} free)',
                'source': 'disk'
            })
    except Exception:
        pass
    
    # Check for connections to suspicious ports
    try:
        connections = psutil.net_connections(kind='inet')
        suspicious_ports = {4444, 5555, 6666, 31337, 12345}
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                if conn.raddr.port in suspicious_ports:
                    alerts.append({
                        'time': now.strftime('%H:%M:%S'),
                        'severity': 'critical',
                        'type': 'Suspicious Connection',
                        'message': f'Connection to suspicious port {conn.raddr.port} on {conn.raddr.ip}',
                        'source': 'netmon'
                    })
    except Exception:
        pass
    
    # If no alerts, report all-clear
    if not alerts:
        alerts.append({
            'time': now.strftime('%H:%M:%S'),
            'severity': 'info',
            'type': 'All Clear',
            'message': 'No security events detected — system operating normally',
            'source': 'sysmon'
        })
    
    return jsonify(alerts)


@bp.route('/system-status', methods=['GET'])
def get_system_status():
    """Get real system status details"""
    uptime_seconds = int(time.time() - psutil.boot_time())
    h, remainder = divmod(uptime_seconds, 3600)
    m, s = divmod(remainder, 60)
    
    last_scan = 'Never'
    try:
        result = subprocess.run(
            ['bash', '-c', 'ls -t /tmp/nmap_*.xml 2>/dev/null | head -1'],
            capture_output=True, text=True, timeout=3
        )
        if result.stdout.strip():
            mtime = os.path.getmtime(result.stdout.strip())
            ago = int(time.time() - mtime)
            if ago < 60:
                last_scan = f'{ago}s ago'
            elif ago < 3600:
                last_scan = f'{ago // 60}m ago'
            else:
                last_scan = f'{ago // 3600}h ago'
    except Exception:
        pass
    
    # Attack surface = number of listening ports
    listen_count = 0
    try:
        connections = psutil.net_connections(kind='inet')
        listen_count = sum(1 for c in connections if c.status == 'LISTEN')
    except Exception:
        pass
    
    return jsonify({
        'last_scan': last_scan,
        'uptime': f'{h}:{m:02d}:{s:02d}',
        'attack_surface': listen_count,
        'hostname': os.uname().nodename,
        'kernel': os.uname().release
    })


def _extract_log_time(line):
    """Extract timestamp from syslog line"""
    try:
        parts = line.split()
        if len(parts) >= 3:
            return parts[2]
    except Exception:
        pass
    return datetime.now().strftime('%H:%M:%S')


def _format_bytes(b):
    """Format bytes to human-readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} PB'
