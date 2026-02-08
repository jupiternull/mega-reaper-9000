"""
System Monitoring Service
Provides real-time system metrics for dashboard
"""

import psutil
import time
from collections import defaultdict

class SystemMonitor:
    def __init__(self):
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()
        
    def get_metrics(self):
        """Get current system metrics"""
        
        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory Usage
        memory = psutil.virtual_memory()
        mem_percent = memory.percent
        
        # Network bandwidth
        current_net_io = psutil.net_io_counters()
        current_time = time.time()
        time_delta = current_time - self.last_time
        
        # Calculate bandwidth (bytes per second)
        bytes_sent = (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / time_delta
        bytes_recv = (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / time_delta
        
        # Convert to MB/s
        bandwidth_mbps = (bytes_sent + bytes_recv) / (1024 * 1024)
        
        # Update last values
        self.last_net_io = current_net_io
        self.last_time = current_time
        
        # Network stats
        connections = len(psutil.net_connections(kind='inet'))
        
        # Estimate latency (simplified - would use ping in production)
        latency = self._estimate_latency()
        
        return {
            'cpu_usage': round(cpu_percent, 1),
            'memory_usage': round(mem_percent, 1),
            'bandwidth': round(bandwidth_mbps, 1),
            'latency': latency,
            'hosts_online': self._count_active_hosts(),
            'open_ports': connections,
            'timestamp': int(time.time())
        }
    
    def _estimate_latency(self):
        """Measure actual network latency via ICMP ping to default gateway"""
        import subprocess
        try:
            # Get default gateway
            gw = self._get_default_gateway()
            if not gw:
                gw = '8.8.8.8'  # fallback to Google DNS
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', gw],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Parse "time=X.XX ms" from ping output
                import re
                match = re.search(r'time[=<]([\d.]+)\s*ms', result.stdout)
                if match:
                    return round(float(match.group(1)), 1)
            return 0
        except Exception:
            return 0

    def _get_default_gateway(self):
        """Get the default gateway IP from routing table"""
        import subprocess
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=3
            )
            if result.stdout:
                parts = result.stdout.strip().split()
                if len(parts) >= 3:
                    return parts[2]
        except Exception:
            pass
        return None
    
    def _count_active_hosts(self):
        """Count active hosts on network"""
        # In production, use ARP table or nmap
        # For now, count unique IPs from connections
        try:
            connections = psutil.net_connections(kind='inet')
            unique_ips = set()
            
            for conn in connections:
                if conn.raddr and conn.raddr.ip:
                    unique_ips.add(conn.raddr.ip)
            
            return len(unique_ips) + 1  # +1 for localhost
        except:
            return 0  # Unable to enumerate
    
    def get_detailed_stats(self):
        """Get detailed system statistics"""
        
        # Disk usage
        disk = psutil.disk_usage('/')
        
        # Network interfaces
        net_if_stats = psutil.net_if_stats()
        
        # Process count
        process_count = len(psutil.pids())
        
        return {
            'disk_usage': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            },
            'network_interfaces': {
                iface: {
                    'is_up': stats.isup,
                    'speed': stats.speed,
                    'mtu': stats.mtu
                }
                for iface, stats in net_if_stats.items()
            },
            'process_count': process_count,
            'boot_time': psutil.boot_time()
        }
