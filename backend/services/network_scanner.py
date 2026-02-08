"""
Network Scanner Service
Integrates nmap and provides network discovery functionality
"""

import nmap
import psutil
import socket
from collections import defaultdict
from datetime import datetime

# Import DeviceIdentifier for enriching connections with device info
try:
    from services.device_identifier import DeviceIdentifier
    _device_id = DeviceIdentifier()
except ImportError:
    _device_id = None

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = {}
        self.connection_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        self.device_identifier = _device_id or DeviceIdentifier()
        
    def scan(self, target, scan_type='quick'):
        """
        Execute nmap scan on target
        
        Args:
            target: IP address or CIDR range (e.g., '192.168.1.0/24')
            scan_type: 'quick', 'intense', 'stealth', 'comprehensive'
        
        Returns:
            dict: Scan results with discovered hosts and ports
        """
        
        # Map scan types to nmap arguments
        scan_profiles = {
            'quick': '-T4 -F',
            'intense': '-T4 -A -v',
            'stealth': '-sS -T2',
            'version': '-sV',
            'os': '-O',
            'comprehensive': '-sS -sV -O -A'
        }
        
        args = scan_profiles.get(scan_type, '-T4 -F')
        
        try:
            print(f"[*] Scanning {target} with args: {args}")
            self.nm.scan(hosts=target, arguments=args)
            
            results = {
                'target': target,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'hosts': []
            }
            
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': self.nm[host].hostname() or 'Unknown',
                    'state': self.nm[host].state(),
                    'ports': [],
                    'os': None,
                    'services': []
                }
                
                # Get open ports
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        host_info['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', '')
                        })
                        
                        # Track services
                        if port_info['state'] == 'open':
                            host_info['services'].append(port_info.get('name', 'unknown'))
                
                # OS detection if available
                if 'osmatch' in self.nm[host]:
                    if self.nm[host]['osmatch']:
                        host_info['os'] = self.nm[host]['osmatch'][0]['name']
                
                results['hosts'].append(host_info)
            
            self.scan_results[target] = results
            return results
            
        except Exception as e:
            return {
                'error': str(e),
                'target': target,
                'timestamp': datetime.now().isoformat()
            }
    
    def get_active_connections(self):
        """Get currently active network connections"""
        
        try:
            connections = psutil.net_connections(kind='inet')
            active_conns = []
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    conn_info = {
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                        'state': conn.status,
                        'pid': conn.pid
                    }
                    
                    # Enrich with device identification
                    if conn.raddr and conn.raddr.ip:
                        try:
                            dev_info = self.device_identifier.identify(conn.raddr.ip)
                            conn_info['device'] = {
                                'manufacturer': dev_info.get('manufacturer'),
                                'hostname': dev_info.get('hostname'),
                                'device_type': dev_info.get('device_type'),
                                'icon': dev_info.get('icon'),
                                'friendly_name': dev_info.get('friendly_name'),
                                'mac': dev_info.get('mac')
                            }
                        except Exception:
                            conn_info['device'] = None
                    
                    # Estimate bytes transferred (simplified)
                    conn_key = f"{conn_info['local_addr']}->{conn_info['remote_addr']}"
                    conn_info['bytes'] = self.connection_stats[conn_key]['bytes']
                    
                    active_conns.append(conn_info)
            
            return active_conns[:20]  # Limit to top 20
            
        except Exception as e:
            print(f"[!] Error getting connections: {e}")
            return []
    
    def get_top_talkers(self):
        """Get hosts with highest connection count (real data from psutil)"""
        
        try:
            connections = psutil.net_connections(kind='inet')
            host_stats = defaultdict(lambda: {'conn_count': 0, 'ports': set(), 'protocol': 'TCP'})
            
            # Aggregate by remote IP — count connections and unique ports
            for conn in connections:
                if conn.raddr and conn.raddr.ip:
                    ip = conn.raddr.ip
                    host_stats[ip]['conn_count'] += 1
                    host_stats[ip]['ports'].add(conn.raddr.port)
                    
                    if conn.type == socket.SOCK_STREAM:
                        if conn.raddr.port == 443:
                            host_stats[ip]['protocol'] = 'HTTPS'
                        elif conn.raddr.port == 80:
                            host_stats[ip]['protocol'] = 'HTTP'
                        elif conn.raddr.port == 22:
                            host_stats[ip]['protocol'] = 'SSH'
                        elif conn.raddr.port == 53:
                            host_stats[ip]['protocol'] = 'DNS'
                        else:
                            host_stats[ip]['protocol'] = 'TCP'
                    else:
                        host_stats[ip]['protocol'] = 'UDP'
            
            # Get total network I/O for proportional estimation
            net_io = psutil.net_io_counters()
            total_bytes = net_io.bytes_sent + net_io.bytes_recv
            total_packets = net_io.packets_sent + net_io.packets_recv
            total_conns = sum(s['conn_count'] for s in host_stats.values()) or 1
            
            # Sort by connection count (most active first)
            top_talkers = []
            for ip, stats in sorted(host_stats.items(), key=lambda x: x[1]['conn_count'], reverse=True)[:5]:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ip
                
                # Device identification
                dev_info = {}
                try:
                    dev_info = self.device_identifier.identify(ip)
                    # Prefer device-resolved hostname over DNS
                    if dev_info.get('hostname'):
                        hostname = dev_info['hostname']
                except Exception:
                    pass
                
                # Proportional estimate of bytes/packets based on connection share
                share = stats['conn_count'] / total_conns
                
                top_talkers.append({
                    'ip': ip,
                    'hostname': hostname,
                    'bytes': int(total_bytes * share),
                    'packets': int(total_packets * share),
                    'protocol': stats['protocol'],
                    'connections': stats['conn_count'],
                    'device': {
                        'manufacturer': dev_info.get('manufacturer'),
                        'device_type': dev_info.get('device_type'),
                        'icon': dev_info.get('icon'),
                        'friendly_name': dev_info.get('friendly_name'),
                        'mac': dev_info.get('mac')
                    }
                })
            
            return top_talkers
            
        except Exception as e:
            print(f"[!] Error getting top talkers: {e}")
            return []
    
    def port_scan(self, target, ports='1-1000', protocol='tcp'):
        """Quick port scan"""
        
        try:
            port_arg = f'-p {ports}'
            self.nm.scan(hosts=target, arguments=port_arg)
            
            results = []
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    for port in self.nm[target][proto].keys():
                        port_info = self.nm[target][proto][port]
                        if port_info['state'] == 'open':
                            results.append({
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', '')
                            })
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
