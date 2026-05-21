"""
Packet capture service using Scapy.
Runs a background sniffing thread per interface.
Decodes protocols, tracks flows, and maintains rolling stats.
Requires CAP_NET_RAW or root for raw socket access.
"""

import threading
import time
import socket
from collections import defaultdict, deque

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

_PROTO_MAP = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}

# Rolling window: keep last 500 packets
_MAX_PACKETS = 500
_MAX_FLOWS = 200


class PacketCapture:
    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._interface = None

        # Rolling packet log
        self._packets: deque = deque(maxlen=_MAX_PACKETS)

        # Protocol counts (reset on each start)
        self._proto_counts: dict = defaultdict(int)

        # Flow table: {(src_ip, dst_ip, dst_port, proto): {bytes, packets, last_seen}}
        self._flows: dict = {}

        # Per-port stats
        self._port_counts: dict = defaultdict(int)

        # Flags
        self.available = SCAPY_AVAILABLE
        self._capture_start = None
        self._total_packets = 0
        self._total_bytes = 0

    def start(self, interface: str = None, packet_filter: str = 'ip'):
        if not SCAPY_AVAILABLE:
            return {'error': 'Scapy not available'}
        if self._running:
            return {'error': 'Capture already running'}

        self._interface = interface
        self._running = True
        self._capture_start = time.time()
        self._proto_counts.clear()
        self._flows.clear()
        self._port_counts.clear()
        self._packets.clear()
        self._total_packets = 0
        self._total_bytes = 0

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, packet_filter),
            daemon=True
        )
        self._thread.start()
        return {'status': 'started', 'interface': interface or 'default'}

    def stop(self):
        self._running = False
        return {'status': 'stopped', 'total_packets': self._total_packets}

    def _capture_loop(self, interface, packet_filter):
        try:
            sniff(
                iface=interface,
                filter=packet_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            print(f'[!] Packet capture error: {e}')
            self._running = False

    def _handle_packet(self, pkt):
        if not self._running:
            return

        try:
            pkt_info = self._decode(pkt)
            if pkt_info:
                with self._lock:
                    self._packets.append(pkt_info)
                    self._proto_counts[pkt_info['proto']] += 1
                    self._total_packets += 1
                    self._total_bytes += pkt_info.get('length', 0)

                    # Update flow table
                    flow_key = (
                        pkt_info.get('src_ip', ''),
                        pkt_info.get('dst_ip', ''),
                        pkt_info.get('dst_port', 0),
                        pkt_info['proto']
                    )
                    if len(self._flows) < _MAX_FLOWS or flow_key in self._flows:
                        f = self._flows.setdefault(flow_key, {'bytes': 0, 'packets': 0, 'first_seen': time.time()})
                        f['bytes'] += pkt_info.get('length', 0)
                        f['packets'] += 1
                        f['last_seen'] = time.time()

                    # Port frequency
                    if pkt_info.get('dst_port'):
                        self._port_counts[pkt_info['dst_port']] += 1
        except Exception:
            pass

    def _decode(self, pkt) -> dict:
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        length = len(pkt)
        proto = _PROTO_MAP.get(ip.proto, str(ip.proto))
        info = {
            'time': time.strftime('%H:%M:%S'),
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'proto': proto,
            'length': length,
            'info': '',
            'src_port': None,
            'dst_port': None,
            'flags': None,
        }

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info['src_port'] = tcp.sport
            info['dst_port'] = tcp.dport
            flags = []
            if tcp.flags.S: flags.append('SYN')
            if tcp.flags.A: flags.append('ACK')
            if tcp.flags.F: flags.append('FIN')
            if tcp.flags.R: flags.append('RST')
            if tcp.flags.P: flags.append('PSH')
            info['flags'] = '|'.join(flags) if flags else None

            # HTTP detection
            if tcp.dport == 80 or tcp.sport == 80:
                info['proto'] = 'HTTP'
                if pkt.haslayer(Raw):
                    raw = pkt[Raw].load
                    try:
                        decoded = raw[:200].decode('utf-8', errors='ignore')
                        if decoded.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                            first_line = decoded.split('\n')[0].strip()
                            info['info'] = first_line[:100]
                    except Exception:
                        pass
            elif tcp.dport == 443 or tcp.sport == 443:
                info['proto'] = 'HTTPS'
                info['info'] = 'TLS encrypted'
            elif tcp.dport == 22 or tcp.sport == 22:
                info['proto'] = 'SSH'
            elif tcp.dport == 21 or tcp.sport == 21:
                info['proto'] = 'FTP'
            elif tcp.dport == 25 or tcp.sport == 25:
                info['proto'] = 'SMTP'
            elif tcp.dport == 3306 or tcp.sport == 3306:
                info['proto'] = 'MySQL'
            elif tcp.dport == 5432 or tcp.sport == 5432:
                info['proto'] = 'PostgreSQL'

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info['src_port'] = udp.sport
            info['dst_port'] = udp.dport

            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                info['proto'] = 'DNS'
                if dns.qd:
                    try:
                        qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        qtype = dns.qd.qtype
                        info['info'] = f'Query: {qname} (type {qtype})'
                    except Exception:
                        pass
            elif udp.dport == 67 or udp.dport == 68:
                info['proto'] = 'DHCP'
            elif udp.dport == 123:
                info['proto'] = 'NTP'

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            type_map = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable',
                        11: 'TTL Exceeded', 5: 'Redirect'}
            info['proto'] = 'ICMP'
            info['info'] = type_map.get(icmp.type, f'Type {icmp.type}')

        return info

    def get_stats(self) -> dict:
        with self._lock:
            elapsed = time.time() - self._capture_start if self._capture_start else 0
            pps = self._total_packets / elapsed if elapsed > 0 else 0

            # Top flows by bytes
            top_flows = sorted(
                [
                    {
                        'src': k[0],
                        'dst': k[1],
                        'port': k[2],
                        'proto': k[3],
                        'bytes': v['bytes'],
                        'packets': v['packets'],
                        'duration': round(time.time() - v['first_seen'], 1),
                    }
                    for k, v in self._flows.items()
                ],
                key=lambda x: x['bytes'],
                reverse=True
            )[:20]

            # Top ports
            top_ports = sorted(
                [{'port': p, 'count': c} for p, c in self._port_counts.items()],
                key=lambda x: x['count'],
                reverse=True
            )[:10]

            # Protocol breakdown
            proto_breakdown = dict(self._proto_counts)

            return {
                'running': self._running,
                'interface': self._interface,
                'total_packets': self._total_packets,
                'total_bytes': self._total_bytes,
                'packets_per_sec': round(pps, 1),
                'elapsed_seconds': round(elapsed, 1),
                'proto_breakdown': proto_breakdown,
                'top_flows': top_flows,
                'top_ports': top_ports,
                'recent_packets': list(self._packets)[-50:],
                'available': self.available,
            }

    def get_recent_packets(self, limit: int = 50) -> list:
        with self._lock:
            return list(self._packets)[-limit:]


# Singleton — shared across the app
capture = PacketCapture()
