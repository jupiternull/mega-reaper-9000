"""
IoT Device Scanner
Three discovery layers:
  1. ARP table — fast, passive, shows in topology immediately
  2. nmap IoT port probe — checks each host for known IoT services
  3. mDNS/Bonjour — catches self-announcing devices (Chromecast, printers, HomeKit)
Gracefully degrades if nmap or zeroconf unavailable.
"""

import socket
import time
import threading

import nmap

try:
    from services.device_identifier import _lookup_oui, _parse_arp_table
except ImportError:
    from device_identifier import _lookup_oui, _parse_arp_table

try:
    from zeroconf import Zeroconf, ServiceBrowser
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False

IOT_PORTS = [23, 80, 443, 554, 1883, 2323, 5683, 8080, 8443, 8888, 9100, 49152]

_PORT_NAMES = {
    23: 'Telnet', 80: 'HTTP', 443: 'HTTPS', 554: 'RTSP',
    1883: 'MQTT', 2323: 'Telnet-alt', 5683: 'CoAP',
    8080: 'HTTP-alt', 8443: 'HTTPS-alt', 8888: 'HTTP-proxy',
    9100: 'IPP/Print', 49152: 'UPnP',
}

# (required_port_set, device_type, icon, label)
_PORT_SIGS = [
    ({554},       'camera',     'fa-camera',        'IP Camera'),
    ({1883},      'smart-home', 'fa-house-signal',  'MQTT Hub'),
    ({9100},      'printer',    'fa-print',         'Network Printer'),
    ({5683},      'iot',        'fa-microchip',     'CoAP Device'),
    ({23},        'iot',        'fa-microchip',     'Telnet Device'),
    ({554, 80},   'camera',     'fa-camera',        'IP Camera w/ Web UI'),
]

_VENDOR_SIGS = {
    'hikvision': ('camera',     'fa-camera',        'Hikvision Camera'),
    'dahua':     ('camera',     'fa-camera',        'Dahua Camera'),
    'axis':      ('camera',     'fa-camera',        'Axis Camera'),
    'amcrest':   ('camera',     'fa-camera',        'Amcrest Camera'),
    'reolink':   ('camera',     'fa-camera',        'Reolink Camera'),
    'wyze':      ('camera',     'fa-camera',        'Wyze Camera'),
    'ring':      ('camera',     'fa-camera',        'Ring Device'),
    'nest':      ('smart-home', 'fa-house-signal',  'Nest Device'),
    'philips':   ('smart-home', 'fa-house-signal',  'Philips Hue'),
    'tuya':      ('smart-home', 'fa-house-signal',  'Tuya Device'),
    'shelly':    ('smart-home', 'fa-house-signal',  'Shelly Device'),
    'sonoff':    ('smart-home', 'fa-house-signal',  'Sonoff Device'),
    'esp':       ('iot',        'fa-microchip',     'ESP Device'),
    'arduino':   ('iot',        'fa-microchip',     'Arduino'),
    'raspberry': ('server',     'fa-microchip',     'Raspberry Pi'),
}

_MDNS_SERVICES = [
    '_http._tcp.local.',
    '_printer._tcp.local.',
    '_ipp._tcp.local.',
    '_googlecast._tcp.local.',
    '_raop._tcp.local.',
    '_hap._tcp.local.',
    '_airplay._tcp.local.',
    '_homekit._tcp.local.',
    '_ssh._tcp.local.',
    '_smb._tcp.local.',
    '_daap._tcp.local.',
]


class _MDNSCollector:
    def __init__(self):
        self.devices = {}
        self._lock = threading.Lock()

    def add_service(self, zc, type_, name):
        try:
            info = zc.get_service_info(type_, name, timeout=3000)
            if not info or not info.addresses:
                return
            ip = socket.inet_ntoa(info.addresses[0])
            with self._lock:
                if ip not in self.devices:
                    self.devices[ip] = {
                        'mdns_name': name.split('.')[0],
                        'mdns_type': type_,
                        'mdns_port': info.port,
                    }
        except Exception:
            pass

    def remove_service(self, *_):
        pass

    def update_service(self, *_):
        pass


def _run_mdns(duration=6):
    if not ZEROCONF_AVAILABLE:
        return {}
    collector = _MDNSCollector()
    zc = Zeroconf()
    try:
        [ServiceBrowser(zc, svc, collector) for svc in _MDNS_SERVICES]
        time.sleep(duration)
    finally:
        zc.close()
    return dict(collector.devices)


def _fingerprint(mac, open_ports, vendor_str):
    """Return (device_type, icon, label) from OUI + ports + vendor string."""
    if vendor_str:
        vl = vendor_str.lower()
        for kw, sig in _VENDOR_SIGS.items():
            if kw in vl:
                return sig

    port_set = set(open_ports)
    for req, dtype, icon, label in _PORT_SIGS:
        if req.issubset(port_set):
            return dtype, icon, label

    if mac:
        oui = _lookup_oui(mac)
        if oui:
            vendor, dtype, icon = oui
            return dtype, icon, vendor

    return 'iot', 'fa-microchip', 'Unknown Device'


class IoTScanner:
    def __init__(self):
        self._nm = nmap.PortScanner()
        self._last_results = []
        self._scanning = False

    @property
    def is_scanning(self):
        return self._scanning

    def get_last_results(self):
        return list(self._last_results)

    def get_lan_topology(self):
        """Fast ARP-table snapshot — no scan, used for live topology canvas."""
        arp = _parse_arp_table()
        devices = []
        for ip, mac in arp.items():
            oui = _lookup_oui(mac) if mac else None
            vendor = oui[0] if oui else None
            dtype  = oui[1] if oui else 'unknown'
            icon   = oui[2] if oui else 'fa-circle-question'
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None
            devices.append({
                'ip': ip,
                'mac': mac,
                'manufacturer': vendor,
                'hostname': hostname,
                'device_type': dtype,
                'icon': icon,
                'friendly_name': hostname or vendor or ip,
            })
        return sorted(devices, key=lambda d: d['ip'])

    def scan(self, subnet=None, progress_cb=None):
        """
        Full IoT scan: ARP discovery → IoT port probe → mDNS merge.
        progress_cb(message, percent) is called at key milestones.
        Returns list of device dicts, or {'error': str} on failure.
        """
        if self._scanning:
            return {'error': 'Scan already in progress'}
        self._scanning = True

        def _cb(msg, pct):
            if progress_cb:
                try:
                    progress_cb(msg, pct)
                except Exception:
                    pass

        try:
            _cb('Starting mDNS discovery in background...', 5)
            mdns_result = {}

            def _mdns_worker():
                mdns_result.update(_run_mdns(duration=6))

            mdns_thread = threading.Thread(target=_mdns_worker, daemon=True)
            mdns_thread.start()

            _cb('Reading ARP table...', 10)
            arp = _parse_arp_table()

            if not arp and subnet:
                _cb(f'ARP table empty — probing {subnet} with nmap...', 15)
                try:
                    self._nm.scan(hosts=subnet, arguments='-sn -PR --host-timeout 5s')
                    for host in self._nm.all_hosts():
                        if self._nm[host].state() == 'up':
                            mac = (self._nm[host].get('addresses', {}).get('mac', '') or '').lower() or None
                            arp[host] = mac or ''
                except Exception as e:
                    _cb(f'ARP probe failed: {e}', 15)

            total = max(len(arp), 1)
            _cb(f'Found {len(arp)} LAN hosts — probing IoT ports...', 20)

            port_str = ','.join(str(p) for p in IOT_PORTS)
            results = []

            for idx, (ip, mac) in enumerate(arp.items()):
                pct = 20 + int((idx / total) * 60)
                _cb(f'Probing {ip}...', pct)

                open_ports = []
                services   = []
                try:
                    self._nm.scan(
                        hosts=ip,
                        arguments=f'-p {port_str} -T4 --open --host-timeout 10s'
                    )
                    if ip in self._nm.all_hosts():
                        for proto in self._nm[ip].all_protocols():
                            for port, info in self._nm[ip][proto].items():
                                if info['state'] == 'open':
                                    open_ports.append(port)
                                    svc = info.get('name') or _PORT_NAMES.get(port, str(port))
                                    services.append({'port': port, 'name': svc})
                except Exception:
                    pass

                oui = _lookup_oui(mac) if mac else None
                vendor = oui[0] if oui else None
                dtype, icon, label = _fingerprint(mac, open_ports, vendor or '')

                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = None

                results.append({
                    'ip': ip,
                    'mac': mac or None,
                    'manufacturer': vendor,
                    'hostname': hostname,
                    'device_type': dtype,
                    'icon': icon,
                    'label': label,
                    'friendly_name': hostname or label or vendor or ip,
                    'open_ports': open_ports,
                    'services': services,
                    'iot_ports': [p for p in open_ports if p in IOT_PORTS],
                    'is_iot': bool([p for p in open_ports if p in IOT_PORTS])
                              or dtype in ('camera', 'smart-home', 'iot', 'printer'),
                })

            _cb('Collecting mDNS results...', 82)
            mdns_thread.join(timeout=7)

            # Merge mDNS data into existing entries
            arp_ips = {d['ip'] for d in results}
            for ip, m in mdns_result.items():
                existing = next((d for d in results if d['ip'] == ip), None)
                if existing:
                    existing['mdns_name'] = m.get('mdns_name')
                    if not existing['hostname']:
                        existing['hostname'] = m.get('mdns_name')
                        existing['friendly_name'] = m['mdns_name']
                elif ip not in arp_ips:
                    results.append({
                        'ip': ip,
                        'mac': None,
                        'manufacturer': None,
                        'hostname': m.get('mdns_name'),
                        'device_type': 'iot',
                        'icon': 'fa-microchip',
                        'label': m.get('mdns_name', 'mDNS Device'),
                        'friendly_name': m.get('mdns_name', ip),
                        'open_ports': [],
                        'services': [{'port': m.get('mdns_port', 0), 'name': m.get('mdns_type', '')}],
                        'iot_ports': [],
                        'is_iot': True,
                        'mdns_name': m.get('mdns_name'),
                    })

            _cb('Scan complete', 100)
            self._last_results = results
            return results

        except Exception as e:
            return {'error': str(e)}
        finally:
            self._scanning = False
