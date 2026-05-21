"""
Device Identifier Service
Resolves IPs to MAC addresses via ARP, then looks up vendor OUI.
Device type is inferred from vendor string.
Cache TTL: 60 seconds.
"""

import subprocess
import socket
import time
import re

# OUI prefix → (vendor, device_type, icon)
# Covers the vast majority of home/office network traffic.
_OUI_TABLE = {
    # Apple
    '00:1b:63': ('Apple', 'laptop', 'fa-laptop'),
    '00:23:12': ('Apple', 'laptop', 'fa-laptop'),
    '00:25:00': ('Apple', 'laptop', 'fa-laptop'),
    '00:26:bb': ('Apple', 'laptop', 'fa-laptop'),
    '04:0c:ce': ('Apple', 'phone', 'fa-mobile-screen'),
    '04:15:52': ('Apple', 'phone', 'fa-mobile-screen'),
    '04:26:65': ('Apple', 'phone', 'fa-mobile-screen'),
    '04:52:f3': ('Apple', 'laptop', 'fa-laptop'),
    '08:6d:41': ('Apple', 'laptop', 'fa-laptop'),
    '0c:4d:e9': ('Apple', 'laptop', 'fa-laptop'),
    '18:65:90': ('Apple', 'phone', 'fa-mobile-screen'),
    '18:9e:fc': ('Apple', 'laptop', 'fa-laptop'),
    '1c:36:bb': ('Apple', 'laptop', 'fa-laptop'),
    '20:c9:d0': ('Apple', 'laptop', 'fa-laptop'),
    '28:37:37': ('Apple', 'phone', 'fa-mobile-screen'),
    '2c:be:08': ('Apple', 'laptop', 'fa-laptop'),
    '34:08:bc': ('Apple', 'phone', 'fa-mobile-screen'),
    '3c:07:54': ('Apple', 'phone', 'fa-mobile-screen'),
    '3c:2e:f9': ('Apple', 'laptop', 'fa-laptop'),
    '40:33:1a': ('Apple', 'laptop', 'fa-laptop'),
    '4c:57:ca': ('Apple', 'phone', 'fa-mobile-screen'),
    '60:c5:47': ('Apple', 'phone', 'fa-mobile-screen'),
    '64:76:ba': ('Apple', 'laptop', 'fa-laptop'),
    '70:3e:ac': ('Apple', 'laptop', 'fa-laptop'),
    '78:4f:43': ('Apple', 'laptop', 'fa-laptop'),
    '80:49:71': ('Apple', 'phone', 'fa-mobile-screen'),
    '8c:85:90': ('Apple', 'laptop', 'fa-laptop'),
    '90:fd:61': ('Apple', 'phone', 'fa-mobile-screen'),
    'a4:5e:60': ('Apple', 'phone', 'fa-mobile-screen'),
    'ac:de:48': ('Apple', 'laptop', 'fa-laptop'),
    'b8:ff:61': ('Apple', 'phone', 'fa-mobile-screen'),
    'bc:92:6b': ('Apple', 'laptop', 'fa-laptop'),
    'c8:69:cd': ('Apple', 'phone', 'fa-mobile-screen'),
    'd8:bb:2c': ('Apple', 'laptop', 'fa-laptop'),
    'dc:9b:9c': ('Apple', 'laptop', 'fa-laptop'),
    'f0:18:98': ('Apple', 'laptop', 'fa-laptop'),
    'f4:37:b7': ('Apple', 'laptop', 'fa-laptop'),
    # Samsung
    '00:07:ab': ('Samsung', 'phone', 'fa-mobile-screen'),
    '00:12:47': ('Samsung', 'phone', 'fa-mobile-screen'),
    '00:26:37': ('Samsung', 'phone', 'fa-mobile-screen'),
    '34:14:5f': ('Samsung', 'phone', 'fa-mobile-screen'),
    '38:16:d1': ('Samsung', 'phone', 'fa-mobile-screen'),
    '3c:8b:fe': ('Samsung', 'phone', 'fa-mobile-screen'),
    '8c:f5:a3': ('Samsung', 'phone', 'fa-mobile-screen'),
    'a0:75:91': ('Samsung', 'phone', 'fa-mobile-screen'),
    'b4:79:a7': ('Samsung', 'phone', 'fa-mobile-screen'),
    'f4:7b:5e': ('Samsung', 'phone', 'fa-mobile-screen'),
    # Google
    '00:1a:11': ('Google', 'server', 'fa-server'),
    '3c:5a:b4': ('Google', 'media', 'fa-tv'),
    '54:60:09': ('Google', 'media', 'fa-tv'),
    '6c:ad:f8': ('Google', 'media', 'fa-tv'),
    'a4:77:33': ('Google', 'phone', 'fa-mobile-screen'),
    'f4:f5:d8': ('Google', 'smart-home', 'fa-house-signal'),
    # Cisco
    '00:00:0c': ('Cisco', 'router', 'fa-network-wired'),
    '00:01:42': ('Cisco', 'router', 'fa-network-wired'),
    '00:01:63': ('Cisco', 'router', 'fa-network-wired'),
    '00:01:96': ('Cisco', 'router', 'fa-network-wired'),
    '00:02:16': ('Cisco', 'router', 'fa-network-wired'),
    '00:0a:f3': ('Cisco', 'router', 'fa-network-wired'),
    '00:0b:45': ('Cisco', 'router', 'fa-network-wired'),
    '00:0c:ce': ('Cisco', 'router', 'fa-network-wired'),
    '00:1c:57': ('Cisco', 'router', 'fa-network-wired'),
    '00:1e:49': ('Cisco', 'router', 'fa-network-wired'),
    '00:21:1b': ('Cisco', 'router', 'fa-network-wired'),
    '00:22:55': ('Cisco', 'router', 'fa-network-wired'),
    '00:23:ac': ('Cisco', 'router', 'fa-network-wired'),
    '00:24:97': ('Cisco', 'router', 'fa-network-wired'),
    '00:25:45': ('Cisco', 'router', 'fa-network-wired'),
    '00:26:cb': ('Cisco', 'router', 'fa-network-wired'),
    'f8:72:ea': ('Cisco', 'router', 'fa-network-wired'),
    # Netgear
    '00:09:5b': ('Netgear', 'router', 'fa-network-wired'),
    '00:0f:b5': ('Netgear', 'router', 'fa-network-wired'),
    '00:14:6c': ('Netgear', 'router', 'fa-network-wired'),
    '00:18:4d': ('Netgear', 'router', 'fa-network-wired'),
    '00:1b:2f': ('Netgear', 'router', 'fa-network-wired'),
    '00:1e:2a': ('Netgear', 'router', 'fa-network-wired'),
    '00:26:f2': ('Netgear', 'router', 'fa-network-wired'),
    '20:4e:7f': ('Netgear', 'router', 'fa-network-wired'),
    'a0:04:60': ('Netgear', 'router', 'fa-network-wired'),
    'c0:3f:0e': ('Netgear', 'router', 'fa-network-wired'),
    # TP-Link
    '00:27:19': ('TP-Link', 'router', 'fa-network-wired'),
    '14:cc:20': ('TP-Link', 'router', 'fa-network-wired'),
    '18:d6:c7': ('TP-Link', 'router', 'fa-network-wired'),
    '30:de:4b': ('TP-Link', 'router', 'fa-network-wired'),
    '50:c7:bf': ('TP-Link', 'router', 'fa-network-wired'),
    '64:70:02': ('TP-Link', 'router', 'fa-network-wired'),
    '6c:5a:b0': ('TP-Link', 'router', 'fa-network-wired'),
    '98:da:c4': ('TP-Link', 'router', 'fa-network-wired'),
    'b0:95:75': ('TP-Link', 'router', 'fa-network-wired'),
    # Intel (laptops/desktops)
    '00:1b:21': ('Intel', 'computer', 'fa-desktop'),
    '00:1e:65': ('Intel', 'computer', 'fa-desktop'),
    '00:21:6a': ('Intel', 'computer', 'fa-desktop'),
    '00:23:14': ('Intel', 'computer', 'fa-desktop'),
    '00:24:d6': ('Intel', 'computer', 'fa-desktop'),
    '00:27:10': ('Intel', 'computer', 'fa-desktop'),
    '10:02:b5': ('Intel', 'computer', 'fa-desktop'),
    '28:d2:44': ('Intel', 'computer', 'fa-desktop'),
    '34:13:e8': ('Intel', 'computer', 'fa-desktop'),
    '40:a8:f0': ('Intel', 'computer', 'fa-desktop'),
    '48:51:b7': ('Intel', 'computer', 'fa-desktop'),
    '54:27:1e': ('Intel', 'computer', 'fa-desktop'),
    '60:57:18': ('Intel', 'computer', 'fa-desktop'),
    '68:5d:43': ('Intel', 'computer', 'fa-desktop'),
    '8c:ec:4b': ('Intel', 'computer', 'fa-desktop'),
    'a0:36:9f': ('Intel', 'computer', 'fa-desktop'),
    'b8:ae:ed': ('Intel', 'computer', 'fa-desktop'),
    'd4:be:d9': ('Intel', 'computer', 'fa-desktop'),
    # Raspberry Pi
    'b8:27:eb': ('Raspberry Pi', 'server', 'fa-microchip'),
    'dc:a6:32': ('Raspberry Pi', 'server', 'fa-microchip'),
    'e4:5f:01': ('Raspberry Pi', 'server', 'fa-microchip'),
    # Amazon
    '40:b4:cd': ('Amazon', 'media', 'fa-tv'),
    '44:65:0d': ('Amazon', 'smart-home', 'fa-house-signal'),
    '68:37:e9': ('Amazon', 'media', 'fa-tv'),
    '74:75:48': ('Amazon', 'smart-home', 'fa-house-signal'),
    'a0:02:dc': ('Amazon', 'media', 'fa-tv'),
    'fc:a1:83': ('Amazon', 'media', 'fa-tv'),
    # Microsoft
    '00:50:f2': ('Microsoft', 'computer', 'fa-desktop'),
    '28:18:78': ('Microsoft', 'computer', 'fa-desktop'),
    '60:45:bd': ('Microsoft', 'computer', 'fa-desktop'),
    '7c:ed:8d': ('Microsoft', 'computer', 'fa-desktop'),
    'c8:3f:26': ('Microsoft', 'computer', 'fa-desktop'),
    # VMware / VirtualBox
    '00:0c:29': ('VMware', 'server', 'fa-server'),
    '00:50:56': ('VMware', 'server', 'fa-server'),
    '08:00:27': ('VirtualBox', 'server', 'fa-server'),
    # Ubiquiti
    '00:27:22': ('Ubiquiti', 'router', 'fa-network-wired'),
    '04:18:d6': ('Ubiquiti', 'router', 'fa-network-wired'),
    '24:a4:3c': ('Ubiquiti', 'router', 'fa-network-wired'),
    '44:d9:e7': ('Ubiquiti', 'router', 'fa-network-wired'),
    '68:72:51': ('Ubiquiti', 'router', 'fa-network-wired'),
    '78:8a:20': ('Ubiquiti', 'router', 'fa-network-wired'),
    'ac:8b:a9': ('Ubiquiti', 'router', 'fa-network-wired'),
    'dc:9f:db': ('Ubiquiti', 'router', 'fa-network-wired'),
    # Synology (NAS)
    '00:11:32': ('Synology', 'server', 'fa-hard-drive'),
    # QNAP (NAS)
    '00:08:9b': ('QNAP', 'server', 'fa-hard-drive'),
    '24:5e:be': ('QNAP', 'server', 'fa-hard-drive'),
    # Roku
    'b8:3e:59': ('Roku', 'media', 'fa-tv'),
    'cc:6d:a0': ('Roku', 'media', 'fa-tv'),
    'd8:31:cf': ('Roku', 'media', 'fa-tv'),
    # Sony
    '00:01:4a': ('Sony', 'gaming', 'fa-gamepad'),
    '00:13:a9': ('Sony', 'gaming', 'fa-gamepad'),
    '00:1d:0d': ('Sony', 'media', 'fa-tv'),
    '70:2b:a5': ('Sony', 'gaming', 'fa-gamepad'),
    'a8:e0:73': ('Sony', 'gaming', 'fa-gamepad'),
    # Lenovo
    '00:1c:25': ('Lenovo', 'laptop', 'fa-laptop'),
    '34:73:5a': ('Lenovo', 'laptop', 'fa-laptop'),
    '54:ee:75': ('Lenovo', 'laptop', 'fa-laptop'),
    '60:6c:66': ('Lenovo', 'laptop', 'fa-laptop'),
    '70:5a:0f': ('Lenovo', 'laptop', 'fa-laptop'),
    '98:fa:9b': ('Lenovo', 'laptop', 'fa-laptop'),
    'd8:b4:2d': ('Lenovo', 'laptop', 'fa-laptop'),
    # Dell
    '00:14:22': ('Dell', 'computer', 'fa-desktop'),
    '00:1a:4b': ('Dell', 'computer', 'fa-desktop'),
    '18:03:73': ('Dell', 'computer', 'fa-desktop'),
    '18:fb:7b': ('Dell', 'computer', 'fa-desktop'),
    '24:b6:fd': ('Dell', 'computer', 'fa-desktop'),
    '44:a8:42': ('Dell', 'computer', 'fa-desktop'),
    'b0:83:fe': ('Dell', 'computer', 'fa-desktop'),
    'f8:db:88': ('Dell', 'computer', 'fa-desktop'),
}


def _lookup_oui(mac):
    """Return (vendor, device_type, icon) for a MAC address, or None."""
    if not mac:
        return None
    prefix = mac.lower()[:8]
    entry = _OUI_TABLE.get(prefix)
    if entry:
        return entry
    # Try first two bytes as fallback (less precise, skip)
    return None


def _parse_arp_table():
    """
    Read ARP table from kernel. Returns dict of {ip: mac}.
    Uses /proc/net/arp first (fast, no subprocess), then falls back to `ip neigh`.
    """
    arp = {}
    try:
        with open('/proc/net/arp') as f:
            for line in f:
                parts = line.split()
                # Format: IP HW_TYPE FLAGS MAC_ADDR MASK DEVICE
                if len(parts) >= 4 and parts[0] not in ('IP', '0.0.0.0'):
                    ip = parts[0]
                    mac = parts[3]
                    if mac != '00:00:00:00:00:00' and re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac.lower()):
                        arp[ip] = mac.lower()
        return arp
    except Exception:
        pass

    # Fallback: `ip neigh show`
    try:
        result = subprocess.run(
            ['ip', 'neigh', 'show'],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            # Format: IP dev IFACE lladdr MAC_ADDR [REACHABLE|STALE|...]
            m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-f:]{17})', line.lower())
            if m:
                arp[m.group(1)] = m.group(2)
    except Exception:
        pass

    return arp


def _resolve_hostname(ip):
    """Reverse DNS lookup with short timeout. Returns None on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


class DeviceIdentifier:
    _arp_cache: dict = {}
    _arp_cache_time: float = 0
    _ARP_TTL = 60  # seconds

    def _refresh_arp(self):
        now = time.time()
        if now - self._arp_cache_time > self._ARP_TTL:
            self._arp_cache = _parse_arp_table()
            self._arp_cache_time = now

    def identify(self, ip):
        self._refresh_arp()
        mac = self._arp_cache.get(ip)
        vendor, device_type, icon = 'Unknown', 'unknown', 'fa-circle-question'
        hostname = None

        if mac:
            oui = _lookup_oui(mac)
            if oui:
                vendor, device_type, icon = oui

        # Hostname via reverse DNS (best-effort)
        hostname = _resolve_hostname(ip)

        friendly_name = hostname or (vendor if vendor != 'Unknown' else ip)

        return {
            'ip': ip,
            'mac': mac,
            'manufacturer': vendor if vendor != 'Unknown' else None,
            'hostname': hostname,
            'device_type': device_type,
            'icon': icon,
            'friendly_name': friendly_name,
        }

    def get_network_inventory(self):
        """Return all devices currently in ARP table with enrichment."""
        self._refresh_arp()
        inventory = []
        for ip, mac in self._arp_cache.items():
            inventory.append(self.identify(ip))
        return sorted(inventory, key=lambda d: d['ip'])
