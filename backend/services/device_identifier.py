"""Device Identifier Service — stub"""

class DeviceIdentifier:
    _device_cache = {}
    _arp_cache = {}
    _arp_cache_time = 0
    
    def __init__(self):
        pass
    
    def identify(self, ip):
        return {
            'ip': ip, 'mac': None, 'manufacturer': None,
            'hostname': None, 'device_type': 'unknown',
            'icon': 'fa-circle-question', 'friendly_name': ip
        }
    
    def get_network_inventory(self):
        return []
