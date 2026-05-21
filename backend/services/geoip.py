"""
GeoIP enrichment via ip-api.com (free, no key required).
Batch lookups up to 100 IPs per request.
Cache TTL: 1 hour — IP geolocation rarely changes.
"""

import time
import threading
import urllib.request
import urllib.error
import json

_cache: dict = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 3600  # 1 hour

# IPs that are never worth looking up
_SKIP_PREFIXES = ('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
                  '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                  '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                  '172.29.', '172.30.', '172.31.', '::1', 'fe80', '0.0.0.0')

_FIELDS = 'status,country,countryCode,regionName,city,isp,org,as,query'


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _SKIP_PREFIXES)


def _cache_get(ip: str):
    with _cache_lock:
        entry = _cache.get(ip)
        if entry and time.time() - entry['_ts'] < _CACHE_TTL:
            return entry
    return None


def _cache_set(ip: str, data: dict):
    data['_ts'] = time.time()
    with _cache_lock:
        _cache[ip] = data


def _empty(ip: str) -> dict:
    return {
        'ip': ip,
        'country': None,
        'country_code': None,
        'region': None,
        'city': None,
        'isp': None,
        'org': None,
        'asn': None,
        'flag': None,
        'private': _is_private(ip),
    }


def _format(raw: dict) -> dict:
    cc = raw.get('countryCode', '')
    return {
        'ip': raw.get('query', ''),
        'country': raw.get('country'),
        'country_code': cc,
        'region': raw.get('regionName'),
        'city': raw.get('city'),
        'isp': raw.get('isp'),
        'org': raw.get('org'),
        'asn': raw.get('as'),
        'flag': f'https://flagcdn.com/16x12/{cc.lower()}.png' if cc else None,
        'private': False,
    }


def lookup(ip: str) -> dict:
    """Look up a single IP. Returns cached result if available."""
    if _is_private(ip):
        r = _empty(ip)
        r['private'] = True
        return r

    cached = _cache_get(ip)
    if cached:
        return cached

    try:
        url = f'http://ip-api.com/json/{ip}?fields={_FIELDS}'
        req = urllib.request.Request(url, headers={'User-Agent': 'mega-reaper-9000'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = json.loads(resp.read())
        if raw.get('status') == 'success':
            result = _format(raw)
            _cache_set(ip, result)
            return result
    except Exception:
        pass

    result = _empty(ip)
    _cache_set(ip, result)
    return result


def lookup_batch(ips: list) -> dict:
    """
    Look up multiple IPs. Uses batch endpoint for uncached IPs (up to 100/request).
    Returns dict of {ip: geoip_data}.
    """
    results = {}
    to_fetch = []

    for ip in ips:
        if _is_private(ip):
            r = _empty(ip)
            r['private'] = True
            results[ip] = r
            continue
        cached = _cache_get(ip)
        if cached:
            results[ip] = cached
        else:
            to_fetch.append(ip)

    if not to_fetch:
        return results

    # Batch in chunks of 100
    for chunk_start in range(0, len(to_fetch), 100):
        chunk = to_fetch[chunk_start:chunk_start + 100]
        try:
            url = f'http://ip-api.com/batch?fields={_FIELDS}'
            payload = json.dumps(chunk).encode()
            req = urllib.request.Request(
                url, data=payload,
                headers={'Content-Type': 'application/json', 'User-Agent': 'mega-reaper-9000'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                batch_raw = json.loads(resp.read())
            for raw in batch_raw:
                if raw.get('status') == 'success':
                    r = _format(raw)
                    _cache_set(r['ip'], r)
                    results[r['ip']] = r
        except Exception:
            pass

    # Fill any that failed
    for ip in to_fetch:
        if ip not in results:
            r = _empty(ip)
            _cache_set(ip, r)
            results[ip] = r

    return results
