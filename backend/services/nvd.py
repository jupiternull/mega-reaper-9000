"""
NVD REST API v2 — CVSS score + description lookup for CVE IDs.
No API key required for basic lookups (rate limit: 5 req/30s without key).
Cache TTL: 24 hours — CVE data is stable.
"""

import time
import threading
import urllib.request
import urllib.error
import json

_cache: dict = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 86400  # 24 hours
_RATE_LIMIT_DELAY = 0.7  # ~5 req/30s safe margin
_last_request_time = 0.0
_rate_lock = threading.Lock()

_NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def _rate_wait():
    global _last_request_time
    with _rate_lock:
        now = time.time()
        gap = now - _last_request_time
        if gap < _RATE_LIMIT_DELAY:
            time.sleep(_RATE_LIMIT_DELAY - gap)
        _last_request_time = time.time()


def _empty(cve_id: str) -> dict:
    return {
        'cve_id': cve_id,
        'description': None,
        'cvss_v3_score': None,
        'cvss_v3_severity': None,
        'cvss_v2_score': None,
        'cvss_v2_severity': None,
        'published': None,
        'references': [],
        'error': None,
    }


def _severity_label(score) -> str:
    if score is None:
        return None
    score = float(score)
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    return 'LOW'


def _parse_response(data: dict, cve_id: str) -> dict:
    result = _empty(cve_id)
    vulns = data.get('vulnerabilities', [])
    if not vulns:
        result['error'] = 'Not found in NVD'
        return result

    cve_data = vulns[0].get('cve', {})

    # Description (English preferred)
    for desc in cve_data.get('descriptions', []):
        if desc.get('lang') == 'en':
            result['description'] = desc.get('value', '')
            break

    result['published'] = cve_data.get('published', '')[:10]

    # CVSS scores
    metrics = cve_data.get('metrics', {})

    # CVSSv3.1 or CVSSv3.0
    for key in ('cvssMetricV31', 'cvssMetricV30'):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get('cvssData', {})
            score = m.get('baseScore')
            result['cvss_v3_score'] = score
            result['cvss_v3_severity'] = _severity_label(score)
            break

    # CVSSv2 fallback
    if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        m = metrics['cvssMetricV2'][0].get('cvssData', {})
        score = m.get('baseScore')
        result['cvss_v2_score'] = score
        result['cvss_v2_severity'] = _severity_label(score)

    # References (first 5)
    refs = cve_data.get('references', [])[:5]
    result['references'] = [r.get('url', '') for r in refs]

    return result


def lookup(cve_id: str) -> dict:
    """Look up a single CVE ID. Returns cached result if available."""
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith('CVE-'):
        return _empty(cve_id)

    with _cache_lock:
        entry = _cache.get(cve_id)
        if entry and time.time() - entry.get('_ts', 0) < _CACHE_TTL:
            return {k: v for k, v in entry.items() if k != '_ts'}

    _rate_wait()

    try:
        url = f'{_NVD_BASE}?cveId={cve_id}'
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'mega-reaper-9000', 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        result = _parse_response(data, cve_id)
    except urllib.error.HTTPError as e:
        result = _empty(cve_id)
        result['error'] = f'HTTP {e.code}'
    except Exception as e:
        result = _empty(cve_id)
        result['error'] = str(e)

    cached = dict(result)
    cached['_ts'] = time.time()
    with _cache_lock:
        _cache[cve_id] = cached

    return result


def enrich_vulnerabilities(vulns: list) -> list:
    """
    Add NVD data to a list of vulnerability dicts (each must have a 'cve' key).
    Skips N/A entries. Rate-limited — may be slow for large lists.
    """
    enriched = []
    for v in vulns:
        cve_id = v.get('cve', 'N/A')
        if cve_id and cve_id != 'N/A':
            nvd = lookup(cve_id)
            v = dict(v)
            v['nvd'] = nvd
            # Upgrade severity based on real CVSS score
            score = nvd.get('cvss_v3_score') or nvd.get('cvss_v2_score')
            if score is not None:
                v['cvss_score'] = score
                v['severity'] = _severity_label(score).lower() if _severity_label(score) else v.get('severity', 'unknown')
                v['description'] = nvd.get('description') or v.get('detail', '')
        enriched.append(v)
    return enriched
