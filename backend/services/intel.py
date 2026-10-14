"""
Intel & Recon Service
Self-contained reconnaissance helpers built on the Python standard library so they
work without extra system binaries. Covers TLS/certificate inspection, HTTP security
header grading, WHOIS, IP intelligence, and offline hash analysis.

Everything here is read-only reconnaissance intended for authorized, educational and
self-assessment use only.
"""

import hashlib
import socket
import ssl
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

try:
    from services.geoip import lookup as geoip_lookup
except Exception:  # pragma: no cover - geoip optional
    geoip_lookup = None


# ── TLS / certificate inspection ─────────────────────────────────────
_WEAK_TLS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}


def tls_inspect(host, port=443, timeout=8):
    """Connect to host:port, negotiate TLS and return certificate + cipher detail."""
    host = (host or '').strip()
    if not host:
        return {'error': 'No host specified'}
    # Allow "host:port" shorthand
    if ':' in host and not host.replace(':', '').isdigit():
        maybe_host, _, maybe_port = host.rpartition(':')
        if maybe_port.isdigit():
            host, port = maybe_host, int(maybe_port)

    ctx = ssl.create_default_context()
    # We want to inspect certs even if they fail validation.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
    except ssl.SSLError as e:
        return {'error': f'TLS handshake failed: {e}', 'host': host, 'port': port}
    except socket.timeout:
        return {'error': f'Connection to {host}:{port} timed out', 'host': host, 'port': port}
    except Exception as e:
        return {'error': str(e), 'host': host, 'port': port}

    # getpeercert() returns an empty dict when CERT_NONE is used; parse the DER
    # ourselves for the fields we care about.
    parsed = _parse_cert(der) if not cert else _normalize_cert(cert)

    findings = []
    now = datetime.now(timezone.utc)
    days_left = None
    if parsed.get('not_after'):
        try:
            exp = parsed['not_after']
            days_left = (exp - now).days
            if days_left < 0:
                findings.append({'severity': 'critical', 'message': f'Certificate EXPIRED {abs(days_left)} days ago'})
            elif days_left < 15:
                findings.append({'severity': 'high', 'message': f'Certificate expires in {days_left} days'})
            elif days_left < 30:
                findings.append({'severity': 'medium', 'message': f'Certificate expires in {days_left} days'})
        except Exception:
            pass

    if version in _WEAK_TLS:
        findings.append({'severity': 'high', 'message': f'Weak/deprecated protocol negotiated: {version}'})

    if parsed.get('self_signed'):
        findings.append({'severity': 'medium', 'message': 'Certificate appears to be self-signed'})

    return {
        'host': host,
        'port': int(port),
        'protocol': version,
        'cipher': cipher[0] if cipher else None,
        'cipher_bits': cipher[2] if cipher else None,
        'subject': parsed.get('subject'),
        'issuer': parsed.get('issuer'),
        'valid_from': parsed['not_before'].strftime('%Y-%m-%d') if parsed.get('not_before') else None,
        'valid_until': parsed['not_after'].strftime('%Y-%m-%d') if parsed.get('not_after') else None,
        'days_remaining': days_left,
        'san': parsed.get('san', []),
        'serial': parsed.get('serial'),
        'findings': findings,
    }


def _normalize_cert(cert):
    def _flatten(seq):
        out = {}
        for item in seq or ():
            for k, v in item:
                out[k] = v
        return out

    subject = _flatten(cert.get('subject'))
    issuer = _flatten(cert.get('issuer'))
    san = [v for k, v in cert.get('subjectAltName', ()) if k == 'DNS']
    fmt = '%b %d %H:%M:%S %Y %Z'
    result = {
        'subject': subject.get('commonName') or ', '.join(f'{k}={v}' for k, v in subject.items()),
        'issuer': issuer.get('commonName') or issuer.get('organizationName'),
        'san': san,
        'serial': cert.get('serialNumber'),
        'self_signed': subject == issuer,
    }
    try:
        result['not_before'] = datetime.strptime(cert['notBefore'], fmt).replace(tzinfo=timezone.utc)
        result['not_after'] = datetime.strptime(cert['notAfter'], fmt).replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return result


def _parse_cert(der):
    """Best-effort DER parsing using ssl's PEM/text decoder when available."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        # _ssl has no public text decoder; fall back to openssl if present.
        proc = subprocess.run(
            ['openssl', 'x509', '-noout', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName'],
            input=pem, capture_output=True, text=True, timeout=5,
        )
        out = proc.stdout
        result = {'san': [], 'self_signed': False}
        subject = issuer = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('subject='):
                subject = line.split('=', 1)[1].strip()
                result['subject'] = subject
            elif line.startswith('issuer='):
                issuer = line.split('=', 1)[1].strip()
                result['issuer'] = issuer
            elif line.startswith('notBefore='):
                result['not_before'] = _openssl_date(line.split('=', 1)[1])
            elif line.startswith('notAfter='):
                result['not_after'] = _openssl_date(line.split('=', 1)[1])
            elif line.startswith('DNS:'):
                result['san'] = [p.replace('DNS:', '').strip() for p in line.split(',') if 'DNS:' in p]
        result['self_signed'] = bool(subject and subject == issuer)
        return result
    except Exception:
        return {'san': [], 'self_signed': False}


def _openssl_date(value):
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%b %d %H:%M:%S %Y GMT'):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


# ── HTTP security header analysis ────────────────────────────────────
_SECURITY_HEADERS = {
    'strict-transport-security': ('high', 'HSTS not set — connection downgrade / SSL stripping risk'),
    'content-security-policy': ('high', 'No Content-Security-Policy — increased XSS exposure'),
    'x-frame-options': ('medium', 'No X-Frame-Options — clickjacking risk'),
    'x-content-type-options': ('medium', 'No X-Content-Type-Options — MIME sniffing risk'),
    'referrer-policy': ('low', 'No Referrer-Policy — referrer leakage'),
    'permissions-policy': ('low', 'No Permissions-Policy — unrestricted browser features'),
}


def http_headers(url, timeout=12):
    """Fetch HTTP response headers and grade the security posture."""
    url = (url or '').strip()
    if not url:
        return {'error': 'No URL specified'}
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    req = urllib.request.Request(url, method='GET', headers={'User-Agent': 'mega-reaper-9000/intel'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
            final_url = resp.geturl()
    except urllib.error.HTTPError as e:
        status = e.code
        headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        final_url = url
    except Exception as e:
        return {'error': str(e), 'url': url}

    findings = []
    present = []
    for header, (severity, message) in _SECURITY_HEADERS.items():
        if header in headers:
            present.append(header)
        else:
            findings.append({'severity': severity, 'message': message})

    if 'server' in headers:
        findings.append({'severity': 'low', 'message': f"Server banner disclosed: {headers['server']}"})
    if 'x-powered-by' in headers:
        findings.append({'severity': 'low', 'message': f"Technology disclosed via X-Powered-By: {headers['x-powered-by']}"})

    total = len(_SECURITY_HEADERS)
    score = int(round(len(present) / total * 100)) if total else 0
    grade = 'A' if score >= 90 else 'B' if score >= 75 else 'C' if score >= 55 else 'D' if score >= 35 else 'F'

    return {
        'url': url,
        'final_url': final_url,
        'status': status,
        'grade': grade,
        'score': score,
        'present_headers': present,
        'headers': headers,
        'findings': findings,
    }


# ── WHOIS ────────────────────────────────────────────────────────────
def whois_lookup(target, timeout=15):
    """Run a WHOIS lookup. Uses the system `whois` binary; degrades gracefully."""
    target = (target or '').strip()
    if not target:
        return {'error': 'No target specified'}
    try:
        proc = subprocess.run(['whois', target], capture_output=True, text=True, timeout=timeout)
        out = proc.stdout or proc.stderr
    except FileNotFoundError:
        return {'error': 'whois binary not installed — run: sudo apt install whois', 'target': target}
    except subprocess.TimeoutExpired:
        return {'error': 'WHOIS lookup timed out', 'target': target}
    except Exception as e:
        return {'error': str(e), 'target': target}

    fields = {}
    interesting = ('registrar', 'creation date', 'registry expiry date', 'expiry',
                   'updated date', 'name server', 'org', 'country', 'netname', 'cidr')
    for line in out.splitlines():
        if ':' not in line or line.strip().startswith(('%', '#', '*')):
            continue
        key, _, value = line.partition(':')
        key = key.strip().lower()
        value = value.strip()
        if value and any(key.startswith(i) for i in interesting):
            fields.setdefault(key, value)

    return {'target': target, 'fields': fields, 'raw': out[:6000]}


# ── IP intelligence ──────────────────────────────────────────────────
def ip_info(target):
    """Resolve a host, perform reverse DNS and GeoIP enrichment."""
    target = (target or '').strip()
    if not target:
        return {'error': 'No target specified'}

    result = {'input': target}
    try:
        ip = socket.gethostbyname(target)
        result['ip'] = ip
    except Exception as e:
        return {'error': f'Resolution failed: {e}', 'input': target}

    try:
        result['reverse_dns'] = socket.gethostbyaddr(result['ip'])[0]
    except Exception:
        result['reverse_dns'] = None

    if geoip_lookup:
        try:
            result['geo'] = geoip_lookup(result['ip'])
        except Exception:
            result['geo'] = None

    return result


# ── Offline hash analysis ────────────────────────────────────────────
_HASH_BY_LENGTH = {
    32: ['MD5', 'NTLM'],
    40: ['SHA-1'],
    56: ['SHA-224'],
    64: ['SHA-256'],
    96: ['SHA-384'],
    128: ['SHA-512'],
}
_ALGO_MAP = {
    32: 'md5', 40: 'sha1', 56: 'sha224', 64: 'sha256', 96: 'sha384', 128: 'sha512',
}

_COMMON_WORDS = [
    'password', '123456', '123456789', 'qwerty', 'admin', 'letmein', 'welcome',
    'monkey', 'dragon', 'football', 'iloveyou', 'password1', 'abc123', '111111',
    'sunshine', 'master', 'shadow', 'superman', 'trustno1', 'hello', 'changeme',
    'root', 'toor', 'pass', 'test', 'guest', 'login', 'passw0rd', 'secret',
]


def hash_identify(value):
    value = (value or '').strip()
    if not value:
        return {'error': 'No hash specified'}
    candidates = _HASH_BY_LENGTH.get(len(value))
    hex_only = all(c in '0123456789abcdefABCDEF' for c in value)
    if not candidates or not hex_only:
        guess = ['bcrypt'] if value.startswith('$2') else ['Unknown / non-standard']
        return {'hash': value, 'length': len(value), 'candidates': guess}
    return {'hash': value, 'length': len(value), 'candidates': candidates}


def hash_crack(value, wordlist=None):
    """Attempt a dictionary attack against a hash using a supplied or common wordlist."""
    value = (value or '').strip().lower()
    info = hash_identify(value)
    if 'error' in info:
        return info
    algo = _ALGO_MAP.get(len(value))
    if not algo:
        return {'hash': value, 'cracked': False, 'reason': 'Unsupported hash length for dictionary attack',
                'candidates': info['candidates']}

    words = []
    if wordlist:
        words = [w.strip() for w in wordlist.replace(',', '\n').splitlines() if w.strip()]
    words = words or _COMMON_WORDS

    tried = 0
    for word in words[:100000]:
        tried += 1
        digest = hashlib.new(algo, word.encode()).hexdigest()
        if digest == value:
            return {'hash': value, 'algorithm': algo.upper(), 'cracked': True,
                    'plaintext': word, 'attempts': tried, 'candidates': info['candidates']}
    return {'hash': value, 'algorithm': algo.upper(), 'cracked': False,
            'attempts': tried, 'candidates': info['candidates']}
