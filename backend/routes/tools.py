"""
Security Tools Routes
API endpoints for security scanning tools — REAL EXECUTION ONLY
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required
import subprocess
import shlex
import re
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from services.network_scanner import NetworkScanner
from services.nvd import enrich_vulnerabilities
from services import nvd
from services.geoip import lookup as geoip_lookup
from services import intel

bp = Blueprint('tools', __name__, url_prefix='/api/tools')

scanner = NetworkScanner()

@bp.route('/nmap/scan', methods=['POST'])
@login_required
def nmap_scan():
    """Execute real nmap scan"""
    data = request.get_json()
    
    target = data.get('target', '127.0.0.1')
    scan_type = data.get('scan_type', 'quick')
    
    results = scanner.scan(target, scan_type)
    
    return jsonify(results)

@bp.route('/portscan', methods=['POST'])
@login_required
def port_scan():
    """Execute real port scan"""
    data = request.get_json()
    
    target = data.get('target', '127.0.0.1')
    ports = data.get('ports', '1-1000')
    
    results = scanner.port_scan(target, ports)
    
    return jsonify(results)

@bp.route('/vulnscan', methods=['POST'])
@login_required
def vuln_scan():
    """Execute real vulnerability scan using nmap NSE scripts"""
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    
    try:
        # Run nmap with vulnerability detection scripts
        result = subprocess.run(
            ['nmap', '-sV', '--script', 'vuln', '-T4', '--open', target],
            capture_output=True, text=True, timeout=120
        )
        
        vulnerabilities = []
        current_host = None
        current_port = None
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            # Parse host
            host_match = re.match(r'Nmap scan report for\s+(\S+)', line)
            if host_match:
                current_host = host_match.group(1)
                continue
            
            # Parse port/service
            port_match = re.match(r'(\d+)/(\w+)\s+(\w+)\s+(.*)', line)
            if port_match:
                current_port = {
                    'port': int(port_match.group(1)),
                    'proto': port_match.group(2),
                    'state': port_match.group(3),
                    'service': port_match.group(4).strip()
                }
                continue
            
            # Parse CVE references
            cve_matches = re.findall(r'(CVE-\d{4}-\d+)', line)
            for cve in cve_matches:
                vulnerabilities.append({
                    'cve': cve,
                    'severity': 'high',
                    'host': current_host or target,
                    'service': current_port['service'] if current_port else 'unknown',
                    'port': current_port['port'] if current_port else 0,
                    'detail': line[:200],
                    'exploit_available': 'EXPLOIT' in line.upper() or 'VULNERABLE' in line.upper()
                })
            
            # Parse VULNERABLE flags even without CVE
            if 'VULNERABLE' in line.upper() and not cve_matches:
                vulnerabilities.append({
                    'cve': 'N/A',
                    'severity': 'warning',
                    'host': current_host or target,
                    'service': current_port['service'] if current_port else 'unknown',
                    'port': current_port['port'] if current_port else 0,
                    'detail': line[:200],
                    'exploit_available': False
                })
        
        # Enrich CVEs with real NVD CVSS scores
        enriched = enrich_vulnerabilities(vulnerabilities)

        # GeoIP on the target if it's an IP
        geo = None
        try:
            import socket as _socket
            _socket.inet_aton(target)
            geo = geoip_lookup(target)
        except Exception:
            pass

        return jsonify({
            'target': target,
            'raw_output': result.stdout[-2000:] if result.stdout else result.stderr[-2000:],
            'vulnerabilities': enriched,
            'scan_complete': True,
            'geo': geo,
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({
            'target': target,
            'error': 'Vulnerability scan timed out after 120 seconds',
            'vulnerabilities': [],
            'scan_complete': False
        })
    except FileNotFoundError:
        return jsonify({
            'target': target,
            'error': 'nmap not found — install with: sudo apt install nmap',
            'vulnerabilities': [],
            'scan_complete': False
        })
    except Exception as e:
        return jsonify({
            'target': target,
            'error': str(e),
            'vulnerabilities': [],
            'scan_complete': False
        })

@bp.route('/dns', methods=['POST'])
@login_required
def dns_enum():
    """Execute real DNS enumeration"""
    data = request.get_json()
    target = data.get('target', '')
    mode = data.get('mode', 'standard')
    record_types = data.get('record_types', ['A', 'AAAA', 'MX', 'NS', 'TXT'])
    
    if not target:
        return jsonify({'error': 'No target domain specified'}), 400
    
    results = {'target': target, 'records': [], 'raw_output': ''}
    
    for rtype in record_types:
        try:
            result = subprocess.run(
                ['dig', '+noall', '+answer', target, rtype],
                capture_output=True, text=True, timeout=15
            )
            if result.stdout.strip():
                results['raw_output'] += result.stdout
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 5:
                        results['records'].append({
                            'name': parts[0],
                            'type': parts[3],
                            'value': ' '.join(parts[4:]),
                            'ttl': parts[1]
                        })
        except Exception as e:
            results['raw_output'] += f'Error querying {rtype}: {e}\n'
    
    # Zone transfer attempt if requested
    if mode in ('axfr', 'comprehensive'):
        try:
            result = subprocess.run(
                ['dig', 'axfr', target],
                capture_output=True, text=True, timeout=15
            )
            results['zone_transfer'] = {
                'attempted': True,
                'success': 'Transfer failed' not in result.stdout and bool(result.stdout.strip()),
                'output': result.stdout[-1000:] if result.stdout else 'No output'
            }
        except Exception:
            results['zone_transfer'] = {'attempted': True, 'success': False, 'output': 'Error'}
    
    return jsonify(results)

@bp.route('/webscan', methods=['POST'])
@login_required
def web_scan():
    """Execute real web scan using nikto or curl-based checks"""
    data = request.get_json()
    target_url = data.get('target', '')
    
    if not target_url:
        return jsonify({'error': 'No target URL specified'}), 400
    
    results = {'target': target_url, 'findings': [], 'raw_output': ''}
    
    # Try nikto first
    try:
        result = subprocess.run(
            ['nikto', '-h', target_url, '-maxtime', '60s', '-Tuning', '123'],
            capture_output=True, text=True, timeout=90
        )
        results['raw_output'] = result.stdout[-3000:] if result.stdout else result.stderr[-1000:]
        
        # Parse nikto findings
        for line in result.stdout.split('\n'):
            if line.startswith('+'):
                severity = 'info'
                if any(w in line.upper() for w in ['VULNERABILITY', 'INJECTION', 'XSS']):
                    severity = 'critical'
                elif any(w in line.upper() for w in ['OUTDATED', 'DEPRECATED', 'HEADER']):
                    severity = 'warning'
                results['findings'].append({
                    'message': line[2:].strip(),
                    'severity': severity
                })
    except FileNotFoundError:
        results['raw_output'] = 'nikto not installed. Falling back to basic header checks.\n'
        
        # Fallback: basic HTTP header analysis
        try:
            result = subprocess.run(
                ['curl', '-sI', '-m', '10', target_url],
                capture_output=True, text=True, timeout=15
            )
            headers = result.stdout
            results['raw_output'] += headers
            
            # Check security headers
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header'
            }
            
            for header, msg in security_headers.items():
                if header.lower() not in headers.lower():
                    results['findings'].append({
                        'message': msg,
                        'severity': 'warning'
                    })
            
            # Check server version disclosure
            server_match = re.search(r'Server:\s*(.+)', headers, re.IGNORECASE)
            if server_match:
                results['findings'].append({
                    'message': f'Server version disclosed: {server_match.group(1).strip()}',
                    'severity': 'info'
                })
                
        except Exception as e:
            results['raw_output'] += f'Error: {e}\n'
    except subprocess.TimeoutExpired:
        results['raw_output'] = 'Web scan timed out after 90 seconds'
    except Exception as e:
        results['raw_output'] = f'Error: {e}'
    
    return jsonify(results)


# ── Extended recon & intel tooling ───────────────────────────────────

@bp.route('/tls', methods=['POST'])
@login_required
def tls_inspect():
    """Inspect the TLS certificate and negotiated cipher of a host."""
    data = request.get_json() or {}
    host = data.get('target', '')
    port = int(data.get('port') or 443)
    return jsonify(intel.tls_inspect(host, port))


@bp.route('/http-headers', methods=['POST'])
@login_required
def http_headers():
    """Fetch and grade a target's HTTP security headers."""
    data = request.get_json() or {}
    return jsonify(intel.http_headers(data.get('target', '')))


@bp.route('/whois', methods=['POST'])
@login_required
def whois_lookup():
    """Run a WHOIS lookup for a domain or IP."""
    data = request.get_json() or {}
    return jsonify(intel.whois_lookup(data.get('target', '')))


@bp.route('/ipinfo', methods=['POST'])
@login_required
def ip_info():
    """Resolve, reverse-resolve and geolocate a host."""
    data = request.get_json() or {}
    return jsonify(intel.ip_info(data.get('target', '')))


@bp.route('/cve', methods=['POST'])
@login_required
def cve_search():
    """Search the NVD catalog by CVE id or keyword."""
    data = request.get_json() or {}
    return jsonify(nvd.search(data.get('target', ''), limit=int(data.get('limit') or 15)))


@bp.route('/hash', methods=['POST'])
@login_required
def hash_tool():
    """Identify a hash and optionally run a dictionary attack."""
    data = request.get_json() or {}
    value = data.get('target', '')
    if data.get('crack'):
        return jsonify(intel.hash_crack(value, data.get('wordlist')))
    return jsonify(intel.hash_identify(value))


@bp.route('/pingsweep', methods=['POST'])
@login_required
def ping_sweep():
    """Host discovery sweep across a subnet (nmap -sn)."""
    data = request.get_json() or {}
    target = data.get('target', '')
    if not target:
        return jsonify({'error': 'No subnet specified'}), 400
    try:
        result = subprocess.run(
            ['nmap', '-sn', '-T4', target],
            capture_output=True, text=True, timeout=120
        )
    except FileNotFoundError:
        return jsonify({'error': 'nmap not found — install with: sudo apt install nmap'}), 500
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Ping sweep timed out'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    hosts = []
    current_ip = None
    for line in result.stdout.splitlines():
        m = re.search(r'Nmap scan report for (.+)', line)
        if m:
            label = m.group(1).strip()
            ipm = re.search(r'\(([\d.]+)\)', label)
            current_ip = {'host': label, 'ip': ipm.group(1) if ipm else label, 'mac': None, 'vendor': None}
            hosts.append(current_ip)
        elif current_ip is not None and 'MAC Address' in line:
            macm = re.search(r'MAC Address: (\S+)\s*\(([^)]*)\)', line)
            if macm:
                current_ip['mac'] = macm.group(1)
                current_ip['vendor'] = macm.group(2)

    return jsonify({'target': target, 'count': len(hosts), 'hosts': hosts,
                    'raw_output': result.stdout[-2000:]})
