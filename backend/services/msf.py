"""
Metasploit RPC client.
Connects to msfrpcd via pymetasploit3.
Gracefully degrades when msfrpcd is not running — all methods return
{'msf_available': False, 'error': '...'} rather than raising.

Config (from .env):
  MSF_HOST     — default 127.0.0.1
  MSF_PORT     — default 55553
  MSF_PASSWORD — required for real connection
  MSF_SSL      — default true
"""

import os
import time
import threading

_client = None
_client_lock = threading.Lock()
_last_connect_attempt = 0.0
_RECONNECT_INTERVAL = 30  # seconds between reconnect attempts


def _connect():
    global _client, _last_connect_attempt
    now = time.time()
    if now - _last_connect_attempt < _RECONNECT_INTERVAL:
        return _client
    _last_connect_attempt = now

    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        host = os.environ.get('MSF_HOST', '127.0.0.1')
        port = int(os.environ.get('MSF_PORT', 55553))
        password = os.environ.get('MSF_PASSWORD', '')
        ssl = os.environ.get('MSF_SSL', 'true').lower() != 'false'

        if not password:
            return None

        client = MsfRpcClient(password, server=host, port=port, ssl=ssl)
        _client = client
        print(f'[+] MSF RPC connected: {host}:{port}')
        return _client
    except Exception as e:
        print(f'[-] MSF RPC connection failed: {e}')
        _client = None
        return None


def _get_client():
    with _client_lock:
        if _client is None:
            return _connect()
        return _client


def _unavailable(extra=None):
    r = {'msf_available': False, 'error': 'msfrpcd not connected'}
    if extra:
        r.update(extra)
    return r


# ── Status ────────────────────────────────────────────────────────────

def status():
    client = _get_client()
    if not client:
        return {
            'msf_available': False,
            'connected': False,
            'error': 'msfrpcd not running or MSF_PASSWORD not set',
            'config': {
                'host': os.environ.get('MSF_HOST', '127.0.0.1'),
                'port': os.environ.get('MSF_PORT', '55553'),
                'ssl': os.environ.get('MSF_SSL', 'true'),
            }
        }
    try:
        ver = client.core.version()
        return {
            'msf_available': True,
            'connected': True,
            'version': ver.get('version', 'unknown'),
            'ruby': ver.get('ruby', 'unknown'),
            'api': ver.get('api', 'unknown'),
        }
    except Exception as e:
        _reset_client()
        return {'msf_available': False, 'connected': False, 'error': str(e)}


def _reset_client():
    global _client
    with _client_lock:
        _client = None


# ── Sessions ──────────────────────────────────────────────────────────

def get_sessions():
    client = _get_client()
    if not client:
        return _unavailable({'sessions': []})
    try:
        raw = client.sessions.list
        sessions = []
        for sid, info in raw.items():
            sessions.append({
                'id': str(sid),
                'type': info.get('type', 'unknown'),
                'tunnel_local': info.get('tunnel_local', ''),
                'tunnel_peer': info.get('tunnel_peer', ''),
                'via_exploit': info.get('via_exploit', ''),
                'via_payload': info.get('via_payload', ''),
                'desc': info.get('desc', ''),
                'info': info.get('info', ''),
                'workspace': info.get('workspace', 'default'),
                'target_host': info.get('target_host', ''),
                'username': info.get('username', ''),
                'uuid': info.get('uuid', ''),
                'exploit_uuid': info.get('exploit_uuid', ''),
                'routes': info.get('routes', []),
                'arch': info.get('arch', ''),
                'platform': info.get('platform', ''),
                'msf_available': True,
            })
        return {'msf_available': True, 'sessions': sessions}
    except Exception as e:
        _reset_client()
        return _unavailable({'sessions': [], 'error': str(e)})


def session_exec(session_id, cmd, timeout=30):
    client = _get_client()
    if not client:
        return _unavailable({'output': ''})
    try:
        shell = client.sessions.session(str(session_id))
        shell.write(cmd)
        time.sleep(1)
        output = shell.read()
        return {'msf_available': True, 'output': output, 'session_id': session_id}
    except Exception as e:
        return _unavailable({'output': '', 'error': str(e)})


def session_info(session_id):
    result = get_sessions()
    if not result.get('msf_available'):
        return result
    for s in result['sessions']:
        if str(s['id']) == str(session_id):
            return {'msf_available': True, 'session': s}
    return {'msf_available': True, 'session': None, 'error': 'Session not found'}


def kill_session(session_id):
    client = _get_client()
    if not client:
        return _unavailable()
    try:
        client.sessions.session(str(session_id)).stop()
        return {'msf_available': True, 'status': 'killed', 'session_id': session_id}
    except Exception as e:
        return _unavailable({'error': str(e)})


# ── Module operations ─────────────────────────────────────────────────

def module_search(query, module_type=None):
    client = _get_client()
    if not client:
        return _unavailable({'modules': []})
    try:
        results = client.modules.search(query)
        modules = []
        for m in results[:50]:
            if module_type and not m.get('fullname', '').startswith(module_type):
                continue
            modules.append({
                'fullname': m.get('fullname', ''),
                'name': m.get('name', ''),
                'rank': m.get('rank', ''),
                'type': m.get('type', ''),
                'disclosure_date': m.get('disclosure_date', ''),
                'description': m.get('description', '')[:200],
            })
        return {'msf_available': True, 'modules': modules, 'total': len(modules)}
    except Exception as e:
        return _unavailable({'modules': [], 'error': str(e)})


def module_info(module_path):
    client = _get_client()
    if not client:
        return _unavailable()
    try:
        parts = module_path.split('/', 1)
        if len(parts) != 2:
            return {'msf_available': False, 'error': 'Invalid module path (type/name)'}
        mod_type, mod_name = parts
        mod = client.modules.use(mod_type, mod_name)
        options = {}
        for opt_name in mod.options:
            opt = mod.optioninfo(opt_name)
            options[opt_name] = {
                'required': opt.get('required', False),
                'desc': opt.get('desc', ''),
                'default': opt.get('default', ''),
                'type': opt.get('type', 'string'),
            }
        return {
            'msf_available': True,
            'name': mod.name,
            'description': mod.description,
            'rank': mod.rank,
            'references': list(mod.references)[:10],
            'options': options,
            'targets': list(getattr(mod, 'targets', {}).keys())[:20],
        }
    except Exception as e:
        return _unavailable({'error': str(e)})


# ── Exploit execution ─────────────────────────────────────────────────

def run_exploit(module_path, options, payload_path=None, payload_options=None):
    """
    Execute an exploit module via msfrpcd.
    Returns job_id + uuid on success.
    """
    client = _get_client()
    if not client:
        return _unavailable()
    try:
        parts = module_path.split('/', 1)
        if len(parts) != 2:
            return {'msf_available': False, 'error': 'Invalid module path (type/name)'}
        mod_type, mod_name = parts
        mod = client.modules.use(mod_type, mod_name)

        # Set module options
        for key, val in (options or {}).items():
            mod[key] = val

        # Set payload if specified
        payload = None
        if payload_path:
            payload = client.modules.use('payload', payload_path)
            for key, val in (payload_options or {}).items():
                payload[key] = val

        result = mod.execute(payload=payload)
        return {
            'msf_available': True,
            'status': 'launched',
            'job_id': result.get('job_id'),
            'uuid': result.get('uuid'),
            'module': module_path,
        }
    except Exception as e:
        return _unavailable({'error': str(e)})


# ── Multi/handler ─────────────────────────────────────────────────────

def start_handler(payload, lhost, lport, exit_on_session=False):
    """Start a multi/handler listener for reverse shell callbacks."""
    return run_exploit(
        'exploit/multi/handler',
        {'ExitOnSession': exit_on_session},
        payload_path=payload,
        payload_options={'LHOST': lhost, 'LPORT': int(lport)},
    )


def list_jobs():
    client = _get_client()
    if not client:
        return _unavailable({'jobs': []})
    try:
        jobs = client.jobs.list
        return {
            'msf_available': True,
            'jobs': [
                {'id': jid, 'name': info.get('name', ''), 'start_time': info.get('start_time', '')}
                for jid, info in jobs.items()
            ]
        }
    except Exception as e:
        return _unavailable({'jobs': [], 'error': str(e)})


def kill_job(job_id):
    client = _get_client()
    if not client:
        return _unavailable()
    try:
        client.jobs.stop(str(job_id))
        return {'msf_available': True, 'status': 'killed', 'job_id': job_id}
    except Exception as e:
        return _unavailable({'error': str(e)})
