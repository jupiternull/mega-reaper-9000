"""
Metasploit Framework Routes
Module search, session management, handler control, payload generation.
All endpoints degrade gracefully when msfrpcd is not connected.
"""

import os
from flask import Blueprint, jsonify, request, send_file, abort
from flask_login import login_required

from services import msf
from services import payload_generator as pg

bp = Blueprint('msf', __name__, url_prefix='/api/msf')


# ── Status ────────────────────────────────────────────────────────────

@bp.route('/status', methods=['GET'])
@login_required
def msf_status():
    return jsonify(msf.status())


# ── Sessions ──────────────────────────────────────────────────────────

@bp.route('/sessions', methods=['GET'])
@login_required
def list_sessions():
    return jsonify(msf.get_sessions())


@bp.route('/sessions/<session_id>/exec', methods=['POST'])
@login_required
def exec_in_session(session_id):
    data = request.get_json(silent=True) or {}
    cmd = data.get('cmd', '').strip()
    if not cmd:
        return jsonify({'error': 'No command provided'}), 400
    return jsonify(msf.session_exec(session_id, cmd))


@bp.route('/sessions/<session_id>', methods=['GET'])
@login_required
def get_session(session_id):
    return jsonify(msf.session_info(session_id))


@bp.route('/sessions/<session_id>', methods=['DELETE'])
@login_required
def kill_session(session_id):
    return jsonify(msf.kill_session(session_id))


# ── Jobs (handlers + running exploits) ───────────────────────────────

@bp.route('/jobs', methods=['GET'])
@login_required
def list_jobs():
    return jsonify(msf.list_jobs())


@bp.route('/jobs/<job_id>', methods=['DELETE'])
@login_required
def kill_job(job_id):
    return jsonify(msf.kill_job(job_id))


# ── Handlers ──────────────────────────────────────────────────────────

@bp.route('/handlers', methods=['POST'])
@login_required
def start_handler():
    data = request.get_json(silent=True) or {}
    payload = data.get('payload', 'windows/meterpreter/reverse_tcp')
    lhost = data.get('lhost')
    lport = data.get('lport')
    exit_on_session = data.get('exit_on_session', False)

    if not lhost or not lport:
        return jsonify({'error': 'lhost and lport required'}), 400

    result = msf.start_handler(payload, lhost, lport, exit_on_session)
    return jsonify(result)


# ── Module search + info ──────────────────────────────────────────────

@bp.route('/modules/search', methods=['GET'])
@login_required
def search_modules():
    query = request.args.get('q', '').strip()
    module_type = request.args.get('type')
    if not query:
        return jsonify({'error': 'Query parameter q is required'}), 400
    return jsonify(msf.module_search(query, module_type=module_type))


@bp.route('/modules/<path:module_path>', methods=['GET'])
@login_required
def module_info(module_path):
    return jsonify(msf.module_info(module_path))


# ── Exploit execution ─────────────────────────────────────────────────

@bp.route('/execute', methods=['POST'])
@login_required
def execute_module():
    data = request.get_json(silent=True) or {}
    module_path = data.get('module')
    options = data.get('options', {})
    payload_path = data.get('payload')
    payload_options = data.get('payload_options', {})

    if not module_path:
        return jsonify({'error': 'module path required'}), 400

    result = msf.run_exploit(module_path, options, payload_path, payload_options)

    # If successful, persist to DB and advance kill chain
    if result.get('status') == 'launched':
        _persist_exploit_launch(
            target=options.get('RHOSTS', options.get('RHOST', 'unknown')),
            exploit=module_path,
            payload=payload_path or '',
            options=options,
            job_id=result.get('job_id'),
        )

    return jsonify(result)


def _persist_exploit_launch(target, exploit, payload, options, job_id=None):
    try:
        from database import ExploitSession, db
        from routes.exploits import _advance_killchain
        import flask
        with flask.current_app.app_context():
            count = ExploitSession.query.count()
            session_id = f"MSF_{count + 1:03d}"
            row = ExploitSession(
                session_id=session_id,
                target=str(target),
                exploit=exploit,
                status='launched',
            )
            row.payload = {'payload': payload, 'options': options, 'job_id': job_id}
            db.session.add(row)
            db.session.commit()
        _advance_killchain('DELIVER')
    except Exception as e:
        print(f'[!] Failed to persist exploit launch: {e}')


# ── Payload generation ────────────────────────────────────────────────

@bp.route('/payload/templates', methods=['GET'])
@login_required
def payload_templates():
    return jsonify({
        'templates': pg.list_templates(),
        'encoders': list(pg.ENCODERS.keys()),
        'msfvenom_available': pg.is_available(),
    })


@bp.route('/payload/generate', methods=['POST'])
@login_required
def generate_payload():
    data = request.get_json(silent=True) or {}
    template = data.get('template')
    lhost = data.get('lhost', '').strip()
    lport = data.get('lport', 4444)
    encoder = data.get('encoder', 'none')
    iterations = data.get('iterations', 1)
    fmt = data.get('format')
    extra = data.get('extra_options', {})

    if not template or not lhost:
        return jsonify({'error': 'template and lhost required'}), 400

    result = pg.generate(
        template_key=template,
        lhost=lhost,
        lport=lport,
        encoder=encoder,
        iterations=iterations,
        extra_options=extra,
        custom_format=fmt,
    )
    return jsonify(result)


@bp.route('/payload/list', methods=['GET'])
@login_required
def list_payloads():
    return jsonify({'payloads': pg.list_generated()})


@bp.route('/payload/download/<filename>', methods=['GET'])
@login_required
def download_payload(filename):
    import re
    if not re.match(r'^payload_[\w]+\.[\w]+$', filename):
        abort(400)
    path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'data', 'payloads', filename
    )
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True)


@bp.route('/payload/<filename>', methods=['DELETE'])
@login_required
def delete_payload(filename):
    return jsonify(pg.delete_payload(filename))
