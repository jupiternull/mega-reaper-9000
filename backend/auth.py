"""
Authentication — Flask-Login + bcrypt.
Single-operator tool; credentials loaded from environment variables.
"""

import os
import bcrypt
from flask import Blueprint, request, jsonify, redirect, url_for, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

login_manager = LoginManager()
bp = Blueprint('auth', __name__, url_prefix='/auth')


class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

    @staticmethod
    def get(user_id):
        if user_id == 'admin':
            return User('admin')
        return None


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@login_manager.unauthorized_handler
def unauthorized():
    # API requests get 401; browser requests get redirect
    if request.path.startswith('/api') or request.path.startswith('/socket.io'):
        return jsonify({'error': 'Unauthorized'}), 401
    return redirect(url_for('auth.login_page'))


def _check_credentials(username, password):
    expected_user = os.environ.get('REAPER_USER', 'admin')
    password_hash = os.environ.get('REAPER_PASSWORD_HASH', '')

    if username != expected_user:
        return False
    if not password_hash:
        # No hash set — deny all logins until configured
        return False
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except Exception:
        return False


@bp.route('/login', methods=['GET'])
def login_page():
    if current_user.is_authenticated:
        return redirect('/')
    # Serve the login HTML (inline, keeps single-file frontend approach)
    return make_response(LOGIN_HTML)


@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if _check_credentials(username, password):
        user = User(username)
        login_user(user, remember=True)
        return jsonify({'status': 'ok'})

    return jsonify({'error': 'Invalid credentials'}), 401


@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'status': 'logged_out'})


@bp.route('/status', methods=['GET'])
def auth_status():
    return jsonify({'authenticated': current_user.is_authenticated})


# ── Login page (themed to match the dashboard design system) ─────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MEGA REAPER 9000 - Sign In</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='5' fill='%234f8cff'/%3E%3Cpath d='M12 4l6 2v5c0 4-2.7 6.7-6 8-3.3-1.3-6-4-6-8V6z' fill='white'/%3E%3C/svg%3E">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0b0e14; --surface: #121722; --surface-2: #1a2130; --border: #273142;
    --text: #e6edf6; --text-dim: #93a1b5; --text-faint: #5d6b82;
    --accent: #4f8cff; --accent-hover: #6ea0ff; --accent-soft: rgba(79,140,255,0.12); --violet: #a78bfa; --critical: #f0506a;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background:
      radial-gradient(1200px 600px at 80% -10%, rgba(79,140,255,0.08), transparent 60%),
      radial-gradient(900px 500px at 0% 110%, rgba(167,139,250,0.06), transparent 55%),
      var(--bg);
    color: var(--text);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    width: 400px; max-width: 100%;
    background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
    padding: 36px 34px; box-shadow: 0 1px 2px rgba(0,0,0,0.3), 0 20px 50px rgba(0,0,0,0.4);
  }
  .brand { display: flex; align-items: center; gap: 13px; margin-bottom: 28px; }
  .brand-mark {
    width: 46px; height: 46px; display: grid; place-items: center; border-radius: 11px;
    background: linear-gradient(135deg, var(--accent), var(--violet)); color: #fff; font-size: 1.3em;
    box-shadow: 0 6px 16px rgba(79,140,255,0.35);
  }
  .brand h1 { font-size: 1.05em; font-weight: 700; letter-spacing: 0.3px; }
  .brand .sub { font-size: 0.68em; color: var(--text-faint); letter-spacing: 1.5px; text-transform: uppercase; font-weight: 500; margin-top: 2px; }
  .heading { font-size: 1.15em; font-weight: 600; margin-bottom: 4px; }
  .heading + p { color: var(--text-dim); font-size: 0.85em; margin-bottom: 24px; }
  label { display: block; font-size: 0.78em; font-weight: 500; color: var(--text-dim); margin-bottom: 7px; }
  input {
    width: 100%; background: var(--surface-2); border: 1px solid var(--border); color: var(--text);
    font-family: inherit; font-size: 0.92em; padding: 11px 13px; margin-bottom: 18px; border-radius: 8px;
    outline: none; transition: all 0.15s;
  }
  input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
  button {
    width: 100%; background: var(--accent); border: 1px solid var(--accent); color: #fff;
    font-family: inherit; font-size: 0.9em; font-weight: 600; padding: 12px; cursor: pointer;
    border-radius: 8px; transition: all 0.15s; display: flex; align-items: center; justify-content: center; gap: 8px;
  }
  button:hover { background: var(--accent-hover); border-color: var(--accent-hover); box-shadow: 0 4px 16px rgba(79,140,255,0.35); }
  button:active { transform: translateY(1px); }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .error { color: var(--critical); font-size: 0.82em; text-align: center; margin-top: 16px; min-height: 1.2em; }
  .foot { margin-top: 24px; padding-top: 18px; border-top: 1px solid var(--border); font-size: 0.74em; color: var(--text-faint); text-align: center; line-height: 1.5; }
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <div class="brand-mark"><i class="fa-solid fa-shield-halved"></i></div>
    <div><h1>MEGA REAPER 9000</h1><div class="sub">Security Operations Center</div></div>
  </div>
  <div class="heading">Operator sign in</div>
  <p>Authenticate to access the operations console.</p>
  <form id="loginForm" onsubmit="doLogin(event)">
    <label for="username">Operator ID</label>
    <input type="text" id="username" autocomplete="username" autofocus spellcheck="false" placeholder="admin">
    <label for="password">Access code</label>
    <input type="password" id="password" autocomplete="current-password" placeholder="password">
    <button type="submit"><i class="fa-solid fa-right-to-bracket"></i> <span id="btnLabel">Sign in</span></button>
  </form>
  <div class="error" id="errMsg"></div>
  <div class="foot"><i class="fa-solid fa-lock"></i> Authorized use only. All activity may be logged.</div>
</div>
<script>
  async function doLogin(e) {
    e.preventDefault();
    const btn = document.querySelector('button');
    const label = document.getElementById('btnLabel');
    label.textContent = 'Signing in...';
    btn.disabled = true;
    document.getElementById('errMsg').textContent = '';
    try {
      const res = await fetch('/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          username: document.getElementById('username').value,
          password: document.getElementById('password').value
        })
      });
      if (res.ok) {
        window.location.href = '/';
      } else {
        const d = await res.json();
        document.getElementById('errMsg').textContent = d.error || 'Access denied';
        label.textContent = 'Sign in';
        btn.disabled = false;
      }
    } catch(err) {
      document.getElementById('errMsg').textContent = 'Connection error';
      label.textContent = 'Sign in';
      btn.disabled = false;
    }
  }
</script>
</body>
</html>
"""
