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


# ── Minimal login page (themed to match dashboard) ───────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MEGA REAPER 9000 — AUTH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0a0e1a;
    color: #00ff41;
    font-family: 'Share Tech Mono', monospace;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    overflow: hidden;
  }
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,65,0.03) 2px, rgba(0,255,65,0.03) 4px);
    pointer-events: none;
    z-index: 0;
  }
  .container {
    position: relative;
    z-index: 1;
    width: 420px;
    border: 1px solid rgba(0,255,65,0.3);
    background: rgba(10,14,26,0.95);
    padding: 40px;
    box-shadow: 0 0 40px rgba(0,255,65,0.1), inset 0 0 40px rgba(0,255,65,0.02);
  }
  .header { text-align: center; margin-bottom: 36px; }
  .header h1 { font-size: 1.1em; letter-spacing: 0.2em; color: #00ff41; text-shadow: 0 0 10px rgba(0,255,65,0.5); }
  .header .sub { font-size: 0.7em; color: #444; letter-spacing: 0.15em; margin-top: 6px; }
  .divider { border: none; border-top: 1px solid rgba(0,255,65,0.15); margin: 0 0 28px; }
  label { display: block; font-size: 0.7em; letter-spacing: 0.15em; color: #555; margin-bottom: 6px; }
  input {
    width: 100%;
    background: rgba(0,0,0,0.5);
    border: 1px solid rgba(0,255,65,0.2);
    color: #00ff41;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.9em;
    padding: 10px 12px;
    margin-bottom: 20px;
    outline: none;
    transition: border-color 0.2s;
  }
  input:focus { border-color: rgba(0,255,65,0.6); box-shadow: 0 0 8px rgba(0,255,65,0.15); }
  button {
    width: 100%;
    background: transparent;
    border: 1px solid rgba(0,255,65,0.5);
    color: #00ff41;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.85em;
    letter-spacing: 0.15em;
    padding: 12px;
    cursor: pointer;
    transition: all 0.2s;
  }
  button:hover { background: rgba(0,255,65,0.08); box-shadow: 0 0 15px rgba(0,255,65,0.2); }
  button:active { background: rgba(0,255,65,0.15); }
  .error {
    color: #ff4444;
    font-size: 0.75em;
    text-align: center;
    margin-top: 14px;
    min-height: 1.2em;
    text-shadow: 0 0 8px rgba(255,68,68,0.4);
  }
  .cursor::after { content: '_'; animation: blink 1s step-end infinite; }
  @keyframes blink { 50% { opacity: 0; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>MEGA REAPER 9000</h1>
    <div class="sub">SECURITY OPERATIONS CENTER</div>
  </div>
  <hr class="divider">
  <form id="loginForm" onsubmit="doLogin(event)">
    <label>OPERATOR ID</label>
    <input type="text" id="username" autocomplete="username" autofocus spellcheck="false">
    <label>ACCESS CODE</label>
    <input type="password" id="password" autocomplete="current-password">
    <button type="submit">AUTHENTICATE<span class="cursor"></span></button>
  </form>
  <div class="error" id="errMsg"></div>
</div>
<script>
  async function doLogin(e) {
    e.preventDefault();
    const btn = document.querySelector('button');
    btn.textContent = 'AUTHENTICATING...';
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
        document.getElementById('errMsg').textContent = '[ ' + (d.error || 'ACCESS DENIED') + ' ]';
        btn.textContent = 'AUTHENTICATE _';
        btn.disabled = false;
      }
    } catch(err) {
      document.getElementById('errMsg').textContent = '[ CONNECTION ERROR ]';
      btn.textContent = 'AUTHENTICATE _';
      btn.disabled = false;
    }
  }
</script>
</body>
</html>
"""
