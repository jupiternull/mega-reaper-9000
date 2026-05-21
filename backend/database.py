"""
SQLAlchemy models and database initialization.
Persists scan history, alert log, exploit sessions, and compromised hosts.
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(256), nullable=False)
    scan_type = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    hosts_found = db.Column(db.Integer, default=0)
    _results_json = db.Column('results_json', db.Text, default='{}')

    @property
    def results(self):
        return json.loads(self._results_json)

    @results.setter
    def results(self, value):
        self._results_json = json.dumps(value)

    def to_dict(self):
        return {
            'id': self.id,
            'target': self.target,
            'scan_type': self.scan_type,
            'timestamp': self.timestamp.isoformat(),
            'hosts_found': self.hosts_found,
            'results': self.results,
        }


class AlertLog(db.Model):
    __tablename__ = 'alert_log'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    alert_type = db.Column(db.String(64))
    severity = db.Column(db.String(32))
    message = db.Column(db.Text)
    source = db.Column(db.String(64))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'type': self.alert_type,
            'severity': self.severity,
            'message': self.message,
            'source': self.source,
        }


class ExploitSession(db.Model):
    __tablename__ = 'exploit_sessions'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    target = db.Column(db.String(256), nullable=False)
    exploit = db.Column(db.String(256), nullable=False)
    status = db.Column(db.String(64), default='launched')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    closed_at = db.Column(db.DateTime, nullable=True)
    _payload_json = db.Column('payload_json', db.Text, default='{}')

    @property
    def payload(self):
        return json.loads(self._payload_json)

    @payload.setter
    def payload(self, value):
        self._payload_json = json.dumps(value)

    def to_dict(self):
        elapsed = int((datetime.utcnow() - self.created_at).total_seconds())
        last_seen = f'{elapsed}s ago' if elapsed < 60 else f'{elapsed // 60}m ago'
        return {
            'id': self.session_id,
            'target': self.target,
            'exploit': self.exploit,
            'status': self.status,
            'timestamp': self.created_at.isoformat(),
            'payload': self.payload,
            'last_seen': last_seen,
            '_created': self.created_at.timestamp(),
        }


class CompromisedHost(db.Model):
    __tablename__ = 'compromised_hosts'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), unique=True, nullable=False)
    hostname = db.Column(db.String(256), default='unknown')
    os = db.Column(db.String(256), default='unknown')
    privilege = db.Column(db.String(64), default='user')
    shell = db.Column(db.String(64), default='unknown')
    loot = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        elapsed = int((datetime.utcnow() - self.created_at).total_seconds())
        last_seen = f'{elapsed}s ago' if elapsed < 60 else f'{elapsed // 60}m ago'
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'os': self.os,
            'privilege': self.privilege,
            'shell': self.shell,
            'loot': self.loot,
            'last_seen': last_seen,
            '_created': self.created_at.timestamp(),
        }
