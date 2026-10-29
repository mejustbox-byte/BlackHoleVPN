"""Experimental offline subscription registry and WSGI response handler.

Not a production server. Place behind a correctly configured HTTPS gateway.
"""
import base64
from contextlib import closing
import hashlib
import re
import secrets
import sqlite3
from urllib.parse import urlsplit

TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{43}')
MAX_BODY = 65536


def token_hash(token):
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise ValueError('invalid subscription token')
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def validate_profiles(profiles):
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= 10:
        raise ValueError('expected 1 to 10 profiles')
    clean = []
    for value in profiles:
        if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 33 or ord(c) == 127 for c in value):
            raise ValueError('invalid profile')
        try:
            uri = urlsplit(value)
            if uri.scheme != 'vless' or not uri.hostname or not uri.username or uri.port is None:
                raise ValueError('invalid VLESS profile')
        except ValueError:
            raise ValueError('invalid VLESS profile') from None
        clean.append(value)
    payload = ('\n'.join(clean) + '\n').encode('utf-8')
    if len(payload) > MAX_BODY:
        raise ValueError('subscription too large')
    return base64.b64encode(payload)


def connect(path):
    db = sqlite3.connect(path, timeout=5)
    db.execute('CREATE TABLE IF NOT EXISTS subscriptions (token_hash TEXT PRIMARY KEY, body BLOB NOT NULL)')
    db.commit()
    return db


def issue(db, profiles):
    body = validate_profiles(profiles)
    token = secrets.token_urlsafe(32)
    with db:
        db.execute('INSERT INTO subscriptions(token_hash, body) VALUES (?,?)', (token_hash(token), body))
    return token


def update(db, token, profiles):
    body = validate_profiles(profiles)
    with db:
        result = db.execute('UPDATE subscriptions SET body=? WHERE token_hash=?', (body, token_hash(token)))
        if result.rowcount != 1:
            raise KeyError('subscription not found')


def revoke(db, token):
    with db:
        return db.execute('DELETE FROM subscriptions WHERE token_hash=?', (token_hash(token),)).rowcount == 1


def application(db_path):
    """WSGI app: GET /s/<token>; logs and TLS belong to the deployment gateway."""
    def handle(env, start_response):
        headers = [('Cache-Control', 'no-store, private'), ('Pragma', 'no-cache'), ('X-Content-Type-Options', 'nosniff'), ('Content-Type', 'text/plain; charset=utf-8')]
        if env.get('REQUEST_METHOD') != 'GET':
            start_response('405 Method Not Allowed', headers + [('Allow', 'GET')])
            return [b'Not found\n']
        match = re.fullmatch(r'/s/([A-Za-z0-9_-]{43})', env.get('PATH_INFO', ''))
        body = None
        if match:
            with closing(connect(db_path)) as db:
                row = db.execute('SELECT body FROM subscriptions WHERE token_hash=?', (token_hash(match.group(1)),)).fetchone()
                if row: body = row[0]
        if body is None:
            start_response('404 Not Found', headers)
            return [b'Not found\n']
        start_response('200 OK', headers)
        return [body]
    return handle
