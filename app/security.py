# ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Password hashing and opaque server-side cookie sessions."""
import hashlib
import hmac
import secrets
import time
from fastapi import HTTPException, Request
from .db import connect

SESSION_TTL = 8 * 3600
COOKIE = 'rpmgr_session'

def hash_password(password: str, salt: bytes | None = None) -> str:
    if len(password) < 8:
        raise ValueError('Admin-Passwort muss mindestens 8 Zeichen haben')
    salt = salt or secrets.token_bytes(16)
    hash_bytes = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return 'scrypt$' + salt.hex() + '$' + hash_bytes.hex()

def verify_password(password: str, saved: str) -> bool:
    try:
        algo, salt, expected = saved.split('$')
        if algo != 'scrypt':
            return False
        actual = hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False

def new_session(username: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(36)
    csrf = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    con = connect()
    con.execute('DELETE FROM sessions WHERE expires<?', (int(time.time()),))
    con.execute('INSERT INTO sessions(token_hash,username,csrf,expires) VALUES(?,?,?,?)',
                (token_hash, username, csrf, int(time.time()) + SESSION_TTL))
    con.commit()
    con.close()
    return token, csrf

def get_session(request: Request, check_csrf: bool = True) -> dict:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, detail='Bitte erneut anmelden')
    con = connect()
    row = con.execute('''SELECT s.username,s.csrf,s.expires,a.role,a.active FROM sessions s JOIN admins a ON s.username=a.username WHERE s.token_hash=?''',
                      (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    con.close()
    if not row or not row['active'] or row['expires'] < int(time.time()):
        raise HTTPException(401, detail='Sitzung abgelaufen. Bitte erneut anmelden')
    if check_csrf and request.method not in ('GET', 'HEAD', 'OPTIONS'):
        supplied = request.headers.get('x-csrf-token', '')
        if not hmac.compare_digest(supplied, row['csrf']):
            raise HTTPException(403, detail='Sicherheitsprüfung fehlgeschlagen (CSRF)')
    return {'username': row['username'], 'role': row['role'], 'csrf': row['csrf']}

def require_session(request: Request):
    return get_session(request, check_csrf=True)


def require_editor(request: Request):
    user = get_session(request, check_csrf=True)
    if user['role'] not in ('admin', 'editor'):
        raise HTTPException(403, 'Nur Administratoren oder Bearbeiter duerfen aendern')
    return user


def require_admin(request: Request):
    user = get_session(request, check_csrf=True)
    if user['role'] != 'admin':
        raise HTTPException(403, 'Diese Funktion ist Administratoren vorbehalten')
    return user
