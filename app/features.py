# ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Role-based user management, safe bulk operations and certificate renewal requests."""
import re
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from .db import connect, asdicts
from .security import hash_password, require_admin, require_editor
from .validation import HostInput
from .main import transactional_write

router = APIRouter(prefix='/api')
USER_RE = re.compile(r'^[A-Za-z0-9._-]{3,80}$')


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=256)
    role: Literal['admin', 'editor', 'viewer'] = 'viewer'
    active: bool = True

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not USER_RE.fullmatch(v):
            raise ValueError('Benutzername: 3-80 Buchstaben, Ziffern, Punkte, Bindestriche, Unterstriche')
        return v


class UserModify(BaseModel):
    role: Literal['admin', 'editor', 'viewer']
    active: bool = True


class PasswordModify(BaseModel):
    password: str = Field(min_length=8, max_length=256)


class BulkModify(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=500)
    action: Literal['delete', 'enable', 'disable', 'categorize']
    delete_certificates: bool = False
    category: str = Field(default='', max_length=70)

    @field_validator('ids')
    @classmethod
    def ids_valid(cls, v):
        if len(set(v)) != len(v) or any(not re.fullmatch(r'[a-f0-9]{16}', x) for x in v):
            raise ValueError('Ungueltige oder doppelte Domain-IDs')
        return v

    @field_validator('category')
    @classmethod
    def category_valid(cls, v):
        v = v.strip()
        if any(ord(c) < 32 for c in v) or any(c in '<>\\/' for c in v):
            raise ValueError('Ungueltiger Kategoriename')
        return v


@router.get('/users')
def users(session=Depends(require_admin)):
    con = connect()
    try:
        return asdicts(con.execute('SELECT username,role,active,created_at FROM admins ORDER BY username'))
    finally:
        con.close()


@router.post('/users')
async def user_create(data: UserCreate, session=Depends(require_admin)):
    # Perform expensive scrypt before obtaining SQLite's write lock.
    password_hash = hash_password(data.password)

    def operation(con):
        if con.execute('SELECT 1 FROM admins WHERE username=?', (data.username,)).fetchone():
            raise HTTPException(409, 'Benutzername bereits vorhanden')
        con.execute('INSERT INTO admins(username,password_hash,role,active) VALUES(?,?,?,?)',
                    (data.username, password_hash, data.role, int(data.active)))
        return data.username

    return await transactional_write(session['username'], 'user.create', data.username, operation, deploy=False)


@router.put('/users/{username}')
async def user_update(username: str, data: UserModify, session=Depends(require_admin)):
    def operation(con):
        old = con.execute('SELECT username,role,active FROM admins WHERE username=?', (username,)).fetchone()
        if not old:
            raise HTTPException(404, 'Benutzer nicht gefunden')
        if session['username'] == username and (not data.active or data.role != 'admin'):
            raise HTTPException(409, 'Eigenen Administratorzugang nicht deaktivieren oder herabstufen')
        last_active_admin = con.execute("SELECT COUNT(*) FROM admins WHERE role='admin' AND active=1").fetchone()[0]
        if old['role'] == 'admin' and old['active'] and (not data.active or data.role != 'admin') and last_active_admin <= 1:
            raise HTTPException(409, 'Der letzte aktive Administrator muss erhalten bleiben')
        con.execute('UPDATE admins SET role=?,active=? WHERE username=?', (data.role, int(data.active), username))
        if not data.active or data.role != old['role']:
            con.execute('DELETE FROM sessions WHERE username=?', (username,))
        return username
    return await transactional_write(session['username'], 'user.update', username, operation, deploy=False)


@router.post('/users/{username}/password')
async def user_password(username: str, data: PasswordModify, session=Depends(require_admin)):
    password_hash = hash_password(data.password)

    def operation(con):
        if not con.execute('SELECT 1 FROM admins WHERE username=?', (username,)).fetchone():
            raise HTTPException(404, 'Benutzer nicht gefunden')
        con.execute('UPDATE admins SET password_hash=? WHERE username=?', (password_hash, username))
        con.execute('DELETE FROM sessions WHERE username=?', (username,))
        return username

    return await transactional_write(session['username'], 'user.password_reset', username, operation, deploy=False)


@router.delete('/users/{username}')
async def user_delete(username: str, session=Depends(require_admin)):
    def operation(con):
        old = con.execute('SELECT role,active FROM admins WHERE username=?', (username,)).fetchone()
        if not old:
            raise HTTPException(404, 'Benutzer nicht gefunden')
        if username == session['username']:
            raise HTTPException(409, 'Eigenen Benutzer nicht loeschen')
        if old['role'] == 'admin' and old['active']:
            n = con.execute("SELECT COUNT(*) FROM admins WHERE role='admin' AND active=1").fetchone()[0]
            if n <= 1:
                raise HTTPException(409, 'Der letzte aktive Administrator muss erhalten bleiben')
        con.execute('DELETE FROM admins WHERE username=?', (username,))
        return username

    return await transactional_write(session['username'], 'user.delete', username, operation, deploy=False)


@router.post('/hosts/bulk')
async def bulk_hosts(payload: BulkModify, session=Depends(require_editor)):
    """An all-or-nothing write. Only unreferenced certificates are removed."""
    def operation(con):
        selected = [dict(x) for x in con.execute(
            f"SELECT * FROM hosts WHERE id IN ({','.join('?' for _ in payload.ids)})", payload.ids)]
        if len(selected) != len(payload.ids):
            raise HTTPException(404, 'Mindestens eine Domain ist nicht mehr vorhanden; neu laden')
        count = len(selected)
        shared = []
        removed_certs = []
        if payload.action == 'delete':
            cert_ids = {r['certificate_id'] for r in selected if r['certificate_id']}
            con.executemany('DELETE FROM hosts WHERE id=?', [(i,) for i in payload.ids])
            if payload.delete_certificates:
                for cert_id in cert_ids:
                    other = con.execute('SELECT 1 FROM hosts WHERE certificate_id=? LIMIT 1', (cert_id,)).fetchone()
                    if other:
                        shared.append(cert_id)
                        continue
                    c = con.execute('SELECT * FROM certificates WHERE id=?', (cert_id,)).fetchone()
                    if c is None:
                        continue
                    # Only files owned by ProxyCircuit are considered for later safe cleanup.
                    con.execute('INSERT OR IGNORE INTO certificate_cleanup(id,kind,fullchain_path,privkey_path) VALUES(?,?,?,?)',
                                (cert_id, c['kind'], c['fullchain_path'], c['privkey_path']))
                    con.execute('DELETE FROM certificates WHERE id=?', (cert_id,))
                    removed_certs.append(cert_id)
        elif payload.action in ('enable', 'disable'):
            if payload.action == 'enable':
                certs = {r['id']: dict(r) for r in con.execute('SELECT * FROM certificates')}
                from .validation import cert_matches_domain
                for host in selected:
                    if host['certificate_id']:
                        cert = certs.get(host['certificate_id'])
                        if not cert or cert['status'] != 'ready' or not cert_matches_domain(cert['domain'], host['domain']):
                            raise HTTPException(422, f'{host["domain"]}: Zertifikat fehlt oder deckt die Domain nicht ab')
            con.executemany('UPDATE hosts SET enabled=? WHERE id=?',
                            [(int(payload.action == 'enable'), i) for i in payload.ids])
        else:
            con.executemany('UPDATE hosts SET category=? WHERE id=?',
                            [(payload.category, i) for i in payload.ids])
        return {'count': count, 'action': payload.action,
                'certificates_removed': len(removed_certs),
                'certificates_kept_shared': len(shared)}

    return await transactional_write(session['username'], 'hosts.bulk.'+payload.action, str(len(payload.ids)), operation)


@router.post('/certificates/{cert_id}/renew')
async def renew_certificate(cert_id: str, session=Depends(require_editor)):
    """Queue a one-time ACME renewal. Never attempt to renew imported PEM certificates."""
    def operation(con):
        cert = con.execute('SELECT * FROM certificates WHERE id=?', (cert_id,)).fetchone()
        if cert is None:
            raise HTTPException(404, 'Zertifikat nicht gefunden')
        if cert['kind'] != 'acme':
            raise HTTPException(422, 'Importierte PEM-Zertifikate koennen nicht per ACME erneuert werden; neues PEM importieren')
        if cert['status'] != 'ready':
            raise HTTPException(409, 'Zertifikat ist noch nicht bereit')
        if con.execute("SELECT 1 FROM certificate_jobs WHERE cert_id=? AND status='pending'", (cert_id,)).fetchone():
            raise HTTPException(409, 'Fuer dieses Zertifikat laeuft bereits ein Auftrag')
        job = con.execute("SELECT email FROM certificate_jobs WHERE cert_id=? AND email<>'' ORDER BY created_at DESC LIMIT 1",(cert_id,)).fetchone()
        if job is None:
            raise HTTPException(422, 'ACME-Kontaktadresse fehlt; sichere manuelle Neu-Ausstellung erforderlich')
        host = con.execute('SELECT 1 FROM hosts WHERE domain=? AND enabled=1', (cert['domain'],)).fetchone()
        if not host:
            raise HTTPException(422, 'Fuer HTTP-01 muss ein aktiver Host dieser Domain eingerichtet sein')
        jid = uuid.uuid4().hex[:16]
        con.execute("INSERT INTO certificate_jobs(id,cert_id,domain,email,operation,status) VALUES(?,?,?,?,?,'pending')",
                    (jid, cert_id, cert['domain'], job['email'], 'renew'))
        return {'job_id': jid, 'domain': cert['domain'], 'state': 'queued'}
    return await transactional_write(session['username'], 'certificate.renew', cert_id, operation)


class ManualCertReplace(BaseModel):
    fullchain_pem: str = Field(min_length=100, max_length=200000)
    private_key_pem: str = Field(min_length=100, max_length=200000)


@router.post('/certificates/{cert_id}/replace')
async def replace_manual_certificate(cert_id: str, data: ManualCertReplace, session=Depends(require_editor)):
    """Replace a PEM pair in place, preserving all host assignments.

    Old certificate files are retained for secure backup/recovery, but not selected
    in the live Nginx config after a successful apply.
    """
    import os
    from pathlib import Path
    from .settings import CERTS
    from .main import validate_manual_pem
    import asyncio
    from datetime import datetime, timezone

    con = connect()
    try:
        certificate = con.execute('SELECT id,domain,kind FROM certificates WHERE id=?', (cert_id,)).fetchone()
        if not certificate:
            raise HTTPException(404, 'Zertifikat nicht gefunden')
        if certificate['kind'] != 'manual':
            raise HTTPException(422, 'ACME-Zertifikate bitte ueber Erneuern aktualisieren')
        cert_domain = certificate['domain']
    finally:
        con.close()

    expiry = await asyncio.to_thread(validate_manual_pem, cert_domain, data.fullchain_pem, data.private_key_pem)
    # Each replacement uses a new unique pair; never overwrite keys while nginx uses them.
    nonce = uuid.uuid4().hex[:12]
    folder = CERTS / cert_id
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    cert_file = folder / ('fullchain-' + nonce + '.pem')
    key_file = folder / ('privkey-' + nonce + '.pem')
    try:
        for path, content, mode in ((cert_file,data.fullchain_pem,0o644), (key_file,data.private_key_pem,0o600)):
            with os.fdopen(os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode), 'w') as fp:
                fp.write(content)
            os.chmod(path, mode)
        def operation(con):
            current = con.execute('SELECT kind FROM certificates WHERE id=?', (cert_id,)).fetchone()
            if not current or current['kind'] != 'manual':
                raise HTTPException(409, 'Zertifikat zwischenzeitlich veraendert')
            con.execute("UPDATE certificates SET fullchain_path=?,privkey_path=?,expires_at=?,status='ready',error='' WHERE id=?",
                        (str(cert_file), str(key_file), expiry, cert_id))
            return {'certificate_id': cert_id, 'expires_at': expiry}
        return await transactional_write(session['username'], 'certificate.replace', cert_id, operation)
    except Exception:
        cert_file.unlink(missing_ok=True)
        key_file.unlink(missing_ok=True)
        raise
