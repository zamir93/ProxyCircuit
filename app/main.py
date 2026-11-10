# ProxyCircuit v0.2.3 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""FastAPI admin service. Run as unprivileged rpmgr; root worker applies Nginx config."""
import asyncio
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from fastapi import FastAPI, Request, Response, HTTPException, Depends, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import psutil
from pydantic import BaseModel
from . import __version__
from .db import init_db, connect, asdicts, audit
from .diagnostics import diagnose_route
from .security import (COOKIE, SESSION_TTL, hash_password, verify_password, new_session, require_session, require_editor, require_admin, get_session)
from .settings import BASE, CERTS, DEPLOY, PLUGINS, DEV
from .validation import (HostInput, StreamInput, LoginInput, CertImportInput,
                         CertIssueInput, cert_matches_domain)

app = FastAPI(title='ProxyCircuit', version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
STATIC = Path(__file__).resolve().parent / 'static'
app.mount('/static', StaticFiles(directory=str(STATIC)), name='static')
change_lock = asyncio.Lock()
login_fails = {}

@app.on_event('startup')
async def startup():
    init_db()

@app.middleware('http')
async def headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss:; frame-src blob:; frame-ancestors 'none'"
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    return response

@app.get('/')
def homepage():
    return FileResponse(STATIC / 'index.html')

@app.get('/favicon.ico', include_in_schema=False)
def favicon():
    return FileResponse(STATIC / 'favicon.ico', media_type='image/x-icon')

@app.get('/api/version')
def version():
    return {'version': __version__}

@app.post('/api/login')
def login(data: LoginInput, request: Request, response: Response):
    # Managed Nginx always replaces this header with its *actual* incoming scheme.
    # The UI already blocks HTTP; enforce the same security rule server-side.
    if request.headers.get('x-forwarded-proto', '').strip().lower() == 'http':
        raise HTTPException(403, 'Anmeldung ueber HTTP ist verboten. HTTPS oder VPN nutzen.')
    client = request.client.host if request.client else 'unknown'
    # Simple per-IP memory rate limiter; management access also needs firewall controls.
    old = [t for t in login_fails.get(client, []) if t > time.time() - 900]
    login_fails[client] = old
    if len(old) >= 8:
        raise HTTPException(429, 'Zu viele Anmeldeversuche. In 15 Minuten erneut probieren')
    con = connect()
    admin = con.execute('SELECT password_hash,role,active FROM admins WHERE username=?', (data.username,)).fetchone()
    con.close()
    if not admin or not admin['active'] or not verify_password(data.password, admin['password_hash']):
        login_fails[client].append(time.time())
        raise HTTPException(401, 'Benutzername oder Passwort falsch')
    login_fails.pop(client, None)
    token, csrf = new_session(data.username)
    response.set_cookie(COOKIE, token, max_age=SESSION_TTL, secure=True, httponly=True, samesite='strict', path='/')
    return {'username': data.username, 'role': admin['role'], 'csrf': csrf}

@app.get('/api/me')
def me(request: Request):
    return get_session(request, check_csrf=False)

@app.post('/api/logout')
def logout(request: Request, response: Response, session=Depends(require_session)):
    cookie = request.cookies.get(COOKIE, '')
    con = connect()
    con.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(cookie.encode()).hexdigest(),))
    con.commit()
    con.close()
    response.delete_cookie(COOKIE, path='/')
    return {'ok': True}


def get_rows(table: str):
    if table not in ('hosts','streams','certificates','certificate_jobs','audit'):
        raise ValueError('Tabelle unbekannt')
    con = connect()
    if table == 'audit':
        rows = asdicts(con.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 50'))
    else:
        rows = asdicts(con.execute(f'SELECT * FROM {table} ORDER BY created_at DESC, id DESC'))
    con.close()
    return rows

async def trigger_apply():
    DEPLOY.mkdir(parents=True, exist_ok=True)
    rid = str(uuid.uuid4())
    staged = DEPLOY / ('request-' + rid + '.tmp')
    staged.write_text(json.dumps({'id': rid, 'time': datetime.now(timezone.utc).isoformat()}), encoding='utf-8')
    os.replace(staged, DEPLOY / 'request.json')
    # A durable marker activates the systemd PathExistsGlob watcher.
    # The root worker removes only markers already present when it started.
    (DEPLOY / ('pending-' + rid + '.json')).write_text(rid, encoding='ascii')
    return {'requested': True, 'request_id': rid, 'state': 'dry-run (RPMGR_DEV=1)' if DEV else 'queued'}

async def transactional_write(actor, action, description, fn, deploy=True):
    async with change_lock:
        con = connect()
        try:
            con.execute('BEGIN IMMEDIATE')
            result = fn(con)
            # Reject broken generated Nginx configuration BEFORE committing the database.
            # This is a structural check; root worker still validates with nginx -t.
            if deploy:
                from .engine import render_http, render_stream
                render_http(asdicts(con.execute('SELECT * FROM hosts')),
                            asdicts(con.execute('SELECT * FROM certificates')))
                render_stream(asdicts(con.execute('SELECT * FROM streams')))
            audit(con, actor, action, description)
            con.commit()
        except ValueError as exc:
            con.rollback()
            raise HTTPException(422, str(exc)[:350]) from exc
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()
        if deploy:
            try:
                apply = await trigger_apply()
            except OSError as exc:
                # Database is already committed: do not imply a rollback occurred.
                apply = {'requested': False, 'state': 'error', 'message': 'Deploy-Warteschlange nicht erreichbar: ' + str(exc)[:160]}
        else:
            apply = {'requested': False, 'state': 'unchanged'}
        return {'ok': True, 'result': result, 'deployment': apply}

def ensure_cert(con, cert_id, domain):
    if not cert_id:
        return
    c = con.execute('SELECT * FROM certificates WHERE id=?', (cert_id,)).fetchone()
    if not c or c['status'] != 'ready':
        raise HTTPException(422, f'Für {domain} ist das Zertifikat nicht vorhanden oder nicht aktiv')
    if not cert_matches_domain(c['domain'], domain):
        raise HTTPException(422, 'Zertifikat passt nicht zur Domain')

@app.get('/api/hosts')
def hosts(session=Depends(require_session)):
    return get_rows('hosts')

@app.post('/api/hosts')
async def add_host(payload: HostInput, session=Depends(require_editor)):
    uid = uuid.uuid4().hex[:16]
    def task(con):
        if con.execute('SELECT 1 FROM hosts WHERE domain=?', (payload.domain,)).fetchone():
            raise HTTPException(409, 'Domain existiert bereits')
        ensure_cert(con, payload.certificate_id, payload.domain)
        con.execute('''INSERT INTO hosts(id,domain,upstream_scheme,upstream_host,upstream_port,upstream_tls_name,
                     websocket,force_https,certificate_id,category,upstream_host_header,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (uid, payload.domain, payload.upstream_scheme, payload.upstream_host, payload.upstream_port,
                     payload.upstream_tls_name, int(payload.websocket), int(payload.force_https), payload.certificate_id, payload.category, payload.upstream_host_header, int(payload.enabled)))
        return uid
    return await transactional_write(session['username'], 'host.create', payload.domain, task)

@app.put('/api/hosts/{uid}')
async def update_host(uid: str, payload: HostInput, session=Depends(require_editor)):
    def task(con):
        if not con.execute('SELECT 1 FROM hosts WHERE id=?', (uid,)).fetchone():
            raise HTTPException(404, 'Domain wurde nicht gefunden')
        if con.execute('SELECT 1 FROM hosts WHERE domain=? AND id<>?', (payload.domain, uid)).fetchone():
            raise HTTPException(409, 'Domain existiert bereits')
        ensure_cert(con, payload.certificate_id, payload.domain)
        con.execute('''UPDATE hosts SET domain=?,upstream_scheme=?,upstream_host=?,upstream_port=?,upstream_tls_name=?,
                     websocket=?,force_https=?,certificate_id=?,category=?,upstream_host_header=?,enabled=? WHERE id=?''',
                    (payload.domain, payload.upstream_scheme, payload.upstream_host, payload.upstream_port,
                     payload.upstream_tls_name, int(payload.websocket), int(payload.force_https), payload.certificate_id, payload.category, payload.upstream_host_header, int(payload.enabled), uid))
        return uid
    return await transactional_write(session['username'], 'host.update', payload.domain, task)

@app.delete('/api/hosts/{uid}')
async def delete_host(uid: str, session=Depends(require_editor)):
    def task(con):
        cur = con.execute('DELETE FROM hosts WHERE id=?', (uid,))
        if cur.rowcount == 0:
            raise HTTPException(404, 'Domain wurde nicht gefunden')
        return uid
    return await transactional_write(session['username'], 'host.delete', uid, task)

@app.get('/api/hosts/{uid}/diagnostics')
async def host_diagnostics(uid: str, session=Depends(require_session)):
    # Use the host ID instead of a user-supplied URL to prevent arbitrary scanning.
    con = connect()
    try:
        item = con.execute('SELECT * FROM hosts WHERE id=?', (uid,)).fetchone()
    finally:
        con.close()
    if item is None:
        raise HTTPException(404, 'Domain wurde nicht gefunden')
    try:
        return await asyncio.wait_for(asyncio.to_thread(diagnose_route, dict(item)), timeout=18)
    except asyncio.TimeoutError:
        raise HTTPException(504, 'Domain-Diagnose hat das Zeitlimit ueberschritten')

@app.get('/api/streams')
def streams(session=Depends(require_session)):
    return get_rows('streams')

@app.post('/api/streams')
async def add_stream(payload: StreamInput, session=Depends(require_editor)):
    uid = uuid.uuid4().hex[:16]
    def task(con):
        if payload.protocol == 'tcp' and payload.listen_port in (80,443,18081,9443):
            raise HTTPException(422, 'TCP-Port ist für Reverse Proxy, Status oder Admin-Panel reserviert')
        if con.execute('SELECT 1 FROM streams WHERE protocol=? AND listen_port=?', (payload.protocol,payload.listen_port)).fetchone():
            raise HTTPException(409, 'Dieser Port ist bereits vergeben')
        con.execute('''INSERT INTO streams(id,label,protocol,listen_port,target_host,target_port,timeout_seconds,enabled)
                       VALUES(?,?,?,?,?,?,?,?)''',
                    (uid,payload.label,payload.protocol,payload.listen_port,payload.target_host,payload.target_port,
                     payload.timeout_seconds,int(payload.enabled)))
        return uid
    return await transactional_write(session['username'], 'stream.create', f'{payload.listen_port}/{payload.protocol}', task)

@app.put('/api/streams/{uid}')
async def update_stream(uid: str, payload: StreamInput, session=Depends(require_editor)):
    def task(con):
        if not con.execute('SELECT 1 FROM streams WHERE id=?',(uid,)).fetchone():
            raise HTTPException(404, 'Portregel wurde nicht gefunden')
        if payload.protocol == 'tcp' and payload.listen_port in (80,443,18081,9443):
            raise HTTPException(422, 'TCP-Port ist für Reverse Proxy, Status oder Admin-Panel reserviert')
        if con.execute('SELECT 1 FROM streams WHERE protocol=? AND listen_port=? AND id<>?',
                       (payload.protocol,payload.listen_port,uid)).fetchone():
            raise HTTPException(409, 'Dieser Port ist bereits vergeben')
        con.execute('''UPDATE streams SET label=?,protocol=?,listen_port=?,target_host=?,target_port=?,
                       timeout_seconds=?,enabled=? WHERE id=?''',
                    (payload.label,payload.protocol,payload.listen_port,payload.target_host,payload.target_port,
                     payload.timeout_seconds,int(payload.enabled),uid))
        return uid
    return await transactional_write(session['username'], 'stream.update', f'{payload.listen_port}/{payload.protocol}', task)

@app.delete('/api/streams/{uid}')
async def delete_stream(uid: str, session=Depends(require_editor)):
    def task(con):
        cur = con.execute('DELETE FROM streams WHERE id=?', (uid,))
        if not cur.rowcount:
            raise HTTPException(404,'Portregel nicht gefunden')
        return uid
    return await transactional_write(session['username'],'stream.delete',uid,task)

@app.get('/api/certificates')
def certificates(session=Depends(require_session)):
    return get_rows('certificates')

@app.get('/api/certificates/jobs')
def certificates_jobs(session=Depends(require_session)):
    return get_rows('certificate_jobs')

@app.post('/api/certificates/issue')
async def issue_certificate(data: CertIssueInput, session=Depends(require_editor)):
    uid, job_id = uuid.uuid4().hex[:16], uuid.uuid4().hex[:16]
    def task(con):
        if not con.execute('SELECT 1 FROM hosts WHERE domain=? AND enabled=1', (data.domain,)).fetchone():
            raise HTTPException(422, 'Bitte zuerst einen aktiven HTTP-Proxy für diese Domain anlegen')
        if con.execute("SELECT 1 FROM certificates WHERE domain=? AND kind='acme' AND status IN ('ready','pending')",(data.domain,)).fetchone():
            raise HTTPException(409, 'Für diese Domain existiert bereits ein ACME-Zertifikat')
        con.execute('INSERT INTO certificates(id,label,domain,kind,status) VALUES(?,?,?,?,?)',
                    (uid, 'Let\'s Encrypt ' + data.domain, data.domain, 'acme','pending'))
        con.execute('INSERT INTO certificate_jobs(id,cert_id,domain,email,status) VALUES(?,?,?,?,?)',
                    (job_id,uid,data.domain,data.email,'pending'))
        return {'certificate_id':uid,'job_id':job_id}
    return await transactional_write(session['username'],'certificate.issue',data.domain,task)

def validate_manual_pem(domain, fullchain, private_key):
    with tempfile.TemporaryDirectory() as td:
        cert_file, key_file = Path(td)/'fullchain.pem',Path(td)/'privkey.pem'
        cert_file.write_text(fullchain)
        key_file.write_text(private_key)
        os.chmod(key_file,0o600)
        checkhost = 'example-check.' + domain[2:] if domain.startswith('*.') else domain
        commands = [
            ['openssl','x509','-in',str(cert_file),'-noout','-checkhost',checkhost],
            ['openssl','x509','-in',str(cert_file),'-noout','-checkend','0'],
            ['openssl','pkey','-in',str(key_file),'-noout'],
        ]
        messages = ('Zertifikat passt nicht zur Domain', 'Zertifikat ist abgelaufen', 'Privater Schlüssel ist ungültig')
        for command, message in zip(commands, messages):
            try:
                proc = subprocess.run(command,capture_output=True,text=True,timeout=12)
            except (OSError, subprocess.TimeoutExpired):
                raise HTTPException(422, 'Zertifikatsprüfung konnte nicht ausgeführt werden')
            if proc.returncode:
                raise HTTPException(422, message)
        try:
            pubcert = subprocess.run(['openssl','x509','-in',str(cert_file),'-pubkey','-noout'], capture_output=True,check=True,timeout=12).stdout
            pubkey = subprocess.run(['openssl','pkey','-in',str(key_file),'-pubout'], capture_output=True,check=True,timeout=12).stdout
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise HTTPException(422, 'Zertifikat und Schlüssel konnten nicht geprüft werden')
        if pubcert.strip()!=pubkey.strip():
            raise HTTPException(422,'Zertifikat und privater Schlüssel gehören nicht zusammen')
        expiry = subprocess.run(['openssl','x509','-in',str(cert_file),'-noout','-enddate'],capture_output=True,text=True,check=True).stdout.strip()
        from datetime import datetime
        expires = datetime.strptime(expiry.split('=',1)[1],'%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc).isoformat()
        return expires

@app.post('/api/certificates/import')
async def import_certificate(data: CertImportInput, session=Depends(require_editor)):
    expiry = await asyncio.to_thread(validate_manual_pem,data.domain,data.fullchain_pem,data.private_key_pem)
    uid = uuid.uuid4().hex[:16]
    folder = CERTS / uid
    folder.mkdir(parents=True, mode=0o700, exist_ok=False)
    cert_file, key_file = folder/'fullchain.pem',folder/'privkey.pem'
    try:
        for path, content, mode in ((cert_file,data.fullchain_pem,0o644),(key_file,data.private_key_pem,0o600)):
            with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode),'w') as fp:
                fp.write(content)
            os.chmod(path,mode)
        def task(con):
            con.execute('''INSERT INTO certificates(id,label,domain,kind,status,fullchain_path,privkey_path,expires_at)
                           VALUES(?,?,?,?,?,?,?,?)''',
                        (uid,data.label,data.domain,'manual','ready',str(cert_file),str(key_file),expiry))
            return uid
        return await transactional_write(session['username'],'certificate.import',data.domain,task)
    except Exception:
        shutil.rmtree(folder,ignore_errors=True)
        raise

@app.delete('/api/certificates/{uid}')
async def delete_certificate(uid: str, session=Depends(require_editor)):
    def task(con):
        if con.execute('SELECT 1 FROM hosts WHERE certificate_id=?',(uid,)).fetchone():
            raise HTTPException(409, 'Zertifikat ist noch einer Domain zugewiesen')
        row=con.execute('SELECT kind FROM certificates WHERE id=?',(uid,)).fetchone()
        if not row:
            raise HTTPException(404,'Zertifikat nicht gefunden')
        con.execute('DELETE FROM certificates WHERE id=?',(uid,))
        return uid
    result = await transactional_write(session['username'],'certificate.delete',uid,task)
    # Intentionally retain certificate files; root-only backup/cleanup policy avoids accidental key loss.
    return result

@app.post('/api/deploy')
async def deploy(session=Depends(require_editor)):
    return {'ok':True,'deployment':await trigger_apply()}

@app.get('/api/deploy')
def deployment(session=Depends(require_session)):
    file=DEPLOY/'status.json'
    req=DEPLOY/'request.json'
    try:
        status=json.loads(file.read_text()) if file.exists() else None
        request=json.loads(req.read_text()) if req.exists() else None
        if status and request and status.get('id') != request.get('id'):
            return {'state':'pending','status':status,'request_id':request.get('id')}
        return {'state':'applied' if status and status.get('ok') else 'error', 'status':status,'request_id':request.get('id')}
    except (OSError,ValueError) as exc:
        return {'state':'error','status':{'message':str(exc)}}

@app.get('/api/summary')
def summary(session=Depends(require_session)):
    con=connect()
    active_hosts=con.execute('SELECT COUNT(*) FROM hosts WHERE enabled=1').fetchone()[0]
    total_hosts=con.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
    active_streams=con.execute('SELECT COUNT(*) FROM streams WHERE enabled=1').fetchone()[0]
    total_streams=con.execute('SELECT COUNT(*) FROM streams').fetchone()[0]
    expiring=con.execute("SELECT COUNT(*) FROM certificates WHERE status='ready' AND expires_at IS NOT NULL AND date(expires_at) <= date('now','+30 days')").fetchone()[0]
    con.close()
    vm=psutil.virtual_memory()
    net=psutil.net_io_counters()
    connections=None
    try:
        import urllib.request
        with urllib.request.urlopen('http://127.0.0.1:18081/nginx_status',timeout=0.6) as r:
            content=r.read(1000).decode()
            import re
            match=re.search(r'Active connections:\s*(\d+)',content)
            connections=int(match.group(1)) if match else None
    except Exception:
        pass
    return {'hosts_active':active_hosts,'hosts_total':total_hosts,'streams_active':active_streams,
            'streams_total':total_streams,'certs_expiring_30d':expiring,
            'cpu_percent':psutil.cpu_percent(interval=0.12),'ram_percent':vm.percent,
            'ram_total_mb':round(vm.total/1048576), 'ram_used_mb':round(vm.used/1048576),
            'bytes_sent':net.bytes_sent,'bytes_recv':net.bytes_recv,'connections':connections}

@app.get('/api/healthchecks')
async def healthchecks(session=Depends(require_session)):
    from .diagnostics import probe_upstream
    con=connect()
    try:
        hosts=asdicts(con.execute('SELECT * FROM hosts WHERE enabled=1 ORDER BY domain'))
        streams=asdicts(con.execute('SELECT * FROM streams WHERE enabled=1 ORDER BY label'))
    finally:
        con.close()
    semaphore=asyncio.Semaphore(8)
    async def check_host(host):
        async with semaphore:
            result=await asyncio.to_thread(probe_upstream,host)
            return {'id':host['id'],'name':host['domain'],'type':'https' if host['upstream_scheme']=='https' else 'http',
                    'status':result['state'],'code':result.get('code'),'hint':result.get('message','')}
    async def check_stream(s):
        if s['protocol']=='udp':
            return {'id':s['id'],'name':s['label'],'type':'udp','status':'not_tested','hint':'UDP kann nicht per TCP geprueft werden'}
        async with semaphore:
            try:
                reader,writer=await asyncio.wait_for(asyncio.open_connection(s['target_host'],s['target_port']),timeout=3)
                writer.close();await writer.wait_closed()
                status='online'
            except Exception:
                status='offline'
            return {'id':s['id'],'name':s['label'],'type':'tcp','status':status}
    return await asyncio.gather(*([check_host(h) for h in hosts]+[check_stream(s) for s in streams]))

@app.get('/api/logs')
def logs(kind: str='error', lines: int=Query(ge=1,le=200,default=80),session=Depends(require_session)):
    paths={'error':'/var/log/nginx/error.log','access':'/var/log/nginx/access.log'}
    if kind not in paths:
        raise HTTPException(400,'Logtyp nicht unterstützt')
    try:
        with open(paths[kind],encoding='utf-8',errors='replace') as fd:
            selected=list(deque(fd,maxlen=lines))
        return {'kind':kind,'lines':selected}
    except (OSError,PermissionError) as exc:
        return {'kind':kind,'lines':[],'error':'Logdatei nicht lesbar: '+str(exc)}

@app.get('/api/audit')
def audit_entries(session=Depends(require_session)):
    return get_rows('audit')

@app.get('/api/plugins')
def plugins(session=Depends(require_session)):
    result=[]
    if PLUGINS.exists():
        for path in sorted(PLUGINS.glob('*/manifest.json')):
            try:
                if path.stat().st_size > 16000:
                    continue
                d=json.loads(path.read_text(encoding='utf-8'))
                if d.get('id')==path.parent.name:
                    result.append({k:str(d.get(k,''))[:140] for k in ('id','name','version','description')})
            except (OSError,ValueError):
                pass
    return {'installed':result,'install_available':False,'update_available':False}

@app.get('/api/export')
def export_config(session=Depends(require_session)):
    # No credentials or private keys are exported through the browser.
    return {'format':'rpmgr-config-v1','created':datetime.now(timezone.utc).isoformat(),
            'hosts':get_rows('hosts'),'streams':get_rows('streams'),
            'certificates':[{'label':c['label'],'domain':c['domain'],'kind':c['kind'],
                            'expires_at':c['expires_at']} for c in get_rows('certificates')],
            'note':'Metadatenexport ohne private Schluessel. Vollbackup und Restore ueber root-CLI.'}

# Additional administrator, bulk-domain and certificate endpoints.
from .features import router as features_router
app.include_router(features_router)

# LAN utilities, Web SSH and scanners (role protected).
from .utilities import router as utilities_router
app.include_router(utilities_router)


# Editable fallback page, persisted via SQLite. Administrative changes require CSRF.
from pydantic import Field, field_validator
import re

class FallbackPageInput(BaseModel):
    html: str = Field(min_length=20, max_length=65000)

    @field_validator('html')
    @classmethod
    def validate_markup(cls, value: str):
        if '\x00' in value or not re.search(r'<\s*html\b', value, re.I):
            raise ValueError('Eine vollstaendige HTML-Seite mit <html> ist erforderlich')
        if re.search(r'<\s*(?:script|iframe|object|embed|form|base)\b', value, re.I):
            raise ValueError('Skripte, Formulare, eingebettete Inhalte und base sind nicht erlaubt')
        if re.search(r'\bon[a-z]+\s*=', value, re.I):
            raise ValueError('HTML-Eventhandler sind nicht erlaubt')
        if re.search(r'\b(?:javascript|vbscript)\s*:', value, re.I):
            raise ValueError('Aktive URL-Schemata sind nicht erlaubt')
        return value

@app.get('/api/default-page')
def get_default_page(session=Depends(require_session)):
    con = connect()
    try:
        row = con.execute('SELECT fallback_html,updated_at FROM site_settings WHERE id=1').fetchone()
    finally:
        con.close()
    if row:
        return {'html':row['fallback_html'], 'updated_at':row['updated_at'], 'customized':True}
    return {'html':(Path(__file__).resolve().parent / 'default_page.html').read_text(encoding='utf-8'),
            'updated_at':None, 'customized':False}

@app.put('/api/default-page')
async def update_default_page(payload: FallbackPageInput, session=Depends(require_admin)):
    def save(con):
        con.execute("""INSERT INTO site_settings(id,fallback_html,updated_at)
            VALUES(1,?,CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET fallback_html=excluded.fallback_html,updated_at=CURRENT_TIMESTAMP""",
            (payload.html,))
        return {'saved':True,'bytes':len(payload.html.encode('utf-8'))}
    return await transactional_write(session['username'], 'default_page.update',
                                     'Standard-Fehlerseite geaendert', save)

@app.post('/api/default-page/reset')
async def reset_default_page(session=Depends(require_admin)):
    def reset(con):
        con.execute('DELETE FROM site_settings WHERE id=1')
        return {'reset':True}
    return await transactional_write(session['username'], 'default_page.reset',
                                     'Standard-Fehlerseite zurueckgesetzt', reset)
