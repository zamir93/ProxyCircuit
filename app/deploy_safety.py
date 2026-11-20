# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Staged Nginx syntax validation, active socket verification and version history.

No shell execution and no stopping unrelated processes. Root-only snapshots have
0700 permissions, and private key bytes are never exported to the Web UI.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .port_binding import live_sockets, normalize_bind_ip, RESERVED_TCP
from .settings import DEPLOY

VERSIONS = DEPLOY / 'versions'
ERROR_LOG = Path('/var/log/nginx/error.log')
BIND_ERRORS = re.compile(r'bind\(\).*failed|still could not bind|address already in use|\[emerg\].*(?:bind|listen|socket)', re.I)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def stage_test(http: str, stream: str, runner=subprocess.run):
    """Test generated configuration before overwriting live include files.

    Tests standalone syntax plus certificate file readability; the complete
    production nginx.conf is also checked after installing the staged includes.
    """
    with tempfile.TemporaryDirectory(prefix='pc-nginx-stage-', dir=str(DEPLOY)) as d:
        path = Path(d)
        (path/'http.conf').write_text(http, encoding='utf-8')
        (path/'stream.conf').write_text(stream, encoding='utf-8')
        module = Path('/usr/lib/nginx/modules/ngx_stream_module.so')
        module_line = f'load_module {module};\n' if module.is_file() else ''
        has_stream_module = module.is_file()
        if not has_stream_module:
            # Some systems compile NGINX stream into the binary.
            version = runner(['nginx','-V'],capture_output=True,text=True,timeout=10,check=False)
            flags = version.stderr + version.stdout
            has_stream_module = '--with-stream ' in flags or '--with-stream\n' in flags
        if not has_stream_module and re.search(r'\bserver\s*\{',stream):
            raise RuntimeError('NGINX-Stream-Modul fehlt; bitte libnginx-mod-stream installieren')
        conf = (module_line + 'worker_processes 1;\n'
                + f'pid {path}/nginx.pid;\n'
                + f'error_log {path}/nginx-error.log;\n'
                + 'events { worker_connections 256; }\n'
                + f'http {{ access_log off; include /etc/nginx/mime.types; include {path}/http.conf; }}\n'
                + (f'include {path}/stream.conf;\n' if has_stream_module else ''))
        (path/'nginx.conf').write_text(conf, encoding='utf-8')
        run = runner(['nginx', '-t', '-c', str(path/'nginx.conf'), '-p', str(path)],
                     capture_output=True, text=True, timeout=20, check=False)
        if run.returncode:
            raise RuntimeError('Isolierter NGINX-Konfigurationstest fehlgeschlagen: ' +
                               (run.stderr or run.stdout)[-1300:])
        return {'syntax_ok': True, 'stream_syntax_checked':has_stream_module, 'http_sha256': sha256(http.encode()),
                'stream_sha256': sha256(stream.encode())}


def create_version(before: dict, *, request_id=None):
    VERSIONS.mkdir(parents=True, exist_ok=True)
    os.chmod(VERSIONS, 0o700)
    vid = (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12])
    folder = VERSIONS / vid
    folder.mkdir(mode=0o700)
    for key in ('http', 'stream', 'fallback'):
        raw = before.get(key)
        if raw is not None:
            path = folder / f'{key}.bak'
            path.write_bytes(raw)
            os.chmod(path, 0o600)
    (folder/'meta.json').write_text(json.dumps({'id':vid,'request_id':request_id,
        'created_at':datetime.now(timezone.utc).isoformat(),
        'sha256':{k:sha256(v) for k,v in before.items() if v is not None}},indent=2),encoding='utf-8')
    os.chmod(folder/'meta.json',0o600)
    return vid


def get_version(vid):
    if not re.fullmatch(r'\d{8}T\d{6}Z-[a-f0-9]{12}', vid):
        raise ValueError('Ungueltige Konfigurationsversions-ID')
    folder = VERSIONS / vid
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError('Konfigurationsversion nicht gefunden')
    return {name:(folder/f'{name}.bak').read_bytes() if (folder/f'{name}.bak').is_file() else None
            for name in ('http','stream','fallback')}


def errors_since(offset, log_path=ERROR_LOG):
    try:
        with open(log_path,'rb') as fd:
            if os.fstat(fd.fileno()).st_size < offset:
                offset = 0
            fd.seek(offset)
            tail = fd.read(262144).decode('utf-8','replace')
    except OSError:
        return ''
    lines = [line.strip() for line in tail.splitlines() if BIND_ERRORS.search(line)]
    return '\n'.join(lines[-8:])[:1400]


def log_offset(log_path=ERROR_LOG):
    try:
        return log_path.stat().st_size
    except OSError:
        return 0


def verify_listeners(streams, *, sockets=None, check_http=True, retries=5, delay=.25):
    """Verify exact active Nginx listener sockets, not merely nginx -t or reload exit code.

    If process attribution is unavailable, fail closed rather than claim a
    deployment was activated. UDP sockets are checked separately.
    """
    expected = []
    if check_http:
        expected += [('tcp', 80, '0.0.0.0'), ('tcp', 443, '0.0.0.0')]
    expected += [(r['protocol'], int(r['listen_port']), normalize_bind_ip(r.get('bind_ip')))
                 for r in streams if r.get('enabled', True)]
    if not expected:
        return []
    for attempt in range(retries):
        found = live_sockets() if sockets is None else sockets
        missing = []
        for proto, port, ip in expected:
            # An exact listener is required when using a concrete Bind-IP.
            # It is *not* sufficient that an old wildcard listener overlaps.
            match = any(entry['protocol']==proto and entry['port']==port and
                        entry['bind_ip']==ip and 'nginx' in entry['process'].lower()
                        for entry in found)
            if not match:
                missing.append(f'{proto.upper()} {ip}:{port}')
        if not missing:
            return []
        if sockets is not None:
            break
        if attempt < retries - 1:
            time.sleep(delay)
    return missing


def nginx_supervisor_running(*, runner=subprocess.run):
    if os.getenv('RPMGR_RUNTIME') == 'docker':
        # Executing as root inside the managed container.
        return any('nginx' in p.info['name'].lower() for p in __import__('psutil').process_iter(['name']) if p.info['name'])
    run = runner(['systemctl','is-active','--quiet','nginx'], capture_output=True,text=True,timeout=8,check=False)
    return run.returncode == 0


def nginx_worker_pids():
    """Capture worker process IDs to prove NGINX spawned a new generation."""
    import psutil
    found=set()
    for proc in psutil.process_iter(['pid','name','cmdline']):
        try:
            name=(proc.info.get('name') or '').lower()
            if 'nginx' not in name:
                continue
            arguments=' '.join(proc.info.get('cmdline') or []).lower()
            if 'worker process' in arguments:
                found.add(proc.info['pid'])
        except (psutil.AccessDenied,psutil.NoSuchProcess):
            continue
    return found


def post_reload_status(streams, *, offset=0, check_http=True, before_workers=None):
    if not nginx_supervisor_running():
        raise RuntimeError('NGINX-Hauptdienst ist nicht aktiv')
    if before_workers:
        # A supervisor may return 0 even though nginx workers kept the old
        # configuration. Wait briefly for at least one *new* worker generation.
        for attempt in range(9):
            if nginx_worker_pids() - before_workers:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('NGINX-Reload ohne neue Worker-Generation; Aktivierung nicht nachgewiesen')
    missing = verify_listeners(streams,check_http=check_http)
    log_errors = errors_since(offset)
    if missing:
        raise RuntimeError('NGINX hat angeforderte Listener nicht geoeffnet: '+', '.join(missing)+
                           ((' | '+log_errors) if log_errors else ''))
    if log_errors:
        raise RuntimeError('NGINX-Fehlerprotokoll meldet Bind-Fehler nach Reload: '+log_errors)
    return True


def record_history(con, *, request_id, state, http, stream, message='', rollback_ok=None, previous='', elapsed_ms=0,
                   snapshot_id='', diff_excerpt=''):
    con.execute('''INSERT OR REPLACE INTO deploy_history
        (id,created_at,state,http_sha256,stream_sha256,message,rollback_ok,last_good_at,duration_ms,snapshot_id,diff_excerpt)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
        (request_id or uuid.uuid4().hex, datetime.now(timezone.utc).isoformat(), state,
         sha256(http.encode()),sha256(stream.encode()),message[:1300],
         None if rollback_ok is None else int(rollback_ok), previous or None,int(elapsed_ms),
         snapshot_id, diff_excerpt[:14000]))
    con.commit()


def safe_diff(before,after):
    """Human-readable config diff. No private keys; only generated directives."""
    import difflib
    left=(before or b'').decode('utf-8','replace').splitlines()
    right=after.splitlines()
    return '\n'.join(difflib.unified_diff(left,right,fromfile='vorher',tofile='nachher',lineterm=''))[:14000]
