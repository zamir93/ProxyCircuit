# ProxyCircuit v0.2.3 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Root-only oneshot worker: certificate requests, nginx -t, atomic rollback, reload.

Never expose this module as a web endpoint or execute user-provided commands.
"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from .db import connect, init_db
from .settings import DEPLOY, NGINX_HTTP, NGINX_STREAM, CERTS, FALLBACK_DIR
from .engine import render_http, render_stream
from .validation import CertIssueInput


def cmd(args, timeout=40):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'Zeitüberschreitung bei {args[0]} ({timeout} s)') from exc

def write_atomic(path: Path, contents: str, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.rpmgr-', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def cert_expiry(path: str) -> str | None:
    p = cmd(['openssl', 'x509', '-in', path, '-noout', '-enddate'])
    if p.returncode:
        return None
    from datetime import datetime
    try:
        return datetime.strptime(p.stdout.strip().split('=', 1)[1], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc).isoformat()
    except (IndexError, ValueError):
        return None

def issue_jobs(con):
    jobs = [dict(row) for row in con.execute("SELECT * FROM certificate_jobs WHERE status='pending' ORDER BY created_at")]
    failures = []
    for job in jobs:
        try:
            data = CertIssueInput(domain=job['domain'], email=job['email'])
            cert_name = 'rpmgr-' + job['cert_id']
            # HTTP-01 requires public DNS and inbound TCP/80 on THIS proxy.
            # Renewal is explicit; certbot force-renewal is never used by background monitoring.
            command = ['certbot', 'certonly', '--webroot', '-w', '/var/www/rpmgr-acme',
                       '-d', data.domain, '--cert-name', cert_name,
                       '--agree-tos', '--non-interactive', '--no-eff-email',
                       '--email', data.email]
            if job.get('operation') == 'renew':
                command.append('--force-renewal')
            result = cmd(command, timeout=240)
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout)[-1100:] or 'Certbot fehlgeschlagen')
            fullchain = f'/etc/letsencrypt/live/{cert_name}/fullchain.pem'
            key = f'/etc/letsencrypt/live/{cert_name}/privkey.pem'
            if not Path(fullchain).exists() or not Path(key).exists():
                raise RuntimeError('Zertifikat wurde ausgestellt, ist jedoch nicht auffindbar')
            con.execute('UPDATE certificates SET status=?,fullchain_path=?,privkey_path=?,expires_at=?,error=? WHERE id=?',
                        ('ready', fullchain, key, cert_expiry(fullchain), '', job['cert_id']))
            con.execute('UPDATE certificate_jobs SET status=?,error=? WHERE id=?', ('done', '', job['id']))
        except (ValueError, RuntimeError, FileNotFoundError) as exc:
            message = str(exc)[:1300]
            failures.append(f'{job["domain"]}: {message}')
            # A failed renewal must NOT invalidate the still-working existing certificate.
            if job.get('operation') != 'renew':
                con.execute('UPDATE certificates SET status=?,error=? WHERE id=?', ('error', message, job['cert_id']))
            else:
                con.execute('UPDATE certificates SET error=? WHERE id=?', (message, job['cert_id']))
            con.execute('UPDATE certificate_jobs SET status=?,error=? WHERE id=?', ('error', message, job['id']))
        con.commit()
    return failures

def validate_cert_paths(certs):
    for c in certs:
        if c['status'] != 'ready':
            continue
        if c['kind'] not in ('manual', 'acme'):
            raise ValueError('Ungültiger Zertifikatstyp')
        for col in ('fullchain_path', 'privkey_path'):
            s = c[col]
            if not s or not os.path.isabs(s) or not re.fullmatch(r'[a-zA-Z0-9/_\.\-]+', s):
                raise ValueError('Ungültiger Zertifikatspfad')
            allowed = '/var/lib/rpmgr/certs/' if c['kind'] == 'manual' else '/etc/letsencrypt/live/rpmgr-'
            if not s.startswith(allowed):
                raise ValueError('Zertifikatspfad liegt außerhalb des erlaubten Verzeichnisses')
            if not Path(s).is_file():
                raise ValueError(f'Zertifikatsdatei fehlt: {s}')

def refresh_expiry(con):
    rows = con.execute("SELECT id,fullchain_path FROM certificates WHERE status='ready'").fetchall()
    for cert in rows:
        if cert['fullchain_path'] and Path(cert['fullchain_path']).is_file():
            expiry = cert_expiry(cert['fullchain_path'])
            con.execute('UPDATE certificates SET expires_at=? WHERE id=?', (expiry, cert['id']))
    con.commit()

def cleanup_unused_certificates(con):
    """Run only after an nginx -t + successful reload; never remove referenced keys."""
    base = CERTS.resolve()
    for row in list(con.execute('SELECT * FROM certificate_cleanup')):
        cid = row['id']
        # Even after a migration/reimport, never destroy a certificate that is in use.
        if con.execute('SELECT 1 FROM certificates WHERE id=?', (cid,)).fetchone():
            con.execute('DELETE FROM certificate_cleanup WHERE id=?', (cid,))
            continue
        if con.execute('SELECT 1 FROM hosts WHERE certificate_id=?', (cid,)).fetchone():
            continue
        if row['kind'] == 'manual':
            expected = base / cid
            fullchain = Path(row['fullchain_path'] or '')
            privkey = Path(row['privkey_path'] or '')
            # Only delete within the one, exactly named, managed certificate folder.
            if fullchain.parent == expected and privkey.parent == expected and expected.is_dir() and not expected.is_symlink():
                for f in (fullchain, privkey):
                    if f.is_file() and not f.is_symlink():
                        f.unlink()
                if not list(expected.iterdir()):
                    expected.rmdir()
        elif row['kind'] == 'acme':
            name = 'rpmgr-' + cid
            result = cmd(['certbot', 'delete', '--cert-name', name, '--non-interactive'], timeout=40)
            if result.returncode:
                continue
        con.execute('DELETE FROM certificate_cleanup WHERE id=?', (cid,))
    con.commit()


def reload_nginx():
    """Reload using the active supervisor; Debian uses systemd, Docker uses nginx."""
    if os.environ.get('RPMGR_RUNTIME') == 'docker':
        return cmd(['nginx', '-s', 'reload'])
    return cmd(['systemctl', 'reload', 'nginx'])


def apply_config():
    con = connect()
    job_errors = issue_jobs(con)
    hosts = [dict(r) for r in con.execute('SELECT * FROM hosts')]
    streams = [dict(r) for r in con.execute('SELECT * FROM streams')]
    certs = [dict(r) for r in con.execute('SELECT * FROM certificates')]
    # Unused legacy PEM entries must not block an unrelated Nginx update.
    used_cert_ids = {h['certificate_id'] for h in hosts if h['enabled'] and h['certificate_id']}
    validate_cert_paths([c for c in certs if c['id'] in used_cert_ids])
    fallback_row = con.execute('SELECT fallback_html FROM site_settings WHERE id=1').fetchone()
    if fallback_row is None:
        fallback_html = (Path(__file__).resolve().parent / 'default_page.html').read_text(encoding='utf-8')
    else:
        fallback_html = fallback_row['fallback_html']
    if not fallback_html or len(fallback_html.encode('utf-8')) > 100000:
        raise RuntimeError('Standardseite ist leer oder zu gross')
    # Root worker writes the public HTML; the unprivileged web admin writes only SQLite.
    FALLBACK_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(FALLBACK_DIR, 0o755)
    write_atomic(FALLBACK_DIR / '__proxycircuit_error_page.html', fallback_html, mode=0o644)
    http = render_http(hosts, certs)
    stream = render_stream(streams)
    before = {}
    for path in (NGINX_HTTP, NGINX_STREAM):
        before[str(path)] = path.read_bytes() if path.exists() else None
    try:
        write_atomic(NGINX_HTTP, http)
        write_atomic(NGINX_STREAM, stream)
        test = cmd(['nginx', '-t'])
        if test.returncode:
            raise RuntimeError('Nginx-Konfiguration ungültig: ' + (test.stderr or test.stdout)[-1600:])
        reload_result = reload_nginx()
        if reload_result.returncode:
            raise RuntimeError('Nginx-Neuladen fehlgeschlagen: ' + (reload_result.stderr or reload_result.stdout)[-1200:])
    except Exception:
        for path in (NGINX_HTTP, NGINX_STREAM):
            contents = before[str(path)]
            if contents is None:
                path.unlink(missing_ok=True)
            else:
                write_atomic(path, contents.decode('utf-8'))
        cmd(['nginx', '-t'])
        reload_nginx()
        raise
    refresh_expiry(con)
    try:
        cleanup_unused_certificates(con)
    except (OSError, RuntimeError) as exc:
        job_errors.append("Zertifikatsbereinigung ausstehend: " + str(exc)[:180])
    con.close()
    return job_errors

def main():
    init_db()
    req_path = DEPLOY / 'request.json'
    request = json.loads(req_path.read_text()) if req_path.exists() else {'id': 'manual'}
    present_markers = list(DEPLOY.glob('pending-*.json'))
    status = {'id': request['id'], 'time': datetime.now(timezone.utc).isoformat(), 'ok': False, 'message': ''}
    try:
        job_errors = apply_config()
        status['ok'] = True
        status['message'] = 'Nginx-Konfiguration erfolgreich geprüft und aktiviert'
        if job_errors:
            status['message'] += '; ACME-Fehler: ' + ' | '.join(job_errors)[:1000]
    except Exception as exc:
        status['message'] = str(exc)[:2000]
    write_atomic(DEPLOY / 'status.json', json.dumps(status, ensure_ascii=False, indent=2), 0o644)
    # Markers created during this run remain and trigger another apply.
    for marker in present_markers:
        marker.unlink(missing_ok=True)
    print(status['message'])
    return 0 if status['ok'] else 1

if __name__ == '__main__':
    sys.exit(main())
