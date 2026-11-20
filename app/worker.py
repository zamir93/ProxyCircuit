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
from .port_binding import assert_bindings
from .deploy_safety import (stage_test, create_version, log_offset,
                            post_reload_status, record_history, nginx_worker_pids,
                            safe_diff, get_version)


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


def apply_config(*, request_id='manual'):
    """Apply desired DB state without declaring success on a reload signal alone.

    Requested DB changes remain saved if an activation fails, while the last
    working NGINX include files are restored. No Postfix or other service is
    stopped and no public listener is preemptively bound by the worker.
    """
    import time
    begin=time.monotonic()
    con=connect()
    job_errors=[]
    http=stream=''
    last_good=''
    previous=None
    try:
        job_errors=issue_jobs(con)
        hosts=[dict(r) for r in con.execute('SELECT * FROM hosts')]
        streams=[dict(r) for r in con.execute('SELECT * FROM streams')]
        certs=[dict(r) for r in con.execute('SELECT * FROM certificates')]
        used_cert_ids={h['certificate_id'] for h in hosts if h['enabled'] and h['certificate_id']}
        validate_cert_paths([c for c in certs if c['id'] in used_cert_ids])
        page=con.execute('SELECT fallback_html FROM site_settings WHERE id=1').fetchone()
        fallback_html=(page['fallback_html'] if page else
                       (Path(__file__).resolve().parent/'default_page.html').read_text(encoding='utf-8'))
        if not fallback_html or len(fallback_html.encode('utf-8'))>100000:
            raise RuntimeError('Standardseite ist leer oder zu gross')
        http=render_http(hosts,certs)
        stream=render_stream(streams)
        # Only admin port, web, or transport listeners named in the target
        # configuration may be considered; foreign services always win.
        preflight=assert_bindings(streams)
        DEPLOY.mkdir(parents=True,exist_ok=True)
        stage_test(http,stream)
        old_status=DEPLOY/'status.json'
        try:
            last_good=json.loads(old_status.read_text()).get('activated_at','')
        except (OSError,ValueError):
            pass
        paths={'http':NGINX_HTTP, 'stream':NGINX_STREAM,
               'fallback':FALLBACK_DIR/'__proxycircuit_error_page.html'}
        before={key:p.read_bytes() if p.exists() else None for key,p in paths.items()}
        diff_excerpt=safe_diff(before['http'],http)+'\n--- STREAM ---\n'+safe_diff(before['stream'],stream)
        # Snapshot only after syntax validation, before any live file change.
        previous=create_version(before,request_id=request_id)
        offset=log_offset()
        before_workers=nginx_worker_pids()
        try:
            FALLBACK_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
            os.chmod(FALLBACK_DIR,0o755)
            write_atomic(paths['fallback'],fallback_html,mode=0o644)
            write_atomic(NGINX_HTTP,http)
            write_atomic(NGINX_STREAM,stream)
            test=cmd(['nginx','-t'])
            if test.returncode:
                detail=(test.stderr or test.stdout)[-1200:]
                if 'server_names_hash' in detail:
                    detail+=' | NGINX server_names_hash_max_size / server_names_hash_bucket_size im HTTP-Kontext pruefen; keine automatische Aenderung fremder NGINX-Dateien.'
                raise RuntimeError('Vollstaendiger NGINX-Konfigurationstest fehlgeschlagen: '+detail)
            reload_result=reload_nginx()
            if reload_result.returncode:
                raise RuntimeError('NGINX-Reload fehlgeschlagen: '+(reload_result.stderr or reload_result.stdout)[-1200:])
            # A successful command is NOT proof of a successful reload.
            post_reload_status(streams,offset=offset,before_workers=before_workers)
        except Exception as cause:
            rollback_errors=[]
            for key,path in paths.items():
                try:
                    original=before[key]
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        write_atomic(path,original.decode('utf-8'),mode=0o644)
                except (OSError,UnicodeError) as exc:
                    rollback_errors.append(f'{key}: {exc}')
            backup_test=cmd(['nginx','-t'])
            if backup_test.returncode:
                rollback_errors.append('Wiederhergestellte NGINX-Syntax ungueltig: '+(backup_test.stderr or backup_test.stdout)[-300:])
            else:
                backup_reload=reload_nginx()
                if backup_reload.returncode:
                    rollback_errors.append('Rollback-Reload fehlgeschlagen: '+(backup_reload.stderr or backup_reload.stdout)[-300:])
                # nginx -t and reload alone do not guarantee a restored runtime.
                try:
                    from .deploy_safety import nginx_supervisor_running
                    if not nginx_supervisor_running():
                        rollback_errors.append('NGINX nach Rollback nicht aktiv')
                except Exception as exc:
                    rollback_errors.append('NGINX-Rollbackstatus unklar: '+str(exc)[:120])
            rollback_ok=not rollback_errors
            elapsed=round((time.monotonic()-begin)*1000)
            message=str(cause)[:1100]+(' | Vorherige Konfiguration wiederhergestellt.' if rollback_ok
                       else ' | WARNUNG: Rollback unvollstaendig: '+'; '.join(rollback_errors)[:700])
            record_history(con,request_id=request_id,state='activation_failed',http=http,stream=stream,
                           message=message,rollback_ok=rollback_ok,previous=last_good,elapsed_ms=elapsed,
                           snapshot_id=previous,diff_excerpt=diff_excerpt)
            raise RuntimeError(message) from cause
        refresh_expiry(con)
        try:
            cleanup_unused_certificates(con)
        except (OSError,RuntimeError) as exc:
            job_errors.append('Zertifikatsbereinigung ausstehend: '+str(exc)[:180])
        elapsed=round((time.monotonic()-begin)*1000)
        record_history(con,request_id=request_id,state='active',http=http,stream=stream,
                       message='NGINX aktiv und erwartete Listener verifiziert',rollback_ok=None,
                       previous=last_good,elapsed_ms=elapsed,snapshot_id=previous,diff_excerpt=diff_excerpt)
        return {'warnings':preflight['warnings']+job_errors,
                'snapshot_id':previous, 'activated_at':datetime.now(timezone.utc).isoformat(),
                'http_sha256':__import__('hashlib').sha256(http.encode()).hexdigest(),
                'stream_sha256':__import__('hashlib').sha256(stream.encode()).hexdigest(),
                'duration_ms':elapsed}
    except Exception as exc:
        # If preflight fails BEFORE files were changed, log a failed attempt.
        if not previous:
            try:
                record_history(con,request_id=request_id,state='preflight_failed',
                               http=http,stream=stream,message=str(exc)[:1300],
                               rollback_ok=None,previous=last_good,
                               elapsed_ms=round((time.monotonic()-begin)*1000))
            except Exception:
                pass
        raise
    finally:
        con.close()


def restore_live_version(version_id, *, apply=False):
    """Root-only restoration of last NGINX files, not SQLite desired state.

    The caller must explicitly pass --apply. A second snapshot always preserves
    the configuration we are replacing so the operator can undo a restore.
    """
    from .port_binding import parse_managed_listeners
    from .deploy_safety import nginx_worker_pids, safe_diff
    snapshot=get_version(version_id)
    if snapshot['http'] is None or snapshot['stream'] is None:
        raise ValueError('Snapshot ohne vollstaendige NGINX-Include-Dateien')
    http=snapshot['http'].decode('utf-8')
    stream=snapshot['stream'].decode('utf-8')
    check=stage_test(http,stream)
    if not apply:
        return {'valid':True,'version':version_id,'note':'Keine Dateien veraendert'}
    paths={'http':NGINX_HTTP,'stream':NGINX_STREAM,'fallback':FALLBACK_DIR/'__proxycircuit_error_page.html'}
    current={key:p.read_bytes() if p.exists() else None for key,p in paths.items()}
    undo_id=create_version(current,request_id='restore-'+version_id)
    status={'restored':False,'undo_id':undo_id,'version':version_id}
    offset=log_offset()
    before_workers=nginx_worker_pids()
    try:
        for key,path in paths.items():
            content=snapshot[key]
            if content is None:
                path.unlink(missing_ok=True)
            else:
                write_atomic(path,content.decode('utf-8'))
        test=cmd(['nginx','-t'])
        if test.returncode:
            raise RuntimeError('NGINX-Syntax nach Wiederherstellung fehlgeschlagen: '+(test.stderr or test.stdout)[-500:])
        reload=reload_nginx()
        if reload.returncode:
            raise RuntimeError('NGINX-Reload fehlgeschlagen: '+(reload.stderr or reload.stdout)[-500:])
        specs=parse_managed_listeners(NGINX_STREAM)
        rows=[{'protocol':proto,'listen_port':port,'bind_ip':ip,'enabled':True} for proto,port,ip in specs]
        post_reload_status(rows,offset=offset,before_workers=before_workers)
        status['restored']=True
        status['note']='Nur live NGINX wiederhergestellt. Gespeicherte Datenbankregeln bleiben unveraendert.'
        return status
    except Exception as exc:
        for key,path in paths.items():
            prior=current[key]
            if prior is None:
                path.unlink(missing_ok=True)
            else:
                write_atomic(path,prior.decode('utf-8'))
        test=cmd(['nginx','-t'])
        if test.returncode or reload_nginx().returncode:
            raise RuntimeError('Wiederherstellung UND Ruecknahme fehlgeschlagen; manueller Eingriff erforderlich: '+str(exc)) from exc
        raise RuntimeError('Wiederherstellung fehlgeschlagen; Ausgangskonfiguration zurueckgeschrieben: '+str(exc)) from exc


def main():
    if len(sys.argv)>1:
        if os.geteuid()!=0:
            raise SystemExit('Nur root darf Live-Konfigurationen wiederherstellen')
        if len(sys.argv)==3 and sys.argv[1]=='--check-live-restore':
            print(json.dumps(restore_live_version(sys.argv[2],apply=False),ensure_ascii=False))
            return 0
        if len(sys.argv)==4 and sys.argv[1]=='--restore-live' and sys.argv[3]=='--apply':
            init_db()
            print(json.dumps(restore_live_version(sys.argv[2],apply=True),ensure_ascii=False))
            return 0
        raise SystemExit('Verwendung: --check-live-restore ID ODER --restore-live ID --apply')
    init_db()
    req_path=DEPLOY/'request.json'
    request=json.loads(req_path.read_text()) if req_path.exists() else {'id':'manual'}
    present_markers=list(DEPLOY.glob('pending-*.json'))
    status={'id':request['id'], 'time':datetime.now(timezone.utc).isoformat(),
            'ok':False,'state':'activation_failed','saved':True,'active':False,'message':''}
    old=DEPLOY/'status.json'
    if old.is_file():
        try:
            status['last_good_at']=json.loads(old.read_text()).get('activated_at') or json.loads(old.read_text()).get('last_good_at')
        except (OSError,ValueError):
            pass
    try:
        detail=apply_config(request_id=request['id'])
        status.update(ok=True,state='active',active=True,
                      message='NGINX-Konfiguration geprueft und Listener nach Reload bestaetigt',
                      **detail)
        status['last_good_at']=detail['activated_at']
    except Exception as exc:
        status['message']=str(exc)[:2000]
        status['rollback_ok']='Vorherige Konfiguration wiederhergestellt.' in str(exc)
        status['state']='activation_failed'
    write_atomic(DEPLOY/'status.json',json.dumps(status,ensure_ascii=False,indent=2),0o644)
    for marker in present_markers:
        marker.unlink(missing_ok=True)
    print(status['message'])
    return 0 if status['ok'] else 1

if __name__ == '__main__':
    sys.exit(main())
