#!/usr/bin/env python3
# ProxyCircuit NPM Migration v1.0 | Author: Mohammad Zamir Akbari
# Author URL: https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""NPM to ProxyCircuit: read-only export, preview, disabled staging import.

This tool never activates an imported host or changes Nginx.  All imports
are staged disabled; activation must be done after individual checks.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import uuid

MANIFEST_SCHEMA = 'proxycircuit-npm-inventory-v1'
HOST_COLS = ('id', 'domain', 'upstream_scheme', 'upstream_host', 'upstream_port',
             'upstream_tls_name', 'websocket', 'force_https', 'certificate_id', 'enabled')
DNS_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.I)


def require_root():
    if os.geteuid() != 0:
        raise RuntimeError('Run as root in the correct LXC container')


def safe_domain(value: str, wildcard: bool = False) -> str:
    if not isinstance(value, str) or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError('invalid domain characters')
    name = value.lower().rstrip('.')
    wc = name.startswith('*.')
    if wc and not wildcard:
        raise ValueError('wildcard proxy hosts are not supported')
    suffix = name[2:] if wc else name
    suffix = suffix.encode('idna').decode('ascii')
    parts = suffix.split('.')
    if len(suffix) > 253 or len(parts) < 2 or not all(DNS_LABEL.fullmatch(x) for x in parts):
        raise ValueError('invalid domain syntax')
    return ('*.' if wc else '') + suffix


def safe_target(value: str) -> str:
    if not isinstance(value, str) or not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError('invalid target')
    value = value.lower()
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not all(DNS_LABEL.fullmatch(p) for p in value.split('.')):
        raise ValueError('invalid target host')
    return value


def json_domains(text):
    try:
        data = json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) and all(isinstance(x, str) for x in data) else []


def has_locations(text):
    try:
        return bool(json.loads(text or '[]'))
    except (ValueError, TypeError):
        return bool(str(text or '').strip())


def read_only_db(path: Path):
    if not path.is_file():
        raise RuntimeError(f'Database not found: {path}')
    con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def private_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f'Output directory must not be a symlink: {path}')
    os.chmod(path, 0o700)


def json_private(path: Path, payload: dict):
    private_dir(path.parent)
    tmp = path.parent / ('.tmp-' + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    finally:
        if tmp.exists():
            tmp.unlink()


def cert_source(cert_id: int):
    if not isinstance(cert_id, int) or cert_id < 1:
        return None
    for base in (Path('/etc/letsencrypt/live'), Path('/data/letsencrypt/live')):
        folder = base / f'npm-{cert_id}'
        if (folder / 'fullchain.pem').is_file() and (folder / 'privkey.pem').is_file():
            return folder
    return None


def write_secure_file(source: Path, dest: Path, mode: int):
    data = source.read_bytes()
    if not data or len(data) > 500_000:
        raise ValueError('certificate file missing or unexpectedly large')
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(dest, mode)


def export_inventory(db: Path, out_dir: Path, include_keys: bool):
    require_root()
    private_dir(out_dir)
    manifest_file = out_dir / 'manifest.json'
    if any(out_dir.iterdir()):
        raise RuntimeError('Export directory is not empty; use a new empty directory')
    con = read_only_db(db)
    try:
        con.execute('BEGIN')
        hosts = [dict(r) for r in con.execute('SELECT * FROM proxy_host ORDER BY id')]
        certs = [dict(r) for r in con.execute('SELECT * FROM certificate ORDER BY id')]
        con.commit()
    finally:
        con.close()
    live = [r for r in hosts if not r.get('is_deleted') and r.get('enabled')]
    entries = []
    referenced = set()
    for row in live:
        source_id = int(row['id'])
        names = json_domains(row.get('domain_names'))
        ssl_id = int(row.get('certificate_id') or 0)
        if ssl_id:
            referenced.add(ssl_id)
        entries.append({
            'source_id': source_id,
            'domains': names,
            'upstream_scheme': str(row.get('forward_scheme') or '').lower(),
            'upstream_host': str(row.get('forward_host') or ''),
            'upstream_port': row.get('forward_port'),
            'npm_certificate_id': ssl_id,
            'websocket': bool(row.get('allow_websocket_upgrade')),
            'force_https': bool(row.get('ssl_forced')),
            'http2_support': bool(row.get('http2_support')),
            'hsts_enabled': bool(row.get('hsts_enabled')),
            'hsts_subdomains': bool(row.get('hsts_subdomains')),
            'block_exploits': bool(row.get('block_exploits')),
            'caching_enabled': bool(row.get('caching_enabled')),
            'custom_advanced_config': bool(str(row.get('advanced_config') or '').strip()),
            'custom_locations': has_locations(row.get('locations')),
            'access_list_used': bool(row.get('access_list_id')),
        })
    metadata = []
    for row in certs:
        cid = int(row['id'])
        if cid not in referenced or row.get('is_deleted'):
            continue
        metadata.append({
            'source_id': cid,
            'provider': str(row.get('provider') or ''),
            'nice_name': str(row.get('nice_name') or '')[:150],
            'domains': json_domains(row.get('domain_names')),
            'expires_on': str(row.get('expires_on') or ''),
            'material': 'not-exported',
        })
    metadata_by_id = {c['source_id']: c for c in metadata}
    if include_keys:
        private_dir(out_dir / 'certs')
        for cid in sorted(referenced):
            record = metadata_by_id.get(cid)
            if record is None:
                continue
            folder = cert_source(cid)
            if folder is None:
                record['material'] = 'missing-in-usual-npm-paths'
                continue
            dst = out_dir / 'certs' / f'npm-{cid}'
            try:
                private_dir(dst)
                write_secure_file(folder / 'fullchain.pem', dst / 'fullchain.pem', 0o600)
                write_secure_file(folder / 'privkey.pem', dst / 'privkey.pem', 0o600)
            except (OSError, ValueError) as exc:
                shutil.rmtree(dst, ignore_errors=True)
                record['material'] = 'copy-failed'
            else:
                record['material'] = 'exported'
    payload = {
        'schema': MANIFEST_SCHEMA,
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'source': 'Nginx Proxy Manager sqlite (read only)',
        'counts': {
            'total_proxy_hosts': len(hosts),
            'active_hosts': len(live),
            'deleted_hosts': sum(bool(r.get('is_deleted')) for r in hosts),
            'inactive_hosts': sum(not r.get('is_deleted') and not r.get('enabled') for r in hosts),
            'active_domain_names': sum(len(x['domains']) for x in entries),
            'referenced_cert_ids': len(referenced),
            'exported_cert_ids': sum(c['material'] == 'exported' for c in metadata),
            'https_upstreams': sum(x['upstream_scheme'] == 'https' for x in entries),
            'advanced_configs': sum(x['custom_advanced_config'] for x in entries),
            'custom_locations': sum(x['custom_locations'] for x in entries),
        },
        'hosts': entries,
        'certificates': metadata,
        'safety': 'No passwords, private keys or advanced config text in manifest; certificate files are separate.'
    }
    json_private(manifest_file, payload)
    return payload


def cert_matches(cert: Path, key: Path, domain: str):
    try:
        test_domain = 'probe.' + domain[2:] if domain.startswith('*.') else domain
        cmds = [
            ['openssl', 'x509', '-in', str(cert), '-noout', '-checkhost', test_domain],
            ['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '86400'],
            ['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'],
            ['openssl', 'pkey', '-in', str(key), '-pubout'],
        ]
        results = [subprocess.run(cmd, capture_output=True, timeout=12, check=False) for cmd in cmds]
        return (all(x.returncode == 0 for x in results) and
                results[2].stdout.strip() == results[3].stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def cert_expiry(cert: Path):
    result = subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-enddate'],
                            capture_output=True, text=True, check=True, timeout=12)
    text = result.stdout.strip().split('=', 1)[1]
    return datetime.strptime(text, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc).isoformat()


def cert_root_files(certs_dir: Path | None, cid: int):
    if not certs_dir or not isinstance(cid, int) or cid < 1:
        return None
    folder = certs_dir / f'npm-{cid}'
    chain, key = folder / 'fullchain.pem', folder / 'privkey.pem'
    if not chain.is_file() or not key.is_file() or chain.is_symlink() or key.is_symlink():
        return None
    try:
        if not chain.resolve().is_relative_to(certs_dir.resolve()):
            return None
        if not key.resolve().is_relative_to(certs_dir.resolve()):
            return None
        if chain.stat().st_size > 500_000 or key.stat().st_size > 500_000:
            return None
    except (OSError, ValueError):
        return None
    return chain, key


def load_manifest(path: Path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('schema') != MANIFEST_SCHEMA:
        raise RuntimeError('Unrecognized or unsupported manifest format')
    if not isinstance(data.get('hosts'), list) or not isinstance(data.get('certificates'), list):
        raise RuntimeError('Invalid manifest structure')
    if len(data['hosts']) > 5000:
        raise RuntimeError('Manifest contains too many hosts')
    return data


def target_db(path: Path):
    if not path.is_file():
        raise RuntimeError('ProxyCircuit database missing; run inside CT 150, not on pve host')
    con = read_only_db(path)
    try:
        names = {r['name'] for r in con.execute('PRAGMA table_info(hosts)')}
        if not set(HOST_COLS).issubset(names):
            raise RuntimeError('ProxyCircuit database schema mismatch (requires v0.1.4)')
        existing = {r['domain'].lower() for r in con.execute('SELECT domain FROM hosts')}
    finally:
        con.close()
    return existing


def plan(manifest: dict, existing: set, certs_dir: Path | None):
    known_cert_ids = {int(c['source_id']) for c in manifest['certificates']}
    result = []
    seen = set()
    for h in manifest['hosts']:
        if not isinstance(h, dict):
            raise RuntimeError('Invalid host in manifest')
        names = h.get('domains')
        if not isinstance(names, list):
            raise RuntimeError('Invalid domain list')
        for raw_name in names:
            reasons = []
            domain = str(raw_name)
            scheme = str(h.get('upstream_scheme') or '').lower()
            cid = int(h.get('npm_certificate_id') or 0)
            cert_files = None
            try:
                domain = safe_domain(domain, wildcard=True)
                upstream = safe_target(h.get('upstream_host'))
                port = int(h.get('upstream_port'))
                if scheme not in ('http', 'https') or not 1 <= port <= 65535:
                    raise ValueError('unsupported upstream scheme or port')
            except (TypeError, ValueError, UnicodeError) as exc:
                result.append({'domain': domain, 'source_id': h.get('source_id'), 'action': 'INVALID',
                               'reasons': [str(exc)]})
                continue
            if domain in seen:
                action = 'DUPLICATE_IN_NPM'
            elif domain in existing:
                action = 'KEEP_EXISTING'
            else:
                action = 'STAGE_DISABLED'
            seen.add(domain)
            if h.get('custom_advanced_config'):
                reasons.append('advanced_config requires manual migration')
            if h.get('custom_locations'):
                reasons.append('additional locations require manual migration')
            if h.get('access_list_used'):
                reasons.append('access list not supported')
            if h.get('block_exploits'):
                reasons.append('NPM block_exploits option not mapped')
            if h.get('caching_enabled'):
                reasons.append('NPM cache option not mapped')
            if h.get('hsts_enabled') or h.get('hsts_subdomains'):
                reasons.append('HSTS setting not mapped')
            if scheme == 'https':
                reasons.append('HTTPS upstream: review TLS hostname, CA and SNI before enabling')
                if not _ip(upstream) and '.' not in upstream:
                    reasons.append('short upstream hostname: set a verified TLS name before enabling')
            if cid:
                if cid not in known_cert_ids:
                    reasons.append('source certificate metadata missing')
                cert_files = cert_root_files(certs_dir, cid)
                if cert_files is None:
                    reasons.append('certificate material not supplied')
                elif not cert_matches(*cert_files, domain):
                    reasons.append('certificate invalid, expiring or hostname/key mismatch')
                    cert_files = None
            else:
                reasons.append('source HTTP-only (no certificate)')
            result.append({
                'domain': domain, 'source_id': h.get('source_id'), 'action': action,
                'upstream_scheme': scheme, 'upstream_host': upstream, 'upstream_port': port,
                'upstream_tls_name': upstream if scheme == 'https' and not _ip(upstream) and '.' in upstream else None,
                'npm_certificate_id': cid,
                'certificate_available': cert_files is not None,
                'websocket': bool(h.get('websocket')),
                'force_https_requested': bool(h.get('force_https')),
                'reasons': reasons,
            })
    return result


def _ip(value: str):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def summary(plan_items):
    counts = Counter(x['action'] for x in plan_items)
    warnings = Counter()
    for item in plan_items:
        for reason in item.get('reasons', []):
            warnings[reason] += 1
    return {'actions': dict(counts), 'warnings': dict(warnings),
            'new_with_certificate': sum(x['action'] == 'STAGE_DISABLED' and x.get('certificate_available') for x in plan_items)}


def snapshot(db: Path, backup: Path):
    private_dir(backup.parent)
    src = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
    dst = sqlite3.connect(str(backup))
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()
    os.chmod(backup, 0o600)


def stage_import(items, certs_dir: Path | None, dest_db: Path, cert_dest: Path, backup_dir: Path):
    require_root()
    if not Path('/opt/rpmgr/.rpmgr-installed').exists() and dest_db == Path('/var/lib/rpmgr/rpmgr.sqlite3'):
        raise RuntimeError('Not installed on this machine: run inside ProxyCircuit CT 150')
    private_dir(backup_dir)
    backup = backup_dir / ('pre-npm-stage-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8] + '.sqlite3')
    snapshot(dest_db, backup)
    created_dirs = []
    staged = 0
    cert_imported = 0
    con = sqlite3.connect(str(dest_db), timeout=30)
    try:
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('BEGIN IMMEDIATE')
        existing = {row[0] for row in con.execute('SELECT domain FROM hosts')}
        for entry in items:
            if entry['action'] != 'STAGE_DISABLED' or entry['domain'] in existing:
                continue
            domain = entry['domain']
            cert_id = None
            cid = entry['npm_certificate_id']
            if entry.get('certificate_available'):
                files = cert_root_files(certs_dir, cid)
                if files is None or not cert_matches(*files, domain):
                    raise RuntimeError(f'Certificate changed after preview for {domain}; aborted')
                cert_id = uuid.uuid4().hex[:16]
                folder = cert_dest / cert_id
                private_dir(cert_dest)
                folder.mkdir(mode=0o700, exist_ok=False)
                os.chmod(folder, 0o700)
                created_dirs.append(folder)
                write_secure_file(files[0], folder / 'fullchain.pem', 0o644)
                write_secure_file(files[1], folder / 'privkey.pem', 0o600)
                con.execute('''INSERT INTO certificates(id,label,domain,kind,fullchain_path,privkey_path,expires_at,status)
                               VALUES(?,?,?,?,?,?,?,?)''',
                            (cert_id, f'NPM #{cid}: {domain}', domain, 'manual',
                             str(folder / 'fullchain.pem'), str(folder / 'privkey.pem'), cert_expiry(files[0]), 'ready'))
                cert_imported += 1
            host_id = uuid.uuid4().hex[:16]
            force_https = int(bool(entry['force_https_requested']) and cert_id is not None)
            con.execute('''INSERT INTO hosts(id,domain,upstream_scheme,upstream_host,upstream_port,
                    upstream_tls_name,websocket,force_https,certificate_id,enabled)
                    VALUES(?,?,?,?,?,?,?,?,?,0)''',
                        (host_id, domain, entry['upstream_scheme'], entry['upstream_host'], entry['upstream_port'],
                         entry['upstream_tls_name'], int(entry['websocket']), force_https, cert_id))
            existing.add(domain)
            staged += 1
        con.commit()
    except Exception:
        con.rollback()
        for d in created_dirs:
            shutil.rmtree(d, ignore_errors=True)
        raise
    finally:
        con.close()
    # No existing proxy row is modified; every new row is disabled.
    # The backup is a consistent SQLite snapshot before the import.
    return {'new_disabled_hosts': staged, 'new_certificate_records': cert_imported,
            'sqlite_backup': str(backup)}


def args_parser():
    parser = argparse.ArgumentParser(description='NPM -> ProxyCircuit safe staging migration')
    subs = parser.add_subparsers(dest='command', required=True)
    exp = subs.add_parser('export', help='Read old NPM SQLite without modifying it')
    exp.add_argument('--db', type=Path, default=Path('/data/database.sqlite'))
    exp.add_argument('--out-dir', type=Path, required=True)
    exp.add_argument('--include-private-keys', action='store_true', help='Copy SSL cert+key to root-only directory')
    for op in ('plan', 'stage'):
        p = subs.add_parser(op)
        p.add_argument('--input', type=Path, required=True, help='manifest.json from export')
        p.add_argument('--certs-dir', type=Path, help='private certs directory from export')
        p.add_argument('--target-db', type=Path, default=Path('/var/lib/rpmgr/rpmgr.sqlite3'))
        p.add_argument('--report', type=Path, help='root-only JSON report')
        if op == 'stage':
            p.add_argument('--confirm', required=True, help='Must be STAGE-DISABLED')
            p.add_argument('--cert-dest', type=Path, default=Path('/var/lib/rpmgr/certs'))
            p.add_argument('--backup-dir', type=Path, default=Path('/var/backups/rpmgr'))
    return parser


def main(argv=None):
    args = args_parser().parse_args(argv)
    try:
        if args.command == 'export':
            payload = export_inventory(args.db, args.out_dir, args.include_private_keys)
            print(json.dumps(payload['counts'], indent=2, ensure_ascii=False))
            print('Export created:', args.out_dir / 'manifest.json')
            if args.include_private_keys:
                print('WARNING: certs directory holds PRIVATE KEYS. Transfer over SSH only; never upload to chat.')
            return 0
        manifest = load_manifest(args.input)
        existing = target_db(args.target_db)
        entries = plan(manifest, existing, args.certs_dir)
        result = summary(entries)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if args.report:
            json_private(args.report, {'summary': result, 'entries': entries})
            print('Detailed report:', args.report)
        if args.command == 'stage':
            if args.confirm != 'STAGE-DISABLED':
                raise RuntimeError('Refusing import: --confirm STAGE-DISABLED required')
            if any(x['action'] == 'INVALID' for x in entries):
                raise RuntimeError('Invalid records in source; fix the manifest/export before staging')
            result = stage_import(entries, args.certs_dir, args.target_db, args.cert_dest, args.backup_dir)
            print('STAGING RESULT:', json.dumps(result, indent=2))
            print('All NEW proxy hosts are DISABLED. No Nginx reload, no router change.')
        return 0
    except (RuntimeError, ValueError, OSError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        print('ERROR:', str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
