# ProxyCircuit | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Safe upstream path routing and backwards compatible SQLite migration."""
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen
import socket
import subprocess
import time

from app.validation import HostInput, clean_upstream_path
from app.engine import render_http, proxy_location


def host(**kw):
    base=dict(domain='inventory.example.org', upstream_scheme='http',
              upstream_host='192.168.10.3', upstream_port=80, websocket=False,
              certificate_id=None, enabled=True, force_https=False)
    base.update(kw)
    return base

class PathValidationTests(unittest.TestCase):
    def test_normalize(self):
        for value, expected in [(None, '/'), ('', '/'), ('/', '/'),
                                ('lager_inventar_system', '/lager_inventar_system/'),
                                ('/lager_inventar_system', '/lager_inventar_system/'),
                                ('/images/icons/', '/images/icons/')]:
            self.assertEqual(clean_upstream_path(value), expected)
            self.assertEqual(HostInput(**host(upstream_path=value)).upstream_path, expected)

    def test_reject_nginx_injection_and_ambiguous_paths(self):
        values=['http://evil.example/', '//evil', '/a//b', '/a/../etc', '/./',
                '/a?q=1', '/a#x', '/a%2Fb', '/a\\b', '/a b',
                '/a;return 200', '/a\nproxy_pass http://evil;', 'x'*513]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                clean_upstream_path(value)

    def test_host_must_be_host_only(self):
        with self.assertRaises(ValueError):
            HostInput(**host(upstream_host='192.168.10.3/lager_inventar_system'))

    def test_upstream_proxy_pass_with_prefix(self):
        conf = render_http([host(upstream_path='/lager_inventar_system/')], [])
        self.assertIn('proxy_pass http://192.168.10.3:80/lager_inventar_system/;', conf)
        self.assertIn('server_name inventory.example.org;', conf)
        self.assertNotIn('proxy_pass http://192.168.10.3:80;', conf)

    def test_default_does_not_change_legacy_proxy_pass(self):
        self.assertIn('proxy_pass http://192.168.10.3:80;', render_http([host()], []))
        self.assertNotIn('proxy_pass http://192.168.10.3:80/;', render_http([host()], []))

    def test_sqlite_migration_preserves_existing_hosts(self):
        import app.db as db
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'rpmgr.sqlite3'
            conn = sqlite3.connect(path)
            legacy = db.SCHEMA.replace(" upstream_path TEXT NOT NULL DEFAULT '/',", '')
            conn.executescript(legacy)
            conn.execute("INSERT INTO hosts(id,domain,upstream_scheme,upstream_host,upstream_port) VALUES('1','old.example.de','http','192.168.10.3',80)")
            conn.commit()
            conn.close()
            with patch.multiple(db, DB=path, BASE=root, CERTS=root/'certs', DEPLOY=root/'deploy', ACME=root/'acme'):
                db.init_db()
                db.init_db()  # idempotent
                conn = db.connect()
                result = conn.execute("SELECT upstream_path,upstream_host FROM hosts WHERE id='1'").fetchone()
                self.assertEqual(result['upstream_path'], '/')
                self.assertEqual(result['upstream_host'], '192.168.10.3')
                conn.close()

    def test_real_nginx_proxies_root_to_subdirectory(self):
        if not Path('/usr/sbin/nginx').exists():
            self.skipTest('nginx not present')
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                content=self.path.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Length',str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            def log_message(self,*args): pass
        backend = HTTPServer(('127.0.0.1',0), Handler)
        thread=threading.Thread(target=backend.serve_forever,daemon=True)
        thread.start()
        try:
            with socket.socket() as s:
                s.bind(('127.0.0.1',0));frontend_port=s.getsockname()[1]
            with tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp)
                mapping=proxy_location(host(upstream_host='127.0.0.1',upstream_port=backend.server_port,
                                            upstream_path='/lager_inventar_system/'))
                config=f"""worker_processes 1;
pid {base}/nginx.pid;
error_log {base}/error.log;
events {{ worker_connections 128; }}
http {{ access_log off; server {{ listen 127.0.0.1:{frontend_port}; server_name localhost;
{mapping}
}} }}
"""
                conf=base/'nginx.conf'; conf.write_text(config)
                check=subprocess.run(['/usr/sbin/nginx','-t','-c',str(conf),'-p',str(base)],capture_output=True,text=True)
                self.assertEqual(check.returncode,0,check.stderr)
                process=subprocess.Popen(['/usr/sbin/nginx','-c',str(conf),'-p',str(base),'-g','daemon off;'],
                                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:
                    for _ in range(30):
                        if process.poll() is not None:
                            raise AssertionError('Nginx test instance exited')
                        try:
                            with urlopen(f'http://127.0.0.1:{frontend_port}/', timeout=.3) as response:
                                self.assertEqual(response.read().decode(),'/lager_inventar_system/')
                            break
                        except OSError:
                            time.sleep(.05)
                    else:
                        self.fail('Temporary nginx did not start')
                    with urlopen(f'http://127.0.0.1:{frontend_port}/assets/app.css?x=1', timeout=2) as response:
                        self.assertEqual(response.read().decode(),'/lager_inventar_system/assets/app.css?x=1')
                finally:
                    process.terminate()
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired: process.kill();process.wait(timeout=3)
        finally:
            backend.shutdown();thread.join(timeout=3);backend.server_close()

if __name__ == '__main__':
    unittest.main()
