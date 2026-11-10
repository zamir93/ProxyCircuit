# ProxyCircuit v0.2.3 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Regression: fallback must never overwrite a healthy proxy or weaken upstream TLS."""
import unittest
from pathlib import Path
import subprocess
import tempfile
from app.engine import render_http
from app.main import FallbackPageInput

class DefaultPageTests(unittest.TestCase):
    def test_fallback_config_includes_only_expected_errors(self):
        host=dict(domain='app.example.de', upstream_host='10.0.0.50', upstream_port=8080,
                  upstream_scheme='http',websocket=1,force_https=0,certificate_id=None,enabled=True)
        config=render_http([host],[])
        self.assertIn('listen 80 default_server;',config)
        self.assertIn('listen 443 ssl default_server;',config)
        self.assertIn('error_page 404 /__proxycircuit_error_page.html;',config)
        self.assertIn('error_page 502 503 504 /__proxycircuit_error_page.html;',config)
        self.assertNotIn('error_page 200',config)
        self.assertIn('proxy_pass http://10.0.0.50:8080;',config)
        self.assertIn('proxy_intercept_errors on;',config)
        self.assertIn('internal;',config)
        self.assertIn("script-src 'none'",config)
        self.assertIn('noindex, nofollow, noarchive',config)

    def test_real_nginx_returns_404_default_502_offline_and_200_healthy(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)
            base.chmod(0o755)
            key=base/'tls.key'; cert=base/'tls.crt';page_dir=base/'www';page_dir.mkdir()
            content=(Path(__file__).resolve().parents[1]/'app/default_page.html').read_text()
            (page_dir/'__proxycircuit_error_page.html').write_text(content)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                            '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost'],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            from http.server import HTTPServer,BaseHTTPRequestHandler
            import threading
            import socket
            class UpstreamHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    body=b'LIVE BACKEND CONTENT'
                    self.send_response(200)
                    self.send_header('Content-Type','text/plain')
                    self.send_header('Content-Length',str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                def log_message(self,*args):pass
            backend=HTTPServer(('127.0.0.1',0),UpstreamHandler)
            thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
            def free_port():
                with socket.socket() as conn:
                    conn.bind(('127.0.0.1',0))
                    return conn.getsockname()[1]
            port=free_port()
            # nginx -t must use a cert that exists in this test sandbox.
            host=dict(domain='live.example.de',upstream_scheme='http',upstream_host='127.0.0.1',
                      upstream_port=backend.server_port,websocket=True,force_https=False,
                      certificate_id=None,enabled=True)
            off=dict(host,domain='down.example.de',upstream_port=free_port())
            rendered=render_http([host,off],[])
            rendered=rendered.replace('listen 80 default_server;',f'listen 127.0.0.1:{port} default_server;')
            rendered=rendered.replace('listen 80;',f'listen 127.0.0.1:{port};')
            rendered=rendered.replace('listen 443 ssl default_server;',f'listen 127.0.0.1:{free_port()} ssl default_server;')
            rendered=rendered.replace('listen 127.0.0.1:18081;',f'listen 127.0.0.1:{free_port()};')
            rendered=rendered.replace('/etc/rpmgr/admin.crt',str(cert)).replace('/etc/rpmgr/admin.key',str(key))
            rendered=rendered.replace('/var/www/rpmgr-fallback',str(page_dir))
            (base/'managed.conf').write_text(rendered)
            main=base/'nginx.conf'
            main.write_text(f'worker_processes 1; pid {base}/nginx.pid; error_log {base}/error.log; '+
                            f'events {{ worker_connections 256; }} http {{ include /etc/nginx/mime.types; include {base}/managed.conf; }}')
            proc=subprocess.run(['nginx','-t','-c',str(main),'-p',td],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            server=subprocess.Popen(['nginx','-c',str(main),'-p',td,'-g','daemon off;'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                import urllib.request,urllib.error
                import time
                for i in range(30):
                    if server.poll() is not None:raise AssertionError('Nginx failed to start')
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                    except OSError:time.sleep(.1)
                def request(host):
                    req=urllib.request.Request(f'http://127.0.0.1:{port}/',headers={'Host':host})
                    try:
                        with urllib.request.urlopen(req,timeout=4) as resp:
                            return resp.status,resp.read().decode(),dict(resp.headers)
                    except urllib.error.HTTPError as exc:
                        return exc.code,exc.read().decode(),dict(exc.headers)
                code,body,headers=request('unknown.example.de')
                self.assertEqual(code,404)
                self.assertIn('Diese Seite ist momentan nicht erreichbar',body)
                self.assertIn('noindex',headers.get('X-Robots-Tag',''))
                code,body,headers=request('down.example.de')
                self.assertEqual(code,502)
                self.assertIn('AfghanHost',body)
                self.assertIn('no-store',headers.get('Cache-Control',''))
                code,body,headers=request('live.example.de')
                self.assertEqual(code,200)
                self.assertIn('LIVE BACKEND CONTENT',body)
                self.assertNotIn('Standardseite',body)
            finally:
                server.terminate()
                try:server.wait(timeout=4)
                except subprocess.TimeoutExpired:server.kill()
                backend.shutdown()

    def test_admin_edit_validation(self):
        self.assertIn('<html',FallbackPageInput(html='<html><body>Test HTML</body></html>').html)
        for value in ('<html><script>alert(1)</script></html>',
                      '<html><form action="/">foo</form></html>',
                      '<html><img src=x onerror=alert(1)></html>',
                      '<html><iframe src=evil></iframe></html>'):
            with self.assertRaises(Exception):FallbackPageInput(html=value)

if __name__=='__main__':unittest.main()
