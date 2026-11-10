# ProxyCircuit v0.2.1 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Read-only TLS/virtual-host checks with a local test backend."""
import re
import ssl
import socket
import tempfile
import subprocess
import threading
import unittest
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

from app import diagnostics

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data=b'<html><head><title>AfghanHost FileSharing</title></head><body>Login</body></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self,*args):
        pass

class FullDiagnosisTest(unittest.TestCase):
    def test_active_nginx_parsing(self):
        example='''# HTTP host: control.example.org
server { listen 80; }
# HTTPS host: control.example.org
server {
  location / {
  proxy_pass https://192.168.50.236:443;
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
  proxy_ssl_name control.example.org;
  }
}
# HTTP host: other.afghanhost.de
server { listen 80; }
'''
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'nginx.conf';path.write_text(example)
            status=diagnostics.inspect_nginx_upstream('control.example.org',path=path)
        self.assertTrue(status['http_present'])
        self.assertTrue(status['https_present'])
        self.assertEqual(status['proxy_pass'],'https://192.168.50.236:443')
        self.assertEqual(status['tls_name'],'control.example.org')
        self.assertEqual(status['tls_verification'],'on')

    def test_separate_host_cannot_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'nginx.conf'
            path.write_text('# HTTPS host: another.afghanhost.de\nserver { proxy_ssl_name secrets.example.org; }\n')
            r=diagnostics.inspect_nginx_upstream('control.example.org',path)
            self.assertFalse(r['https_present'])
            self.assertNotIn('secrets', str(r))

    def test_untrusted_certificate_still_gives_only_public_metadata_and_title(self):
        with tempfile.TemporaryDirectory() as tmp:
            key=Path(tmp)/'private.key'; cert=Path(tmp)/'server.crt'
            command=['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','3',
                     '-keyout',str(key),'-out',str(cert),'-subj','/CN=backend.example.test',
                     '-addext','subjectAltName=DNS:backend.example.test,IP:127.0.0.1']
            subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            httpd=HTTPServer(('127.0.0.1',0),Handler)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert),str(key))
            httpd.socket=ctx.wrap_socket(httpd.socket,server_side=True)
            th=threading.Thread(target=httpd.serve_forever,daemon=True)
            th.start()
            try:
                row={'domain':'control.example.org','upstream_scheme':'https',
                     'upstream_host':'127.0.0.1','upstream_port':httpd.server_port,
                     'upstream_tls_name':'backend.example.test','certificate_id':'c1',
                     'enabled':True,'websocket':True,'force_https':False}
                checked=diagnostics.probe_upstream(row)
                self.assertEqual(checked['code'],'TLS_UNTRUSTED')
                self.assertIn('backend.example.test',checked['certificate']['dns_names'])
                self.assertTrue(checked['certificate']['sha256_fingerprint'])
                info=diagnostics.inspect_backend_without_trust(row)
                self.assertTrue(info['reachable'])
                self.assertEqual(info['http_status'],200)
                self.assertEqual(info['page_title'],'AfghanHost FileSharing')
                self.assertNotIn('Login',str(info))
                with (patch.object(diagnostics,'config_presence',return_value={'https':True,'http':True}),
                      patch.object(diagnostics,'resolve_ipv4',return_value={'addresses':['127.0.0.1'],'error':''}),
                      patch.object(diagnostics,'probe_https_local',return_value={'state':'not-configured'}),
                      patch.object(diagnostics,'inspect_nginx_upstream',return_value={
                          'proxy_pass':f'https://127.0.0.1:{httpd.server_port}',
                          'tls_verification':'on','tls_name':'backend.example.test',
                          'https_present':True,'trusted_ca_path':'/etc/ssl/certs/ca-certificates.crt'})):
                    diag=diagnostics.diagnose_route(row)
                self.assertEqual(diag['upstream']['code'],'TLS_UNTRUSTED')
                self.assertEqual(diag['upstream']['unverified_backend']['page_title'],'AfghanHost FileSharing')
                self.assertTrue(diag['applied_nginx_upstream']['matches_database_upstream'])
            finally:
                httpd.shutdown()
                th.join(timeout=2)
                httpd.server_close()

if __name__ == '__main__':unittest.main()
