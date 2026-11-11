# ProxyCircuit v0.2.0 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from app.engine import render_http, render_stream
from app.validation import HostInput, StreamInput, clean_target, clean_domain, cert_matches_domain

class ValidationTest(unittest.TestCase):
    def test_domain_and_host(self):
        self.assertEqual(clean_domain('APP.EXAMPLE.DE.'),'app.example.de')
        self.assertEqual(clean_target('10.0.0.50'),'10.0.0.50')
        self.assertEqual(clean_target('2001:db8::1'),'2001:db8::1')
        for bad in ('example.com; return 200;', 'app.example.com\nlocation /', '_', 'nodot'):
            with self.assertRaises(ValueError):clean_domain(bad)
        for bad in ('10.0.0.50;include /tmp/pwn','127.0.0.1\n','bad host'):
            with self.assertRaises(ValueError):clean_target(bad)
    def test_cert_domain(self):
        self.assertTrue(cert_matches_domain('*.example.org','app.example.org'))
        self.assertFalse(cert_matches_domain('*.example.org','deep.app.example.org'))
        self.assertFalse(cert_matches_domain('*.example.org','example.org'))
    def test_https_requires_cert(self):
        with self.assertRaises(ValueError):
            HostInput(domain='app.example.de',upstream_host='10.0.0.50',upstream_port=8000,force_https=True)
    def test_port_limits(self):
        with self.assertRaises(ValueError):
            StreamInput(label='TCP',protocol='tcp',listen_port=0,target_host='10.0.0.50',target_port=80)
    def test_http_config(self):
        hosts=[dict(domain='app.example.de',upstream_host='10.0.0.50',upstream_port=8080,
                    upstream_scheme='http',websocket=1,force_https=0,certificate_id=None,enabled=1)]
        config=render_http(hosts,[])
        self.assertIn('server_name app.example.de;',config)
        self.assertIn('proxy_pass http://10.0.0.50:8080;',config)
        self.assertIn('proxy_set_header Upgrade $http_upgrade;',config)
        self.assertIn('root /var/www/rpmgr-acme;',config)
    def test_https_upstream_tls_name(self):
        row = dict(domain='pc.example.de', upstream_host='192.168.50.150',
                   upstream_port=9443, upstream_scheme='https',
                   upstream_tls_name='proxycircuit.local', websocket=1,
                   force_https=0, certificate_id=None, enabled=1)
        config = render_http([row], [])
        self.assertIn('proxy_ssl_name proxycircuit.local;', config)
        self.assertIn('proxy_ssl_verify on;', config)
        self.assertIn('proxy_ssl_server_name on;', config)
        self.assertNotIn('proxy_ssl_verify off;', config)
        # For unrelated HTTPS upstreams, preserve strict default verification.
        row['upstream_tls_name'] = None
        self.assertNotIn('proxy_ssl_name proxycircuit.local;', render_http([row], []))
        with self.assertRaises(ValueError):
            HostInput(**dict(row, upstream_tls_name='evil.test; return 200'))
        with self.assertRaises(ValueError):
            HostInput(**dict(row, upstream_tls_name='bad\nname'))
        with self.assertRaises(ValueError):
            HostInput(**dict(row, upstream_scheme='http', upstream_tls_name='proxycircuit.local'))

    def test_stream_config(self):
        streams=[dict(label='SSH',protocol='tcp',listen_port=2222,target_host='10.0.0.50',target_port=22,timeout_seconds=360,enabled=1),
                 dict(label='UDP',protocol='udp',listen_port=5000,target_host='10.0.0.50',target_port=5000,timeout_seconds=10,enabled=1)]
        config=render_stream(streams)
        self.assertIn('listen 2222;',config)
        self.assertIn('proxy_pass 10.0.0.50:22;',config)
        self.assertIn('listen 5000 udp;',config)
        with self.assertRaises(ValueError):render_stream([dict(streams[0],listen_port=443)])
        with self.assertRaises(ValueError):render_stream(streams+[streams[0]])
    def test_nginx_parse_no_tls(self):
        if not Path('/usr/sbin/nginx').exists():self.skipTest('nginx missing')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            h=root/'http.conf';s=root/'stream.conf'
            key=root/'default.key';cert=root/'default.crt'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost'],
                check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            rendered=render_http([],[]).replace('/etc/rpmgr/admin.crt',str(cert)).replace('/etc/rpmgr/admin.key',str(key))
            h.write_text(rendered);s.write_text(render_stream([]))
            nginx=f'''worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/nginx-error.log;
events {{ worker_connections 100; }}
http {{ access_log off; include /etc/nginx/mime.types; include {h}; }}
stream {{ }}
'''
            # Basic parse test with http; Debian's stream module may require explicit load_module.
            if Path('/usr/lib/nginx/modules/ngx_stream_module.so').exists():
                nginx= 'load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n'+nginx.replace('stream { }',s.read_text())
            else:nginx=nginx.replace('stream { }','')
            (root/'nginx.conf').write_text(nginx)
            proc=subprocess.run(['nginx','-t','-c',str(root/'nginx.conf'),'-p',str(root)],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)

if __name__=='__main__':unittest.main()
