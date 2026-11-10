# ProxyCircuit v0.2.0 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
import unittest
from pathlib import Path
from app.engine import render_http
from app.security import hash_password, verify_password

STATIC=Path(__file__).resolve().parents[1] / 'app' / 'static'

class HotfixTest(unittest.TestCase):
    def test_csp_safe_static(self):
        js=(STATIC/'app.js').read_text(encoding='utf-8')
        html=(STATIC/'index.html').read_text(encoding='utf-8')
        self.assertNotIn(' style=', js)
        self.assertNotIn(' style=', html)
        self.assertIn('<progress', js)
        self.assertIn('net-usage-note', js)
        self.assertIn('/favicon.ico', html)
        self.assertTrue((STATIC/'favicon.ico').is_file())
    def test_minimum_password(self):
        saved=hash_password('abc12345')
        self.assertTrue(verify_password('abc12345',saved))
        self.assertFalse(verify_password('wrongkey',saved))
        with self.assertRaises(ValueError): hash_password('abc1234')
    def test_http2_updated(self):
        host={'domain':'example.org','upstream_host':'192.168.50.236','upstream_port':80,
              'upstream_scheme':'http','websocket':1,'force_https':0,'certificate_id':'cert1','enabled':1}
        cert={'id':'cert1','status':'ready','fullchain_path':'/var/lib/rpmgr/certs/fullchain.pem',
              'privkey_path':'/var/lib/rpmgr/certs/privkey.pem','domain':'example.org'}
        config=render_http([host],[cert])
        self.assertIn('    listen 443 ssl;\n    http2 on;',config)
        self.assertNotIn('listen 443 ssl http2', config)

if __name__=='__main__': unittest.main()
