# ProxyCircuit v0.2.0 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Regression tests: distinguish configured, internal, and public accessibility."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi import HTTPException
from app import diagnostics
from app.main import validate_manual_pem


ROW = {
    'domain':'eurotube.afghanhost.de', 'upstream_scheme':'http',
    'upstream_host':'192.168.50.236', 'upstream_port':80,
    'websocket':1, 'force_https':0, 'certificate_id':'cert-id', 'enabled':1,
}

class DiagnosticsTest(unittest.TestCase):
    def test_01_config_presence(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'nginx.conf'
            p.write_text('# HTTP host: eurotube.afghanhost.de\n'
                         'server { server_name eurotube.afghanhost.de; }\n'
                         '# HTTPS host: eurotube.afghanhost.de\n'
                         'server { listen 443 ssl; }\n')
            r = diagnostics.config_presence('eurotube.afghanhost.de', path=p)
            self.assertTrue(r['http'])
            self.assertTrue(r['https'])
            self.assertFalse(diagnostics.config_presence('other.afghanhost.de', path=p)['https'])

    def test_02_missing_conf_is_not_ok(self):
        with tempfile.TemporaryDirectory() as td:
            r = diagnostics.config_presence('eurotube.afghanhost.de', path=Path(td)/'not-present')
            self.assertFalse(r['readable'])
            self.assertFalse(r['https'])

    def test_03_public_wan_never_claimed_verified(self):
        with (patch.object(diagnostics, 'config_presence', return_value={'http':True,'https':True,'readable':True}),
              patch.object(diagnostics, 'resolve_ipv4', return_value={'addresses':['8.8.8.8'],'error':''}),
              patch.object(diagnostics, 'probe_upstream', return_value={'state':'responding','http_status':302}),
              patch.object(diagnostics, 'probe_https_local', return_value={'state':'responding','http_status':200})):
            d = diagnostics.diagnose_route(ROW)
        self.assertEqual(d['local_https']['http_status'], 200)
        self.assertEqual(d['upstream']['http_status'], 302)
        self.assertTrue(d['dns_points_to_public_ip'])
        self.assertEqual(d['public_ingress'], 'not_verified')

    def test_04_private_ip_not_public(self):
        with (patch.object(diagnostics, 'config_presence', return_value={'http':True,'https':False}),
              patch.object(diagnostics, 'resolve_ipv4', return_value={'addresses':['192.168.50.150'],'error':''}),
              patch.object(diagnostics, 'probe_upstream', return_value={'state':'offline'})):
            d = diagnostics.diagnose_route({**ROW, 'certificate_id':None})
        self.assertFalse(d['dns_points_to_public_ip'])
        self.assertEqual(d['local_https']['state'], 'not-configured')

    def test_05_pem_bad_key_gives_specific_error(self):
        with self.assertRaises(HTTPException) as ctx:
            validate_manual_pem('eurotube.afghanhost.de', 'not a pem', 'not a key')
        self.assertEqual(ctx.exception.status_code, 422)

    def test_06_ui_diagnostic_action_is_wired(self):
        static = Path(__file__).resolve().parents[1]/'app'/'static'
        js = (static/'app.js').read_text()
        html = (static/'index.html').read_text()
        self.assertIn('data-action="diagnoseHost"',js)
        self.assertIn("if(action==='diagnoseHost')return runDomainDiagnostics(id)",js)
        self.assertIn('id="routeDiagnostic"',html)
        self.assertIn('public_ingress', (Path(__file__).resolve().parents[1]/'app'/'diagnostics.py').read_text())
        self.assertNotIn('192.168.50.150 https://${r.domain}',js)  # Generic tool, not hardcoded to the test container.

if __name__ == '__main__':
    unittest.main()
