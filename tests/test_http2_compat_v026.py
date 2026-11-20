# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Regression tests for modern and legacy NGINX HTTP/2 syntax."""
import unittest
from unittest.mock import patch
from app import engine


class HTTP2CompatibilityTests(unittest.TestCase):
    def test_modern_and_legacy_generated_configs(self):
        host = dict(domain='example.org', upstream_host='192.0.2.10', upstream_port=8080,
                    upstream_scheme='http', websocket=0, force_https=0,
                    certificate_id='cert-1', enabled=True)
        cert = dict(id='cert-1', status='ready', domain='example.org',
                    fullchain_path='/tmp/demo-fullchain.pem', privkey_path='/tmp/demo-privkey.pem')
        for supports_new, expected_default, expected_host in (
            (True, 'listen 443 ssl default_server;\n    http2 on;',
             'listen 443 ssl;\n    http2 on;'),
            (False, 'listen 443 ssl http2 default_server;',
             'listen 443 ssl http2;'),
        ):
            with self.subTest(modern=supports_new):
                with patch.object(engine, 'nginx_supports_http2_directive',return_value=supports_new):
                    output = engine.render_http([host], [cert])
                self.assertIn(expected_default, output)
                self.assertIn(expected_host, output)
                self.assertEqual(output.count('http2 on;' if supports_new else 'ssl http2'),2)

    def test_nginx_version_parsing_and_compatibility_fallback(self):
        from subprocess import CompletedProcess, TimeoutExpired
        for version, expected in [('1.24.0',False), ('1.25.0',False),
                                  ('1.25.1',True), ('1.26.3',True), ('1.28.0',True)]:
            with self.subTest(version=version):
                with patch.object(engine.subprocess,'run',return_value=CompletedProcess(
                     ['nginx','-v'],0,'',f'nginx version: nginx/{version}')):
                    engine.nginx_supports_http2_directive.cache_clear()
                    self.assertEqual(engine.nginx_supports_http2_directive(),expected)
        with patch.object(engine.subprocess,'run',side_effect=TimeoutExpired('nginx',3)):
            engine.nginx_supports_http2_directive.cache_clear()
            self.assertFalse(engine.nginx_supports_http2_directive())
        engine.nginx_supports_http2_directive.cache_clear()

if __name__ == '__main__':
    unittest.main()
