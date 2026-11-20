# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Bind-IP, socket conflicts, legacy SQLite migration, live and staged deploy."""
from __future__ import annotations
import json
import os
import socket
import sqlite3
import subprocess
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.engine import render_stream, render_http
from app.validation import StreamInput
from app.port_binding import (normalize_bind_ip, overlaps, assert_assigned, assert_bindings,
                              rules_conflicts, find_live_conflicts, parse_managed_listeners,
                              local_addresses, RESERVED_TCP)
from app import db, deploy_safety


def row(ip='0.0.0.0',proto='tcp',port=25,label='SMTP',enabled=True):
    return {'id':'a','label':label,'protocol':proto,'listen_port':port,'bind_ip':ip,
            'target_host':'192.0.2.236','target_port':25,'timeout_seconds':300,'enabled':enabled}


class BindingModel(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_bind_ip(None),'0.0.0.0')
        self.assertEqual(normalize_bind_ip('ALL'),'0.0.0.0')
        self.assertEqual(normalize_bind_ip('2001:0db8::1'),'2001:db8::1')
        for val in ('192.0.2.150; include /etc/passwd','bad.name','127.0.0.1\nlisten 80','[::1]','10.0.0.1 '):
            with self.subTest(val=val),self.assertRaises(ValueError):normalize_bind_ip(val)

    def test_validation_defaults(self):
        self.assertEqual(StreamInput(**{k:v for k,v in row().items() if k!='bind_ip'}).bind_ip,'0.0.0.0')
        self.assertEqual(StreamInput(**row(ip='::1')).bind_ip,'::1')

    def test_render_legacy_wildcard(self):
        config=render_stream([row()])
        self.assertIn('listen 25;',config)
        self.assertNotIn('listen 0.0.0.0:25;',config)

    def test_ipv4_ipv6_render(self):
        self.assertIn('listen 192.0.2.150:25;',render_stream([row(ip='192.0.2.150')]))
        self.assertIn('listen [2001:db8::1]:25;',render_stream([row(ip='2001:db8::1')]))
        self.assertIn('listen 192.0.2.150:53 udp;',render_stream([row(ip='192.0.2.150',proto='udp',port=53)]))

    def test_bind_overlaps(self):
        self.assertTrue(overlaps('0.0.0.0','127.0.0.1'))
        self.assertFalse(overlaps('127.0.0.1','192.0.2.150'))
        self.assertFalse(overlaps('2001:db8::1','192.0.2.150'))
        self.assertTrue(overlaps('::','192.0.2.150'))  # conservative dual stack
        self.assertTrue(overlaps('::1','::1'))

    def test_different_specific_ips_same_port_allowed(self):
        a=row(ip='192.0.2.150');b=row(ip='192.0.2.151',label='Other');b['id']='b'
        self.assertFalse(rules_conflicts([a,b]))
        self.assertEqual(render_stream([a,b]).count('proxy_pass'),2)

    def test_wildcard_overlap_rejected(self):
        a=row(); b=row(ip='192.0.2.150',label='Other');b['id']='b'
        self.assertTrue(rules_conflicts([a,b]))
        with self.assertRaisesRegex(ValueError,'ueberschneiden'):render_stream([a,b])

    def test_udp_independent_tcp(self):
        a=row();b=row(proto='udp',label='UDP');b['id']='b'
        self.assertFalse(rules_conflicts([a,b]))

    def test_disabled_not_reserved(self):
        self.assertIn('stream {',render_stream([row(port=443,enabled=False)]))
        for port in RESERVED_TCP:
            with self.assertRaises(ValueError):render_stream([row(port=port)])

    def test_assigned_ip(self):
        available=[{'address':'127.0.0.1','interface':'lo'}]
        self.assertEqual(assert_assigned('127.0.0.1',available),'127.0.0.1')
        self.assertEqual(assert_assigned('0.0.0.0',available),'0.0.0.0')
        with self.assertRaisesRegex(ValueError,'nicht auf einer lokalen'):
            assert_assigned('192.0.2.150',available)

    def test_legacy_upgrade_preserves_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            dbfile=root/'rpmgr.sqlite3'
            con=sqlite3.connect(dbfile)
            con.execute('''CREATE TABLE streams(id TEXT PRIMARY KEY,label TEXT NOT NULL,protocol TEXT NOT NULL,
                 listen_port INTEGER NOT NULL,target_host TEXT NOT NULL,target_port INTEGER NOT NULL,
                 timeout_seconds INTEGER DEFAULT 300,enabled INTEGER DEFAULT 1,
                 created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(protocol,listen_port))''')
            con.execute("INSERT INTO streams(id,label,protocol,listen_port,target_host,target_port) VALUES('old','SMTP','tcp',25,'192.0.2.236',25)")
            con.commit();con.close()
            with patch.object(db,'BASE',root),patch.object(db,'DB',dbfile),patch.object(db,'CERTS',root/'certs'),patch.object(db,'DEPLOY',root/'deploy'),patch.object(db,'ACME',root/'acme'):
                db.init_db()
                db.init_db()
                con=db.connect()
                existing=con.execute('SELECT * FROM streams').fetchone()
                self.assertEqual(existing['id'],'old')
                self.assertEqual(existing['bind_ip'],'0.0.0.0')
                self.assertEqual(existing['target_host'],'192.0.2.236')
                con.execute('INSERT INTO streams(id,label,protocol,listen_port,bind_ip,target_host,target_port) VALUES(?,?,?,?,?,?,?)',
                            ('new','Other','tcp',25,'192.0.2.150','192.0.2.75',18087))
                con.commit()
                self.assertEqual(con.execute('SELECT count(*) FROM streams').fetchone()[0],2)
                self.assertTrue(con.execute("SELECT name FROM sqlite_master WHERE name='deploy_history'").fetchone())
                con.close()


class LiveConflict(unittest.TestCase):
    def test_postfix_loopback_allows_lan(self):
        sockets=[{'protocol':'tcp','bind_ip':'127.0.0.1','port':25,'pid':444,'process':'postfix'},
                 {'protocol':'tcp','bind_ip':'::1','port':25,'pid':444,'process':'postfix'}]
        result=find_live_conflicts([row(ip='192.0.2.150')],sockets=sockets,managed=set())
        self.assertEqual(result['conflicts'],[])
        self.assertEqual(assert_bindings([row(ip='192.0.2.150')],sockets=sockets,managed=set(),available=[{'address':'192.0.2.150'}])['conflicts'],[])

    def test_postfix_wildcard_conflicts(self):
        sock={'protocol':'tcp','bind_ip':'127.0.0.1','port':25,'pid':444,'process':'postfix'}
        with self.assertRaisesRegex(ValueError,'postfix'):
            assert_bindings([row()],sockets=[sock],managed=set(),available=[])

    def test_existing_managed_nginx_is_warning(self):
        sockets=[{'protocol':'tcp','bind_ip':'0.0.0.0','port':25,'pid':333,'process':'nginx'}]
        result=find_live_conflicts([row(ip='192.0.2.150')],sockets=sockets,managed={('tcp',25,'0.0.0.0')})
        self.assertEqual(result['conflicts'],[])
        self.assertTrue(result['warnings'])

    def test_unmanaged_nginx_is_blocked(self):
        sockets=[{'protocol':'tcp','bind_ip':'0.0.0.0','port':25,'pid':333,'process':'nginx'}]
        result=find_live_conflicts([row(ip='192.0.2.150')],sockets=sockets,managed=set())
        self.assertTrue(result['conflicts'])

    def test_protocol_separated(self):
        sockets=[{'protocol':'tcp','bind_ip':'0.0.0.0','port':53,'pid':333,'process':'named'}]
        self.assertFalse(find_live_conflicts([row(ip='0.0.0.0',proto='udp',port=53)],sockets=sockets,managed=set())['conflicts'])

    def test_read_current_nginx(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'stream.conf'
            path.write_text('''stream {
 server {
    listen 192.0.2.150:25;
    proxy_pass 192.0.2.236:25;}
 server {
    listen 53 udp;
    proxy_pass 192.0.2.236:53; }
 server {
    listen [2001:db8::1]:993;
    proxy_pass 192.0.2.236:993; } }''')
            result=parse_managed_listeners(path)
            self.assertIn(('tcp',25,'192.0.2.150'),result)
            self.assertIn(('udp',53,'0.0.0.0'),result)
            self.assertIn(('tcp',993,'2001:db8::1'),result)


class SafeDeployment(unittest.TestCase):
    def test_version_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(deploy_safety,'VERSIONS',Path(tmp)/'versions'):
            v=deploy_safety.create_version({'http':b'abc','stream':b'def','fallback':None},request_id='test')
            self.assertEqual(deploy_safety.get_version(v)['http'],b'abc')
            self.assertEqual(deploy_safety.get_version(v)['stream'],b'def')
            self.assertEqual(deploy_safety.get_version(v)['fallback'],None)
            with self.assertRaises(ValueError):deploy_safety.get_version('../passwd')

    def test_runtime_check_exact_ip(self):
        sock={'protocol':'tcp','port':25,'bind_ip':'0.0.0.0','process':'nginx','pid':10}
        missing=deploy_safety.verify_listeners([row(ip='192.0.2.150')],sockets=[sock],check_http=False)
        self.assertIn('TCP 192.0.2.150:25',missing)
        self.assertEqual(deploy_safety.verify_listeners([row(ip='0.0.0.0')],sockets=[sock],check_http=False),[])

    def test_reload_does_not_count_as_success_without_listeners(self):
        with patch.object(deploy_safety,'nginx_supervisor_running',return_value=True),\
             patch.object(deploy_safety,'verify_listeners',return_value=['TCP 192.0.2.150:25']),\
             patch.object(deploy_safety,'errors_since',return_value=''):
            with self.assertRaisesRegex(RuntimeError,'nicht geoeffnet'):
                deploy_safety.post_reload_status([row()])

    def test_reload_detects_bind_error(self):
        with patch.object(deploy_safety,'nginx_supervisor_running',return_value=True),\
             patch.object(deploy_safety,'verify_listeners',return_value=[]),\
             patch.object(deploy_safety,'errors_since',return_value='bind() failed: Address already in use'):
            with self.assertRaisesRegex(RuntimeError,'Bind-Fehler'):
                deploy_safety.post_reload_status([row()])

    def test_reload_new_generation_required(self):
        with patch.object(deploy_safety,'nginx_supervisor_running',return_value=True),\
             patch.object(deploy_safety,'nginx_worker_pids',return_value={20}),\
             patch.object(deploy_safety,'verify_listeners',return_value=[]),\
             patch.object(deploy_safety,'errors_since',return_value=''),\
             patch.object(deploy_safety.time,'sleep',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'ohne neue Worker'):
                deploy_safety.post_reload_status([],before_workers={20})

    def test_error_log_offset(self):
        with tempfile.TemporaryDirectory() as tmp:
            log=Path(tmp)/'error.log';log.write_text('old stuff\n')
            offset=deploy_safety.log_offset(log)
            with open(log,'a') as f:f.write('2026/11/20 [emerg] bind() 0.0.0.0:25 failed (98: Address already in use)\n')
            self.assertIn('bind()',deploy_safety.errors_since(offset,log))
            self.assertFalse(deploy_safety.errors_since(log.stat().st_size,log))

    def test_staged_nginx_syntax(self):
        if not Path('/usr/sbin/nginx').exists():self.skipTest('nginx missing')
        with tempfile.TemporaryDirectory() as tmp,patch.object(deploy_safety,'DEPLOY',Path(tmp)):
            root=Path(tmp)
            cert=root/'admin.crt';key=root/'admin.key'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                            '-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost'],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
            http=render_http([],[]).replace('/etc/rpmgr/admin.crt',str(cert)).replace('/etc/rpmgr/admin.key',str(key))          
            http = re.sub(r'(\blisten\s+)80(?=[\s;])', r'\g<1>18080', http)
            http = re.sub(r'(\blisten\s+)443(?=[\s;])', r'\g<1>18443', http)
            # Test works with port 80/443 because nginx -t is syntax only.
            report=deploy_safety.stage_test(http,render_stream([]))
            self.assertTrue(report['syntax_ok'])
            self.assertEqual(len(report['http_sha256']),64)
            with self.assertRaises(RuntimeError):deploy_safety.stage_test(http+'\ninvalid_directive here;',render_stream([]))


if __name__=='__main__':unittest.main()
