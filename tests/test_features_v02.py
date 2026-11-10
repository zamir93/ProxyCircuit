# ProxyCircuit v0.2.0 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Regression tests for roles, migration, bulk changes, certificate renewal and diagnostics."""
import contextlib
import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

os.environ['RPMGR_DEV'] = '1'

from fastapi.testclient import TestClient
from app import db, main, worker
from app.security import hash_password
from app.diagnostics import probe_upstream


class FeaturesTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='pc-features-')
        base=Path(self.temp.name)
        self.base=base
        self.stack=contextlib.ExitStack()
        for module,key,value in (
            (db,'BASE',base),(db,'DB',base/'db.sqlite3'),(db,'CERTS',base/'certs'),
            (db,'DEPLOY',base/'deploy'),(db,'ACME',base/'acme'),
            (main,'DEPLOY',base/'deploy'),(worker,'CERTS',base/'certs'),
        ):
            self.stack.enter_context(patch.object(module,key,value))
        db.init_db()
        con=db.connect()
        with con:
            con.execute('INSERT INTO admins(username,password_hash) VALUES(?,?)',
                        ('admin',hash_password('super-secret-password')))
        con.close()
        self.client=TestClient(main.app,base_url='https://localhost:9443')
        self.client.__enter__()
        login=self.client.post('/api/login',json={'username':'admin','password':'super-secret-password'})
        self.assertEqual(login.status_code,200,login.text)
        self.token=login.json()['csrf']

    def tearDown(self):
        self.client.__exit__(None,None,None)
        self.stack.close()
        self.temp.cleanup()

    def call(self,method,path,payload=None,client=None,token=None):
        return (client or self.client).request(method,'/api'+path,
                  json=payload,headers={'X-CSRF-Token':token or self.token})

    def add_host(self,domain,**extra):
        values={'domain':domain,'upstream_scheme':'http','upstream_host':'10.0.0.1','upstream_port':80,**extra}
        res=self.call('POST','/hosts',values)
        self.assertEqual(res.status_code,200,res.text)
        return res.json()['result']

    def test_00_http_proxy_login_rejected_by_backend(self):
        response=self.client.post('/api/login',
            json={'username':'admin','password':'super-secret-password'},
            headers={'X-Forwarded-Proto':'http'})
        self.assertEqual(response.status_code,403,response.text)
        self.assertEqual(self.client.get('/api/me').status_code,200)

    def test_01_users_roles_permission(self):
        r=self.call('POST','/users',{'username':'reader','password':'pass-reader-123','role':'viewer'})
        self.assertEqual(r.status_code,200,r.text)
        r=self.call('POST','/users',{'username':'staff','password':'pass-staff-123','role':'editor'})
        self.assertEqual(r.status_code,200,r.text)
        viewer=TestClient(main.app,base_url='https://localhost:9443')
        editor=TestClient(main.app,base_url='https://localhost:9443')
        r=viewer.post('/api/login',json={'username':'reader','password':'pass-reader-123'})
        self.assertEqual(r.json()['role'],'viewer')
        vcsrf=r.json()['csrf']
        r=editor.post('/api/login',json={'username':'staff','password':'pass-staff-123'})
        self.assertEqual(r.json()['role'],'editor')
        ecsrf=r.json()['csrf']
        self.assertEqual(viewer.get('/api/hosts').status_code,200)
        self.assertEqual(viewer.get('/api/users').status_code,403)
        self.assertEqual(self.call('POST','/hosts',{'domain':'x.example.org','upstream_host':'10.0.0.3','upstream_port':80},viewer,vcsrf).status_code,403)
        self.assertEqual(self.call('POST','/hosts',{'domain':'x.example.org','upstream_host':'10.0.0.3','upstream_port':80},editor,ecsrf).status_code,200)
        self.assertEqual(self.call('POST','/users',{'username':'other','password':'secret-1234'},editor,ecsrf).status_code,403)
        self.assertEqual(self.call('POST','/deploy',{},viewer,vcsrf).status_code,403)
        self.assertEqual(self.call('POST','/hosts',{'domain':'x2.example.org','upstream_host':'10.0.0.3','upstream_port':80},viewer,'bad-csrf').status_code,403)
        # Sessions for the same user are independent; concurrent logins do not log each other out.
        second=TestClient(main.app,base_url='https://localhost:9443')
        r=second.post('/api/login',json={'username':'reader','password':'pass-reader-123'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(second.get('/api/me').status_code,200)
        self.assertEqual(viewer.get('/api/me').status_code,200)
        self.assertEqual(self.call('DELETE','/users/reader').status_code,200)
        self.assertEqual(viewer.get('/api/me').status_code,401)
        self.assertEqual(second.get('/api/me').status_code,401)

    def test_02_last_admin_guard_and_password_reset(self):
        self.assertEqual(self.call('PUT','/users/admin',{'role':'viewer','active':True}).status_code,409)
        self.assertEqual(self.call('DELETE','/users/admin').status_code,409)
        self.assertEqual(self.call('POST','/users',{'username':'spare','password':'password-888','role':'admin'}).status_code,200)
        self.assertEqual(self.call('PUT','/users/spare',{'role':'viewer','active':True}).status_code,200)
        self.assertEqual(self.call('POST','/users/spare/password',{'password':'password-999'}).status_code,200)
        bad=TestClient(main.app,base_url='https://localhost:9443')
        self.assertEqual(bad.post('/api/login',json={'username':'spare','password':'password-888'}).status_code,401)
        self.assertEqual(bad.post('/api/login',json={'username':'spare','password':'password-999'}).status_code,200)

    def test_03_bulk_selection_categories_and_atomicity(self):
        first=self.add_host('abc.example.org',category='Kunden')
        second=self.add_host('def.example.org')
        r=self.call('POST','/hosts/bulk',{'ids':[first,second],'action':'categorize','category':'Projekte'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual({x['category'] for x in self.client.get('/api/hosts').json()}, {'Projekte'})
        self.assertEqual(self.call('POST','/hosts/bulk',{'ids':[first,second],'action':'disable'}).status_code,200)
        self.assertEqual({x['enabled'] for x in self.client.get('/api/hosts').json()}, {0})
        self.assertEqual(self.call('POST','/hosts/bulk',{'ids':[first,second],'action':'enable'}).status_code,200)
        self.assertEqual(self.call('POST','/hosts/bulk',{'ids':[first,first],'action':'delete'}).status_code,422)
        self.assertEqual(self.call('POST','/hosts/bulk',{'ids':[first,'f'*16],'action':'delete'}).status_code,404)
        self.assertEqual(len(self.client.get('/api/hosts').json()),2)
        self.assertEqual(self.call('POST','/hosts/bulk',{'ids':[first,second],'action':'delete'}).status_code,200)
        self.assertEqual(len(self.client.get('/api/hosts').json()),0)

    def test_04_shared_certificate_not_destroyed(self):
        cert_id='c'*16
        con=db.connect()
        with con:
            con.execute('INSERT INTO certificates(id,label,domain,kind,status,fullchain_path,privkey_path) VALUES(?,?,?,?,?,?,?)',
                        (cert_id,'Wildcard','*.example.org','manual','ready','/var/lib/rpmgr/certs/'+cert_id+'/fullchain.pem',
                         '/var/lib/rpmgr/certs/'+cert_id+'/privkey.pem'))
        con.close()
        x=self.add_host('api.example.org',certificate_id=cert_id)
        y=self.add_host('store.example.org',certificate_id=cert_id)
        r=self.call('POST','/hosts/bulk',{'ids':[x],'action':'delete','delete_certificates':True})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['result']['certificates_kept_shared'],1)
        self.assertEqual(len(self.client.get('/api/certificates').json()),1)
        r=self.call('POST','/hosts/bulk',{'ids':[y],'action':'delete','delete_certificates':True})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['result']['certificates_removed'],1)
        self.assertEqual(len(self.client.get('/api/certificates').json()),0)
        con=db.connect()
        self.assertEqual(con.execute('SELECT COUNT(*) FROM certificate_cleanup').fetchone()[0],1)
        con.close()

    def test_05_acme_renewal_jobs(self):
        cert_id='d'*16
        con=db.connect()
        with con:
            con.execute('INSERT INTO certificates(id,label,domain,kind,status,fullchain_path,privkey_path) VALUES(?,?,?,?,?,?,?)',
                        (cert_id,'ACME','app.example.org','acme','ready','/etc/letsencrypt/live/rpmgr-'+cert_id+'/fullchain.pem',
                         '/etc/letsencrypt/live/rpmgr-'+cert_id+'/privkey.pem'))
            con.execute('INSERT INTO certificate_jobs(id,cert_id,domain,email,status) VALUES(?,?,?,?,?)',
                        ('e'*16,cert_id,'app.example.org','admin@example.org','done'))
        con.close()
        self.add_host('app.example.org',certificate_id=cert_id)
        result=self.call('POST','/certificates/'+cert_id+'/renew')
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['result']['state'],'queued')
        self.assertEqual(self.call('POST','/certificates/'+cert_id+'/renew').status_code,409)
        con=db.connect()
        row=con.execute("SELECT * FROM certificate_jobs WHERE status='pending'").fetchone()
        self.assertEqual(row['operation'],'renew')
        con.close()

    def test_06_manual_cannot_auto_renew(self):
        con=db.connect()
        with con:
            con.execute('INSERT INTO certificates(id,label,domain,kind,status) VALUES(?,?,?,?,?)',
                        ('a'*16,'Manual','manual.example.org','manual','ready'))
        con.close()
        self.assertEqual(self.call('POST','/certificates/'+'a'*16+'/renew').status_code,422)

    def test_07_cleanup_only_in_managed_cert_folder(self):
        cert_id='f'*16
        folder=self.base/'certs'/cert_id
        folder.mkdir(parents=True)
        (folder/'fullchain.pem').write_text('crt')
        (folder/'privkey.pem').write_text('key')
        con=db.connect()
        with con:
            con.execute('INSERT INTO certificate_cleanup(id,kind,fullchain_path,privkey_path) VALUES(?,?,?,?)',
                        (cert_id,'manual',str(folder/'fullchain.pem'),str(folder/'privkey.pem')))
        worker.cleanup_unused_certificates(con)
        self.assertFalse(folder.exists())
        self.assertEqual(con.execute('SELECT COUNT(*) FROM certificate_cleanup').fetchone()[0],0)
        con.close()

    def test_10_replace_imported_pem_certificate(self):
        import subprocess
        folder=self.base/'generated'
        folder.mkdir()
        cert_path,key_path=folder/'cert.pem',folder/'key.pem'
        result=subprocess.run(['openssl','req','-x509','-nodes','-newkey','rsa:2048',
                               '-days','2','-keyout',str(key_path),'-out',str(cert_path),
                               '-subj','/CN=app.example.org','-addext','subjectAltName=DNS:app.example.org'],
                              capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        cert_id='2'*16
        con=db.connect()
        with con:
            con.execute('INSERT INTO certificates(id,label,domain,kind,status) VALUES(?,?,?,?,?)',
                        (cert_id,'Imported','app.example.org','manual','ready'))
        con.close()
        r=self.call('POST','/certificates/'+cert_id+'/replace',{
            'fullchain_pem':cert_path.read_text(), 'private_key_pem':key_path.read_text()})
        self.assertEqual(r.status_code,200,r.text)
        con=db.connect()
        row=con.execute('SELECT * FROM certificates WHERE id=?',(cert_id,)).fetchone()
        self.assertTrue(Path(row['fullchain_path']).is_file())
        self.assertTrue(Path(row['privkey_path']).is_file())
        self.assertEqual(row['status'],'ready')
        con.close()

    def test_11_failed_renewal_preserves_valid_certificate(self):
        from unittest.mock import patch
        from subprocess import CompletedProcess
        cert_id='3'*16
        con=db.connect()
        with con:
            con.execute('INSERT INTO certificates(id,label,domain,kind,status,fullchain_path,privkey_path) VALUES(?,?,?,?,?,?,?)',
                        (cert_id,'LetsEncrypt','app.example.org','acme','ready','/original/fullchain.pem','/original/key.pem'))
            con.execute("INSERT INTO certificate_jobs(id,cert_id,domain,email,operation,status) VALUES(?,?,?,?,?,'pending')",
                        ('4'*16,cert_id,'app.example.org','ops@example.org','renew'))
        with patch.object(worker,'cmd',return_value=CompletedProcess(['certbot'],1,'','ACME failed')):
            errors=worker.issue_jobs(con)
        self.assertTrue(errors)
        self.assertEqual(con.execute('SELECT status FROM certificates WHERE id=?',(cert_id,)).fetchone()[0],'ready')
        self.assertEqual(con.execute('SELECT status FROM certificate_jobs WHERE id=?',('4'*16,)).fetchone()[0],'error')
        con.close()

    def test_12_upstream_host_header_and_injection_protection(self):
        from app.engine import render_http
        host={'domain':'app.example.org','upstream_scheme':'https','upstream_host':'192.168.50.236',
              'upstream_port':443,'upstream_tls_name':'internal.example.org',
              'upstream_host_header':'internal.example.org','websocket':True,
              'force_https':False,'certificate_id':None,'enabled':True}
        config=render_http([host],[])
        self.assertIn('proxy_set_header Host internal.example.org;',config)
        self.assertIn('proxy_ssl_name internal.example.org;',config)
        host['upstream_host_header']='evil.org\nreturn 200;'
        with self.assertRaises(ValueError):render_http([host],[])

    def test_13_healthchecks_all_hosts(self):
        # The earlier beta used LIMIT 60; the new monitor covers every active host.
        from unittest.mock import patch
        con=db.connect()
        with con:
            con.executemany('INSERT INTO hosts(id,domain,upstream_scheme,upstream_host,upstream_port,enabled) VALUES(?,?,?,?,?,1)',
                            [(f'{i:016x}',f'host{i}.example.org','http','127.0.0.1',80) for i in range(75)])
        con.close()
        with patch('app.diagnostics.probe_upstream',return_value={'state':'online','http_status':200,'message':'ok'}):
            r=self.client.get('/api/healthchecks')
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(len(r.json()),75)

    def test_08_http_get_probe_and_udp_detection(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location','/login')
                self.end_headers()
            def log_message(self,*args):
                return
        server=HTTPServer(('127.0.0.1',0),Handler)
        t=threading.Thread(target=server.serve_forever,daemon=True)
        t.start()
        try:
            d={'domain':'api.example.org','upstream_host':'127.0.0.1','upstream_scheme':'http','upstream_port':server.server_port}
            r=probe_upstream(d)
            self.assertEqual(r['code'],'HTTP_OK')
            self.assertEqual(r['http_status'],302)
            r=probe_upstream({'domain':'ts.example.org','upstream_host':'127.0.0.1','upstream_scheme':'http','upstream_port':9987})
            self.assertEqual(r['code'],'UDP_AS_HTTP')
            self.assertIn('UDP',r['message'])
        finally:
            server.shutdown();server.server_close()


class LegacySchemaMigrationTest(unittest.TestCase):
    def test_09_migration_existing_users_hosts_and_jobs(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)
            con=sqlite3.connect(str(base/'legacy.sqlite3'))
            con.executescript('''CREATE TABLE admins(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,created_at TEXT);
                CREATE TABLE hosts(id TEXT PRIMARY KEY,domain TEXT UNIQUE NOT NULL,
                upstream_scheme TEXT NOT NULL,upstream_host TEXT NOT NULL,upstream_port INTEGER NOT NULL,
                websocket INTEGER DEFAULT 1,force_https INTEGER DEFAULT 0,certificate_id TEXT,
                enabled INTEGER DEFAULT 1,created_at TEXT);
                CREATE TABLE certificate_jobs(id TEXT PRIMARY KEY,cert_id TEXT,domain TEXT,email TEXT,
                status TEXT,error TEXT,created_at TEXT);
                INSERT INTO admins VALUES('admin','existing-hash','2026-10-01');
                INSERT INTO hosts(id,domain,upstream_scheme,upstream_host,upstream_port,enabled)
                VALUES('aaaa','example.org','http','10.0.0.10',80,1);''')
            con.commit();con.close()
            with contextlib.ExitStack() as stack:
                for module,key,value in ((db,'BASE',base),(db,'DB',base/'legacy.sqlite3'),
                        (db,'CERTS',base/'certs'),(db,'DEPLOY',base/'deploy'),(db,'ACME',base/'acme')):
                    stack.enter_context(patch.object(module,key,value))
                db.init_db();db.init_db()
                con=db.connect()
                self.assertEqual(con.execute("SELECT role,active FROM admins WHERE username='admin'").fetchone()[:],('admin',1))
                row=con.execute("SELECT category,upstream_tls_name FROM hosts WHERE domain='example.org'").fetchone()
                self.assertEqual(row['category'],'')
                self.assertIsNone(row['upstream_tls_name'])
                self.assertIn('operation',[r[1] for r in con.execute('PRAGMA table_info(certificate_jobs)')])
                con.close()


if __name__=='__main__':
    unittest.main()
