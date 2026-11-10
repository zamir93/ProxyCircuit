# ProxyCircuit v0.2.0 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
import os
import tempfile
from pathlib import Path
TESTDIR=tempfile.TemporaryDirectory()
os.environ['RPMGR_DATA_DIR']=TESTDIR.name
os.environ['RPMGR_ACME_DIR']=TESTDIR.name+'/acme'
os.environ['RPMGR_PLUGINS']=TESTDIR.name+'/plugins'
os.environ['RPMGR_DEV']='1'
from fastapi.testclient import TestClient
from app.db import init_db, connect
from app.security import hash_password
from app.main import app
import unittest

class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        con=connect();con.execute('INSERT OR REPLACE INTO admins(username,password_hash) VALUES(?,?)',('admin',hash_password('one-very-secure-password')));con.commit();con.close()
        cls.client=TestClient(app,base_url='https://localhost:9443')
        cls.client.__enter__()
        result=cls.client.post('/api/login',json={'username':'admin','password':'one-very-secure-password'})
        assert result.status_code==200,result.text
        cls.csrf=result.json()['csrf']
    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None,None,None)
        TESTDIR.cleanup()
    def test_01_auth_rejects_unauthenticated(self):
        other=TestClient(app,base_url='https://localhost:9443')
        self.assertEqual(other.get('/api/hosts').status_code,401)
        self.assertEqual(self.client.post('/api/hosts',json={'domain':'test.example.de','upstream_host':'10.0.0.2','upstream_port':8000}).status_code,403)
    def test_02_hosts_crud(self):
        d={'domain':'app.example.de','upstream_host':'10.0.0.50','upstream_port':8080,'upstream_scheme':'http'}
        r=self.client.post('/api/hosts',json=d,headers={'X-CSRF-Token':self.csrf});self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['deployment']['state'],'dry-run (RPMGR_DEV=1)')
        uid=r.json()['result']
        r=self.client.post('/api/hosts',json=d,headers={'X-CSRF-Token':self.csrf});self.assertEqual(r.status_code,409)
        r=self.client.put('/api/hosts/'+uid,json={**d,'upstream_scheme':'https','upstream_tls_name':'proxycircuit.local','upstream_port':8088},headers={'X-CSRF-Token':self.csrf});self.assertEqual(r.status_code,200,r.text)
        r=self.client.get('/api/hosts');self.assertEqual(r.json()[0]['upstream_port'],8088);self.assertEqual(r.json()[0]['upstream_tls_name'],'proxycircuit.local')
        self.assertEqual(self.client.delete('/api/hosts/'+uid,headers={'X-CSRF-Token':self.csrf}).status_code,200)
    def test_03_stream_crud(self):
        d={'label':'SSH','protocol':'tcp','listen_port':2222,'target_host':'10.0.0.50','target_port':22}
        r=self.client.post('/api/streams',json=d,headers={'X-CSRF-Token':self.csrf});self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.post('/api/streams',json=d,headers={'X-CSRF-Token':self.csrf}).status_code,409)
        self.assertEqual(self.client.post('/api/streams',json={**d,'listen_port':443},headers={'X-CSRF-Token':self.csrf}).status_code,422)
        self.assertEqual(self.client.delete('/api/streams/'+r.json()['result'],headers={'X-CSRF-Token':self.csrf}).status_code,200)
    def test_04_certificates_need_host(self):
        r=self.client.post('/api/certificates/issue',json={'domain':'app.example.de','email':'ops@example.de'},headers={'X-CSRF-Token':self.csrf})
        self.assertEqual(r.status_code,422)
    def test_05_dashboard_and_export(self):
        self.assertEqual(self.client.get('/api/summary').status_code,200)
        self.assertEqual(self.client.get('/api/export').json()['format'],'rpmgr-config-v1')
        self.assertEqual(self.client.get('/static/app.js').status_code,200)
        self.assertEqual(self.client.get('/').status_code,200)
        self.assertEqual(self.client.get('/favicon.ico').status_code,200)
        self.assertIn("style-src 'self'",self.client.get('/').headers['Content-Security-Policy'])

    def test_06_default_page_read_save_reset(self):
        r=self.client.get('/api/default-page')
        self.assertEqual(r.status_code,200,r.text)
        self.assertFalse(r.json()['customized'])
        self.assertIn('AfghanHost',r.json()['html'])
        page='<html><body><h1>Unser System ist gerade nicht erreichbar.</h1></body></html>'
        blocked=self.client.put('/api/default-page',json={'html':page})
        self.assertEqual(blocked.status_code,403)
        r=self.client.put('/api/default-page',json={'html':page},headers={'X-CSRF-Token':self.csrf})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.get('/api/default-page').json()['html'],page)
        self.assertTrue(self.client.get('/api/default-page').json()['customized'])
        r=self.client.put('/api/default-page',json={'html':'<html><script>alert(1)</script></html>'},headers={'X-CSRF-Token':self.csrf})
        self.assertEqual(r.status_code,422)
        self.assertEqual(self.client.get('/api/default-page').json()['html'],page)
        r=self.client.post('/api/default-page/reset',json={},headers={'X-CSRF-Token':self.csrf})
        self.assertEqual(r.status_code,200,r.text)
        self.assertFalse(self.client.get('/api/default-page').json()['customized'])

if __name__=='__main__':unittest.main()
