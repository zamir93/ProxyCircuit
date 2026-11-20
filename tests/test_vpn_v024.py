# ProxyCircuit v0.2.4 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""VPN database/API, RBAC, strict routing, no secret distribution and gateway tests."""
import base64
import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import db,main,vpn
from app.security import hash_password
from tools.wireguard_gateway import load_plan, render_hub, render_spoke, write_conf, read_private_key

PUB_H=base64.b64encode(bytes(range(1,33))).decode()
PUB_S=base64.b64encode(bytes(range(33,65))).decode()
PUB_T=base64.b64encode(bytes(range(70,102))).decode()

class VPNTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='pc-vpn-test-')
        self.base=Path(self.tmp.name)
        self.stack=contextlib.ExitStack()
        for obj,attr,value in ((db,'BASE',self.base),(db,'DB',self.base/'db.sqlite3'),
               (db,'CERTS',self.base/'certs'),(db,'DEPLOY',self.base/'deploy'),
               (db,'ACME',self.base/'acme'),(main,'DEPLOY',self.base/'deploy')):
            self.stack.enter_context(patch.object(obj,attr,value))
        db.init_db()
        db.init_db() # migration is idempotent
        with db.connect() as con:
            con.execute('INSERT INTO admins(username,password_hash) VALUES(?,?)',('admin',hash_password('very-strong-password')))
            con.execute('INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)',('reader',hash_password('viewer-strong-pass'),'viewer'))
        self.client=TestClient(main.app,base_url='https://localhost:9443')
        self.client.__enter__()
        resp=self.client.post('/api/login',json={'username':'admin','password':'very-strong-password'})
        assert resp.status_code==200,resp.text
        self.csrf=resp.json()['csrf']

    def tearDown(self):
        self.client.__exit__(None,None,None)
        self.stack.close();self.tmp.cleanup()

    def req(self,method,url,data=None,csrf=True):
        return self.client.request(method,url,json=data,headers={'X-CSRF-Token':self.csrf} if csrf else {})

    def add_site(self,name='Remote A',pub=PUB_S,tunnel='10.77.77.2'):
        r=self.req('POST','/api/vpn/sites',{'name':name,'public_key':pub,'tunnel_ip':tunnel,
                                         'endpoint_host':'vpn.remote.example','endpoint_port':51820,'keepalive':25})
        self.assertEqual(r.status_code,200,r.text)
        return r.json()['result']

    def add_route(self,sid,cidr='192.168.20.0/24'):
        r=self.req('POST',f'/api/vpn/sites/{sid}/routes',{'cidr':cidr})
        self.assertEqual(r.status_code,200,r.text)
        return r.json()['result']

    def test_00_auth_csrf_and_rbac(self):
        naked=TestClient(main.app,base_url='https://localhost:9443')
        self.assertEqual(naked.get('/api/vpn/overview').status_code,401)
        self.assertEqual(naked.get('/api/vpn/export').status_code,401)
        self.assertEqual(self.req('PUT','/api/vpn/hub',{},csrf=False).status_code,403)
        viewer=TestClient(main.app,base_url='https://localhost:9443')
        r=viewer.post('/api/login',json={'username':'reader','password':'viewer-strong-pass'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(viewer.get('/api/vpn/overview').status_code,200)
        self.assertEqual(viewer.get('/api/vpn/export').status_code,403)
        self.assertEqual(viewer.post('/api/vpn/sites',json={},headers={'X-CSRF-Token':r.json()['csrf']}).status_code,403)

    def test_01_hub_site_routes(self):
        obj={'interface':'wg-pc0','address':'10.77.77.1/24','listen_port':51820,'endpoint':'vpn.example.org',
             'public_key':PUB_H,'gateway_lan_ip':'10.0.0.250'}
        self.assertEqual(self.req('PUT','/api/vpn/hub',obj).status_code,200)
        s=self.add_site()
        route=self.add_route(s)
        state=self.req('GET','/api/vpn/overview').json()
        self.assertEqual(len(state['sites']),1)
        self.assertEqual(state['routes'][0]['cidr'],'192.168.20.0/24')
        self.assertEqual(state['mode'],'configuration_only')
        self.assertFalse(state['active_tunnels_verified'])
        self.assertEqual(self.req('POST',f'/api/vpn/sites/{s}/routes',{'cidr':'192.168.20.0/25'}).status_code,409)
        self.assertEqual(self.req('POST',f'/api/vpn/sites/{s}/routes',{'cidr':'10.77.77.0/24'}).status_code,422)
        self.assertEqual(self.req('POST',f'/api/vpn/sites/{s}/routes',{'cidr':'0.0.0.0/0'}).status_code,422)
        self.assertEqual(self.req('POST',f'/api/vpn/sites/{s}/routes',{'cidr':'8.8.8.0/24'}).status_code,422)
        self.assertEqual(self.req('PUT','/api/vpn/hub',{**obj,'address':'10.88.88.1/24'}).status_code,409)
        self.assertEqual(self.req('DELETE',f'/api/vpn/routes/{route}').status_code,200)
        self.assertEqual(self.req('DELETE',f'/api/vpn/sites/{s}').status_code,200)

    def test_02_key_injection_ip_validation(self):
        for k in ('bad-key','',PUB_S+'\nInject=true',base64.b64encode(b'\x00'*32).decode()):
            self.assertEqual(self.req('POST','/api/vpn/sites',{'name':'X','public_key':k,'tunnel_ip':'10.77.77.2'}).status_code,422)
        for tunnel in ('8.8.8.8','127.0.0.1','10.0.0.255','10.77.77.1'):
            status=self.req('POST','/api/vpn/sites',{'name':'X','public_key':PUB_S,'tunnel_ip':tunnel}).status_code
            self.assertEqual(status,422,tunnel)
        self.assertEqual(self.req('POST','/api/vpn/sites',{'name':'evil\n[Interface]','public_key':PUB_S,'tunnel_ip':'10.77.77.2'}).status_code,422)
        self.assertEqual(self.req('POST','/api/vpn/sites',{'name':'X','public_key':PUB_S,'tunnel_ip':'10.77.77.2',
            'endpoint_host':'some;\nPreUp=hack'}).status_code,422)
        sid=self.add_site()
        self.assertEqual(self.req('POST','/api/vpn/sites',{'name':'Y','public_key':PUB_S,'tunnel_ip':'10.77.77.3'}).status_code,409)
        self.assertEqual(self.req('POST','/api/vpn/sites',{'name':'Y','public_key':PUB_T,'tunnel_ip':'10.77.77.2'}).status_code,409)

    def test_03_domain_private_routing_and_disabled(self):
        site=self.add_site()
        rid=self.add_route(site)
        invalid={'site_id':site,'route_id':rid,'domain':'app.example.org','target_ip':'192.168.30.10','target_port':8080,'protocol':'http'}
        self.assertEqual(self.req('POST','/api/vpn/domains',invalid).status_code,422)
        self.assertEqual(self.req('POST','/api/vpn/domains',{**invalid,'target_ip':'8.8.8.8'}).status_code,422)
        self.assertEqual(self.req('POST','/api/vpn/domains',{**invalid,'target_ip':'192.168.20.0'}).status_code,422)
        self.assertEqual(self.req('POST','/api/vpn/domains',{**invalid,'target_ip':'192.168.20.10','domain':'bad;return 200;'}).status_code,422)
        r=self.req('POST','/api/vpn/domains',{**invalid,'target_ip':'192.168.20.10'})
        self.assertEqual(r.status_code,200,r.text)
        uid=r.json()['result']
        self.assertFalse(r.json()['applied'])
        with db.connect() as con:
            host=con.execute('SELECT * FROM hosts WHERE id=?',(uid,)).fetchone()
            self.assertEqual(host['enabled'],0)
            self.assertEqual(host['upstream_host'],'192.168.20.10')
            self.assertEqual(host['category'],'VPN · Remote A')
        # Existing host editor may not silently escape the bound RFC1918 remote route.
        update={'domain':'app.example.org','upstream_scheme':'http','upstream_host':'192.168.30.20',
                'upstream_port':8080,'enabled':False}
        self.assertEqual(self.req('PUT',f'/api/hosts/{uid}',update).status_code,422)
        update['upstream_host']='192.168.20.15'
        self.assertEqual(self.req('PUT',f'/api/hosts/{uid}',update).status_code,200)
        self.assertEqual(self.req('DELETE',f'/api/vpn/routes/{rid}').status_code,409)
        self.assertEqual(self.req('DELETE',f'/api/vpn/sites/{site}').status_code,409)
        self.assertEqual(self.req('DELETE',f'/api/vpn/bindings/{uid}').status_code,200)
        self.assertEqual(len(self.req('GET','/api/hosts').json()),1)
        self.assertEqual(self.req('DELETE',f'/api/vpn/routes/{rid}').status_code,200)

    def test_04_bind_existing_restrictions_and_export(self):
        s=self.add_site();r=self.add_route(s)
        with db.connect() as con:
            con.execute("INSERT INTO hosts(id,domain,upstream_scheme,upstream_host,upstream_port,enabled) VALUES(?,?,?,?,?,?)",('host-1','old.example.org','http','192.168.20.20',8080,0))
        data={'host_id':'host-1','site_id':s,'route_id':r}
        self.assertEqual(self.req('POST','/api/vpn/bindings',data).status_code,200)
        self.assertEqual(self.req('POST','/api/vpn/bindings',data).status_code,409)
        exported=self.req('GET','/api/vpn/export').json()
        self.assertIn('Public',self.req('GET','/api/vpn/preview').json()['template'])
        self.assertEqual(exported['sites'][0]['routes'],['192.168.20.0/24'])
        self.assertNotIn('private_key',str(exported).lower())
        with db.connect() as con:
            audits=list(con.execute('SELECT action FROM audit WHERE action LIKE "vpn.%"'))
            self.assertGreater(len(audits),0)

    def test_05_gateway_offline_preview_and_secret_files(self):
        hub=vpn.HubConfig(endpoint='vpn.example.org',public_key=PUB_H)
        site=vpn.SiteInput(name='Remote A',public_key=PUB_S,tunnel_ip='10.77.77.2')
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            plan={'format':'proxycircuit-wireguard-plan-v1','hub':hub.model_dump(),
                  'sites':[{**site.model_dump(),'id':'abc','routes':['192.168.20.0/24']}]}
            import json
            fn=p/'plan.json';fn.write_text(json.dumps(plan))
            gh,entries=load_plan(fn)
            self.assertIn('AllowedIPs = 10.77.77.2/32, 192.168.20.0/24',render_hub(gh,entries,PUB_H))
            self.assertIn('Endpoint = vpn.example.org:51820',render_spoke(gh,site,PUB_S))
            secret=p/'key';secret.write_text(PUB_H)
            secret.chmod(0o644)
            with self.assertRaises(ValueError):read_private_key(secret)
            secret.chmod(0o600)
            self.assertEqual(read_private_key(secret),PUB_H)
            output=p/'wg-pc0.conf';write_conf(output,'secret')
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            with self.assertRaises(ValueError):write_conf(output,'secret changed')
            plan['sites'][0]['routes'].append('192.168.20.128/25')
            fn.write_text(json.dumps(plan))
            with self.assertRaises(ValueError):load_plan(fn)

if __name__=='__main__':unittest.main()
