# ProxyCircuit v0.2.5 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""No privileged actions, no real network connections: isolated API/CLI safety tests."""
import base64
import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import db, main, vpn
from app.security import hash_password
from app.vpn_preflight import readiness_report
from tools.vpn_gateway_preflight import inspect, read_command

PUB_H = base64.b64encode(bytes(range(1, 33))).decode()
PUB_S = base64.b64encode(bytes(range(33, 65))).decode()


class VPNPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='pc-025-test-')
        root=Path(self.tmp.name)
        self.stack=contextlib.ExitStack()
        for obj,attr,value in ((db,'BASE',root),(db,'DB',root/'app.sqlite3'),
                (db,'CERTS',root/'certs'),(db,'DEPLOY',root/'deploy'),
                (db,'ACME',root/'acme'),(main,'DEPLOY',root/'deploy')):
            self.stack.enter_context(patch.object(obj,attr,value))
        db.init_db()
        db.init_db()  # unchanged schema is idempotent
        with db.connect() as con:
            con.execute('INSERT INTO admins(username,password_hash) VALUES (?,?)',('admin',hash_password('password-is-strong')))
            con.execute('INSERT INTO admins(username,password_hash,role) VALUES (?,?,?)',('reader',hash_password('read-only-pass'),'viewer'))
        self.client=TestClient(main.app,base_url='https://localhost:9443')
        self.client.__enter__()
        result=self.client.post('/api/login',json={'username':'admin','password':'password-is-strong'})
        assert result.status_code==200, result.text
        self.csrf=result.json()['csrf']

    def tearDown(self):
        self.client.__exit__(None,None,None)
        self.stack.close()
        self.tmp.cleanup()

    def request(self,verb,path,body=None,csrf=True):
        return self.client.request(verb,path,json=body,
            headers={'X-CSRF-Token':self.csrf} if csrf else {})

    def setup_valid_plan(self):
        result=self.request('PUT','/api/vpn/hub',{
            'interface':'wg-pc0','address':'10.77.77.1/24','listen_port':51820,
            'endpoint':'vpn.example.net','public_key':PUB_H,'gateway_lan_ip':'10.0.0.250'})
        assert result.status_code==200, result.text
        result=self.request('POST','/api/vpn/sites',{
            'name':'Indonesien','public_key':PUB_S,'tunnel_ip':'10.77.77.2',
            'endpoint_host':'vpn.remote.example','endpoint_port':51820,'keepalive':25})
        assert result.status_code==200, result.text
        sid=result.json()['result']
        result=self.request('POST',f'/api/vpn/sites/{sid}/routes',{'cidr':'192.168.20.0/24'})
        assert result.status_code==200, result.text
        rid=result.json()['result']
        return sid,rid

    def test_01_preflight_is_blocked_when_empty_and_read_only(self):
        with db.connect() as con:
            before=con.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        first=self.request('GET','/api/vpn/preflight')
        assert first.status_code==200, first.text
        report=first.json()
        self.assertEqual(report['status'],'blocked')
        self.assertGreaterEqual(report['blockers'],3)
        self.assertFalse(report['active_tunnels_verified'])
        self.assertFalse(report['changes_applied'])
        self.assertFalse(report['reachability_checked'])
        second=self.request('GET','/api/vpn/preflight')
        self.assertEqual(report['config_sha256'],second.json()['config_sha256'])
        with db.connect() as con:
            after=con.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        self.assertEqual(before,after)

    def test_02_admin_only_and_csrf(self):
        self.assertEqual(TestClient(main.app,base_url='https://localhost:9443').get('/api/vpn/preflight').status_code,401)
        viewer=TestClient(main.app,base_url='https://localhost:9443')
        lr=viewer.post('/api/login',json={'username':'reader','password':'read-only-pass'})
        self.assertEqual(lr.status_code,200)
        self.assertEqual(viewer.get('/api/vpn/preflight').status_code,403)
        self.assertEqual(viewer.get('/api/vpn/local-networks').status_code,403)
        self.assertEqual(viewer.put('/api/vpn/local-networks',json={'networks':['10.0.0.0/24']},
            headers={'X-CSRF-Token':lr.json()['csrf']}).status_code,403)
        self.assertEqual(self.request('PUT','/api/vpn/local-networks',{'networks':[]},csrf=False).status_code,403)

    def test_03_local_networks_validate_and_save(self):
        for values in (["0.0.0.0/0"],["8.8.8.0/24"],["10.77.77.0/24"],
                       ["10.0.0.0/24","10.0.0.128/25"],["10.0.0.1/24"],
                       ["192.168.1.0/24;evil"], ["10.0.0.0/24"]*17):
            self.assertIn(self.request('PUT','/api/vpn/local-networks',{'networks':values}).status_code,(409,422),values)
        response=self.request('PUT','/api/vpn/local-networks',{'networks':['192.168.1.0/24','10.0.0.0/24']})
        self.assertEqual(response.status_code,200,response.text)
        self.assertFalse(response.json()['applied'])
        expected=['10.0.0.0/24','192.168.1.0/24']
        self.assertEqual(self.request('GET','/api/vpn/local-networks').json()['networks'],expected)
        self.assertEqual(self.request('GET','/api/vpn/overview').json()['local_networks'],expected)
        self.assertEqual(self.request('GET','/api/vpn/export').json()['local_networks'],expected)
        db.init_db()
        self.assertEqual(self.request('GET','/api/vpn/local-networks').json()['networks'],expected)

    def test_04_local_routes_block_collisions_both_directions(self):
        sid,rid=self.setup_valid_plan()
        self.assertEqual(self.request('PUT','/api/vpn/local-networks',{'networks':['192.168.20.0/24']}).status_code,409)
        self.assertEqual(self.request('PUT','/api/vpn/local-networks',{'networks':['10.0.0.0/24']}).status_code,200)
        self.assertEqual(self.request('POST',f'/api/vpn/sites/{sid}/routes',{'cidr':'10.0.0.0/24'}).status_code,409)
        response=self.request('PUT','/api/vpn/hub',{'interface':'wg-pc0','address':'10.0.0.1/24','listen_port':51820,
            'endpoint':'vpn.example.net','public_key':PUB_H,'gateway_lan_ip':'10.0.0.250'})
        self.assertEqual(response.status_code,409)

    def test_05_good_plan_is_ready_for_gateway_test_not_connected(self):
        self.setup_valid_plan()
        self.assertEqual(self.request('PUT','/api/vpn/local-networks',{'networks':['10.0.0.0/24']}).status_code,200)
        report=self.request('GET','/api/vpn/preflight').json()
        self.assertEqual(report['blockers'],0)
        self.assertEqual(report['warnings'],0)
        self.assertEqual(report['status'],'ready_for_gateway_test')
        self.assertFalse(report['active_tunnels_verified'])
        self.assertFalse(report['reachability_checked'])
        self.assertFalse(report['changes_applied'])
        with db.connect() as con:
            before=con.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
        self.assertEqual(self.request('GET','/api/vpn/preflight').json()['config_sha256'],report['config_sha256'])
        with db.connect() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],before)

    def test_06_domains_warnings_without_autodeploy(self):
        sid,rid=self.setup_valid_plan()
        result=self.request('POST','/api/vpn/domains',{
            'site_id':sid,'route_id':rid,'domain':'vpn.example.org',
            'target_ip':'192.168.20.10','target_port':8080,'protocol':'http'})
        self.assertEqual(result.status_code,200,result.text)
        uid=result.json()['result']
        with db.connect() as con:
            self.assertEqual(con.execute('SELECT enabled FROM hosts WHERE id=?',(uid,)).fetchone()['enabled'],0)
            con.execute('UPDATE hosts SET enabled=1 WHERE id=?',(uid,))
        report=self.request('GET','/api/vpn/preflight').json()
        self.assertIn('active_domain_unverified',[x['code'] for x in report['checks']])
        self.assertNotEqual(report['status'],'ready_for_gateway_test')

    def test_07_digest_changes_when_plan_changes(self):
        self.setup_valid_plan()
        old=self.request('GET','/api/vpn/preflight').json()['config_sha256']
        self.assertEqual(self.request('PUT','/api/vpn/local-networks',{'networks':['10.0.0.0/24']}).status_code,200)
        new=self.request('GET','/api/vpn/preflight').json()['config_sha256']
        self.assertNotEqual(old,new)


class GatewayReadOnlyTests(unittest.TestCase):
    @staticmethod
    def sample():
        return {'format':'proxycircuit-wireguard-plan-v1',
            'hub':{'interface':'wg-pc0','address':'10.77.77.1/24','listen_port':51820,
                   'endpoint':'vpn.example.org','public_key':PUB_H},
            'local_networks':['10.0.0.0/24'],
            'sites':[{'id':'site1','name':'Remote B','public_key':PUB_S,'tunnel_ip':'10.77.77.2',
                     'endpoint_host':'remote.example.org','endpoint_port':51820,
                     'keepalive':25,'routes':['192.168.20.0/24'],'enabled':1}]}

    @staticmethod
    def fake_read(args):
        if args[0]=='ss':return '',None
        if args[:3]==['ip','-j','link']:
            return [{'ifname':'eth0'}],None
        return [{'dst':'10.0.0.0/24','dev':'eth0'}],None

    def test_08_clean_plan_read_only(self):
        r=inspect(self.sample(),'hub',read=self.fake_read)
        self.assertEqual(r['status'],'ready_for_manual_test')
        self.assertFalse(r['network_changed'])
        self.assertFalse(r['tunnel_started'])
        self.assertFalse(r['live_connection_verified'])
        self.assertEqual(r['blockers'],0)

    def test_09_detect_existing_kernel_route(self):
        def existing(args):
            if args[:3]==['ip','-j','-4']:
                return [{'dst':'192.168.20.0/24','dev':'eth0'}],None
            return self.fake_read(args)
        r=inspect(self.sample(),'hub',read=existing)
        self.assertEqual(r['status'],'blocked')
        self.assertIn('kernel_route_collision',[x['code'] for x in r['checks']])

    def test_10_detect_local_plan_overlap(self):
        p=self.sample()
        p['local_networks']=['192.168.20.0/24']
        r=inspect(p,'hub',read=self.fake_read)
        self.assertEqual(r['status'],'blocked')
        self.assertIn('local_route_collision',[x['code'] for x in r['checks']])

    def test_11_spoke_requires_hub_key_and_valid_site(self):
        p=self.sample()
        p['hub']['endpoint']=''
        r=inspect(p,'spoke','site1',read=self.fake_read)
        self.assertEqual(r['status'],'blocked')
        self.assertIn('hub_missing_info',[x['code'] for x in r['checks']])
        with self.assertRaises(ValueError):inspect(p,'spoke','no-such-site',read=self.fake_read)

    def test_12_missing_ip_tools_warn_not_pass(self):
        def missing(args):return None,'FileNotFoundError'
        r=inspect(self.sample(),'hub',read=missing)
        self.assertEqual(r['status'],'review_required')
        self.assertGreater(r['warnings'],0)

    def test_13_unexpected_commands_rejected(self):
        with self.assertRaises(ValueError):
            read_command(['sh','-c','rm -rf /'])


if __name__=='__main__': unittest.main()
