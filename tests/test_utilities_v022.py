# ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Role, boundary, data leakage and utility tests; network effects are mocked."""
import contextlib
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ['RPMGR_DEV'] = '1'
from fastapi.testclient import TestClient
from app import db, main, utilities
from app.security import hash_password

class NetworkToolsV022Test(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='pc-v022-')
        self.base=Path(self.tmp.name)
        self.patches=contextlib.ExitStack()
        for module,key,value in ((db,'BASE',self.base),(db,'DB',self.base/'db.sqlite3'),
                                 (db,'CERTS',self.base/'certs'),(db,'DEPLOY',self.base/'deploy'),
                                 (db,'ACME',self.base/'acme'),(main,'DEPLOY',self.base/'deploy')):
            self.patches.enter_context(patch.object(module,key,value))
        db.init_db()
        con=db.connect()
        with con:
            con.execute('INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)',
                        ('admin',hash_password('password-for-admin'),'admin'))
            con.execute('INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)',
                        ('reader',hash_password('password-for-reader'),'viewer'))
        con.close()
        self.admin=TestClient(main.app,base_url='https://localhost:9443')
        self.viewer=TestClient(main.app,base_url='https://localhost:9443')
        self.patches.enter_context(self.admin)
        self.patches.enter_context(self.viewer)
        a=self.admin.post('/api/login',json={'username':'admin','password':'password-for-admin'})
        v=self.viewer.post('/api/login',json={'username':'reader','password':'password-for-reader'})
        self.assertEqual(a.status_code,200,a.text)
        self.assertEqual(v.status_code,200,v.text)
        self.a_token=a.json()['csrf'];self.v_token=v.json()['csrf']

    def tearDown(self):
        self.patches.close()
        self.tmp.cleanup()

    def post(self,path,body,viewer=False,csrf=None):
        return (self.viewer if viewer else self.admin).post('/api/utilities/'+path,json=body,
                     headers={'X-CSRF-Token':csrf or (self.v_token if viewer else self.a_token)})

    def test_cidr_ipv4_ipv6_and_validation(self):
        r=self.post('cidr',{'cidr':'192.168.12.25/24'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['cidr'],'192.168.12.0/24')
        self.assertEqual(r.json()['usable'],254)
        self.assertEqual(r.json()['broadcast'],'192.168.12.255')
        v=self.post('cidr',{'cidr':'fd00::1/64'},viewer=True)
        self.assertEqual(v.status_code,200,v.text)
        self.assertEqual(v.json()['version'],6)
        self.assertEqual(self.post('cidr',{'cidr':'junk'}).status_code,422)
        self.assertEqual(self.post('cidr',{'cidr':'10.0.0.0/24'},csrf='INVALID').status_code,403)

    def test_scanner_restricts_public_cidr_and_size(self):
        self.assertEqual(self.post('ip-scan',{'cidr':'8.8.8.0/24'}).status_code,422)
        self.assertEqual(self.post('ip-scan',{'cidr':'10.0.0.0/16'}).status_code,422)
        self.assertEqual(self.post('ip-scan',{'cidr':'10.0.0.0/24'},viewer=True).status_code,403)
        self.assertEqual(self.post('port-scan',{'host':'8.8.8.8','ports':[80]}).status_code,422)
        self.assertEqual(self.post('port-scan',{'host':'localhost','ports':[80]}).status_code,422)
        self.assertEqual(self.post('port-scan',{'host':'10.0.0.5','ports':list(range(1,130))}).status_code,422)
        self.assertEqual(self.post('port-scan',{'host':'10.0.0.5','ports':[80,80]}).status_code,422)

    def test_ip_scanner_reports_only_open_ports(self):
        async def fake_probe(ip, port, timeout=.65):
            return ip=='10.10.0.1' and port==443
        with patch.object(utilities,'tcp_probe',fake_probe):
            r=self.post('ip-scan',{'cidr':'10.10.0.0/30','ports':[22,443]})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['responsive'],[{'ip':'10.10.0.1','open_ports':[443]}])
        self.assertEqual(r.json()['scanned_hosts'],2)

    def test_port_scanner_and_role(self):
        async def fake_probe(ip, port, timeout=.65):
            return port in (22,9443)
        with patch.object(utilities,'tcp_probe',fake_probe):
            r=self.post('port-scan',{'host':'192.168.50.150','ports':[443,9443,22]})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['open'],[22,9443])
        self.assertEqual(r.json()['closed_or_filtered'],[443])
        self.assertEqual(self.post('port-scan',{'host':'192.168.50.150','ports':[443]},viewer=True).status_code,403)

    def test_wol_invalid_mac_rejected_and_good_packet(self):
        self.assertEqual(self.post('wake-on-lan',{'mac':'not-a-mac'}).status_code,422)
        self.assertEqual(self.post('wake-on-lan',{'mac':'AA:BB:CC:DD:EE:FE','broadcast':'1.1.1.1'}).status_code,422)
        class StubSocket:
            def __init__(self):self.packet=None
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def setsockopt(self,*args):pass
            def settimeout(self,*args):pass
            def sendto(self,data,target):
                self.packet=data;self.target=target
        mock=StubSocket()
        with patch.object(utilities.socket,'socket',return_value=mock):
            r=self.post('wake-on-lan',{'mac':'AA:BB:CC:DD:EE:FE'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(len(mock.packet),102)
        self.assertEqual(mock.packet[:6],b'\xff'*6)
        self.assertEqual(mock.target,('255.255.255.255',9))

    def test_mdns_and_forward_proxy_restrict_known_domain(self):
        self.assertEqual(self.post('mdns',{},viewer=True).status_code,403)
        with patch.object(utilities,'scan_mdns_sync',return_value={'service_types':[],'devices':[],'note':'mock'}):
            self.assertEqual(self.post('mdns',{}).status_code,200)
        self.assertEqual(self.post('forward-proxy',{'proxy_ip':'8.8.8.8','proxy_port':3128,'host_id':'x'}).status_code,422)
        self.assertEqual(self.post('forward-proxy',{'proxy_ip':'10.0.0.2','proxy_port':3128,'host_id':'x'}).status_code,404)
        response=self.admin.post('/api/hosts',json={'domain':'test.example.com','upstream_scheme':'http','upstream_host':'10.0.0.1','upstream_port':80},headers={'X-CSRF-Token':self.a_token})
        self.assertEqual(response.status_code,200,response.text)
        host_id=response.json()['result']
        with patch.object(utilities,'_test_http_proxy',return_value='HTTP/1.1 200 Connection established') as proxy:
            response=self.post('forward-proxy',{'proxy_ip':'10.0.0.20','proxy_port':3128,'host_id':host_id})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['method'],'HEAD')
        self.assertEqual(proxy.call_args.args,('10.0.0.20',3128,'test.example.com',80,False))

    def test_ssh_roles_hostkey_and_origin(self):
        self.assertEqual(self.post('ssh/hostkey',{'host':'192.168.50.9'},viewer=True).status_code,403)
        self.assertEqual(self.post('ssh/hostkey',{'host':'1.1.1.1'}).status_code,422)
        with patch.object(utilities,'_ssh_fingerprint',return_value={'algorithm':'ssh-ed25519','fingerprint':'SHA256:'+'A'*43}):
            self.assertEqual(self.post('ssh/hostkey',{'host':'192.168.50.9'}).status_code,200)
        from starlette.websockets import WebSocketDisconnect
        with self.assertRaises(WebSocketDisconnect):
            with self.admin.websocket_connect('/api/utilities/ssh/ws') as ws:
                ws.receive_json()
        with self.assertRaises(WebSocketDisconnect):
            with self.viewer.websocket_connect('/api/utilities/ssh/ws',headers={'host':'localhost:9443','origin':'https://localhost:9443',
                              'cookie':'rpmgr_session='+self.viewer.cookies.get('rpmgr_session')}) as ws:
                ws.receive_json()

    def test_ssh_websocket_authenticated_handshake_and_hostkey_pin(self):
        class Transport:
            closed=False
            def close(self):self.closed=True
        class Channel:
            closed=False
            reads=0
            def recv(self, num):
                self.reads+=1
                if self.reads==1:return b'hello from ssh\n'
                self.closed=True
                return b''
            def close(self):self.closed=True
        transport,channel=Transport(),Channel()
        with patch.object(utilities,'_ssh_start',return_value=(transport,channel)):
            with self.admin.websocket_connect('/api/utilities/ssh/ws',
                     headers={'host':'localhost:9443','origin':'https://localhost:9443',
                              'cookie':'rpmgr_session='+self.admin.cookies.get('rpmgr_session')}) as ws:
                ws.send_json({'type':'connect','csrf':self.a_token,'host':'192.168.50.9',
                              'port':22,'username':'admin','password':'x',
                              'fingerprint':'SHA256:'+'A'*43})
                response=ws.receive_json()
                self.assertEqual(response['type'],'ready',response)
                output=ws.receive_json()
                self.assertEqual(output['type'],'output',output)
                self.assertIn('hello from ssh',output['data'])
        self.assertTrue(transport.closed)

    def test_no_database_schema_changes_for_tools(self):
        con=db.connect()
        columns=[r['name'] for r in con.execute('PRAGMA table_info(hosts)').fetchall()]
        con.close()
        self.assertIn('upstream_tls_name',columns)
        self.assertNotIn('ssh_password',columns)

if __name__ == '__main__':unittest.main()
