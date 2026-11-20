# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
import contextlib
import os
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess

from app import db, worker, deploy_safety
from app.operational_diagnostics import inspect_served_tls


class FakeTLS:
    def __init__(self,cert,key,status=401):
        self.ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert),str(key))
        self.listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1',0));self.listener.listen(1)
        self.port=self.listener.getsockname()[1]
        self.done=threading.Event()
        def serve():
            try:
                self.listener.settimeout(4)
                conn,_=self.listener.accept()
                with self.ctx.wrap_socket(conn,server_side=True) as c:
                    c.settimeout(3)
                    c.recv(2048)
                    c.sendall(f'HTTP/1.1 {status} Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode())
            except (OSError,ssl.SSLError):pass
            finally:
                self.listener.close();self.done.set()
        self.thread=threading.Thread(target=serve,daemon=True);self.thread.start()
    def finish(self):self.done.wait(5);self.thread.join(timeout=2)


class CertificateTests(unittest.TestCase):
    def certificate(self,root,domain):
        key=root/'key.pem';cert=root/'cert.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
             '-keyout',str(key),'-out',str(cert),'-subj','/CN='+domain,
             '-addext','subjectAltName=DNS:'+domain],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        return cert,key
    def test_real_sni_certificate_matching_and_401(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert,key=self.certificate(Path(tmp),'admin.example.org')
            server=FakeTLS(cert,key,401)
            result=inspect_served_tls('admin.example.org',port=server.port)
            server.finish()
            self.assertTrue(result['ok'],result)
            self.assertTrue(result['certificate_matches'])
            self.assertEqual(result['http_status'],401)
            self.assertTrue(result['fingerprint_sha256'])
    def test_wrong_certificate_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert,key=self.certificate(Path(tmp),'proxycircuit.local')
            server=FakeTLS(cert,key,404)
            result=inspect_served_tls('admin.example.org',port=server.port)
            server.finish()
            self.assertTrue(result['reachable'],result)
            self.assertFalse(result['certificate_matches'])
            self.assertFalse(result['ok'])
            self.assertIn('proxycircuit.local',result['san'])


class RollbackTests(unittest.TestCase):
    def test_worker_rolls_back_when_reload_signal_succeeds_but_activation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            main_db=root/'rpmgr.sqlite3'
            with patch.object(db,'DB',main_db),patch.object(db,'BASE',root),\
                 patch.object(db,'CERTS',root/'certs'),patch.object(db,'DEPLOY',root/'deploy'),\
                 patch.object(db,'ACME',root/'acme'):
                db.init_db()
                con=db.connect()
                con.execute("INSERT INTO streams(id,label,protocol,listen_port,bind_ip,target_host,target_port,enabled) VALUES(?,?,?,?,?,?,?,?)",
                            ('mail','Mail','tcp',25,'0.0.0.0','127.0.0.1',25,1))
                con.commit();con.close()
            http=root/'http.conf';stream=root/'stream.conf';fallback=root/'fallback'
            fallback.mkdir()
            html=fallback/'__proxycircuit_error_page.html'
            http.write_text('OLD_HTTP');stream.write_text('OLD_STREAM');html.write_text('OLD_FALLBACK')
            # Fake existing runtime: every external command reports success,
            # but the verifier detects that the new listener never opened.
            good=CompletedProcess(['nginx'],0,'','')
            with patch.object(worker,'connect',side_effect=lambda: sqlite3_connect(main_db)),\
                 patch.object(worker,'NGINX_HTTP',http),patch.object(worker,'NGINX_STREAM',stream),\
                 patch.object(worker,'FALLBACK_DIR',fallback),patch.object(worker,'DEPLOY',root/'deploy'),\
                 patch.object(worker,'stage_test',return_value={'syntax_ok':True}),\
                 patch.object(worker,'assert_bindings',return_value={'warnings':[]}),\
                 patch.object(worker,'create_version',return_value='snapshot-test'),\
                 patch.object(worker,'nginx_worker_pids',return_value=set()),\
                 patch.object(worker,'cmd',return_value=good),\
                 patch.object(worker,'reload_nginx',return_value=good),\
                 patch.object(worker,'post_reload_status',side_effect=RuntimeError('NGINX listener missing')):
                with patch('app.deploy_safety.nginx_supervisor_running',return_value=True):
                    with self.assertRaisesRegex(RuntimeError,'Vorherige Konfiguration wiederhergestellt'):
                        worker.apply_config(request_id='test-failed-activation')
            self.assertEqual(http.read_text(),'OLD_HTTP')
            self.assertEqual(stream.read_text(),'OLD_STREAM')
            self.assertEqual(html.read_text(),'OLD_FALLBACK')
            con=sqlite3.connect(main_db)
            state=con.execute('SELECT state,rollback_ok FROM deploy_history WHERE id=?',('test-failed-activation',)).fetchone()
            con.close()
            self.assertEqual(state,('activation_failed',1))


def sqlite3_connect(path):
    con=sqlite3.connect(str(path))
    con.row_factory=sqlite3.Row
    return con

if __name__=='__main__':unittest.main()
