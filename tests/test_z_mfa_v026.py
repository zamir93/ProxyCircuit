# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import db,main,security,mfa


class MfaTests(unittest.TestCase):
    def test_rfc_vector_six_digits(self):
        # RFC 6238 test seed for HMAC-SHA1; expected 8-digit 94287082 -> last 6=287082.
        import base64
        key=base64.b32encode(b'12345678901234567890').decode().rstrip('=')
        self.assertEqual(mfa.totp(key,now=59),'287082')
        self.assertEqual(mfa.valid_counter(key,'287082',now=59),1)
        self.assertIsNone(mfa.valid_counter(key,'287082',now=59,last_counter=1))
        self.assertIsNone(mfa.valid_counter(key,'000000',now=59))
        self.assertTrue('otpauth://totp/' in mfa.uri('admin',key))

    def test_admin_enrollment_and_login_replay_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            with patch.object(db,'BASE',base),patch.object(db,'DB',base/'rpmgr.sqlite3'),\
                 patch.object(db,'CERTS',base/'certs'),patch.object(db,'DEPLOY',base/'deploy'),\
                 patch.object(db,'ACME',base/'acme'),patch.object(main,'connect',side_effect=db.connect),\
                 patch.object(main,'init_db',side_effect=db.init_db),\
                 patch.object(security,'connect',side_effect=db.connect):
                db.init_db()
                con=db.connect()
                con.execute('INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)',
                            ('admin',security.hash_password('safe-test-only-password'),'admin'))
                con.commit();con.close()
                with TestClient(main.app,base_url='https://localhost:9443') as client:
                    user={'username':'admin','password':'safe-test-only-password'}
                    login=client.post('/api/login',json=user)
                    self.assertEqual(login.status_code,200,login.text)
                    csrf={'X-CSRF-Token':login.json()['csrf']}
                    self.assertEqual(client.post('/api/security/mfa/setup').status_code,403)
                    setup=client.post('/api/security/mfa/setup',headers=csrf)
                    self.assertEqual(setup.status_code,200,setup.text)
                    secret=setup.json()['secret']
                    self.assertNotIn('secret',client.get('/api/security/mfa').text)
                    code=mfa.totp(secret)
                    confirmed=client.post('/api/security/mfa/confirm',headers=csrf,json={'code':code})
                    self.assertEqual(confirmed.status_code,200,confirmed.text)
                    self.assertTrue(client.get('/api/security/mfa').json()['enabled'])
                    # Fresh password-only login is now prohibited.
                    client.post('/api/logout',headers=csrf)
                    wrong=client.post('/api/login',json=user)
                    self.assertEqual(wrong.status_code,401)
                    duplicate=client.post('/api/login',json={**user,'otp':code})
                    self.assertEqual(duplicate.status_code,401)
                    # Advance the counter by one (within TOTP skew tolerance).
                    future=mfa.totp(secret,counter=int(time.time()//30)+1)
                    login2=client.post('/api/login',json={**user,'otp':future})
                    self.assertEqual(login2.status_code,200,login2.text)
                    again=client.post('/api/login',json={**user,'otp':future})
                    self.assertEqual(again.status_code,401)
                    con=db.connect()
                    try:
                        self.assertTrue(con.execute('SELECT active FROM user_mfa WHERE username=?',('admin',)).fetchone()[0])
                    finally:con.close()

if __name__=='__main__':unittest.main()
