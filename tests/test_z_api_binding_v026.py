# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock,patch
from fastapi import HTTPException
from app import db,main
from app.validation import StreamInput


class BindIPApiTests(unittest.TestCase):
    def test_stream_create_update_delete_two_interfaces_same_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(db,'BASE',root),patch.object(db,'DB',root/'rpmgr.sqlite3'),\
                 patch.object(db,'CERTS',root/'certs'),patch.object(db,'DEPLOY',root/'deploy'),\
                 patch.object(db,'ACME',root/'acme'):
                db.init_db()
                addresses=[{'interface':'eth0','address':'192.0.2.150','family':'ipv4','loopback':False},
                           {'interface':'eth1','address':'192.0.2.151','family':'ipv4','loopback':False}]
                with patch.object(main,'connect',side_effect=db.connect),\
                     patch.object(main,'trigger_apply',new_callable=AsyncMock,return_value={'state':'test'}),\
                     patch('app.port_binding.local_addresses',return_value=addresses),\
                     patch('app.port_binding.live_sockets',return_value=[]):
                    actor={'username':'admin'}
                    payload={'label':'SMTP','protocol':'tcp','listen_port':25,'target_host':'192.0.2.236','target_port':25}
                    first=asyncio.run(main.add_stream(StreamInput(**dict(payload,bind_ip='192.0.2.150')),actor))['result']
                    second=asyncio.run(main.add_stream(StreamInput(**dict(payload,bind_ip='192.0.2.151',label='Mail2')),actor))['result']
                    con=db.connect()
                    try:
                        entries=[dict(x) for x in con.execute('SELECT * FROM streams ORDER BY bind_ip')]
                        self.assertEqual([x['bind_ip'] for x in entries],['192.0.2.150','192.0.2.151'])
                    finally:con.close()
                    with self.assertRaises(HTTPException) as exc:
                        asyncio.run(main.add_stream(StreamInput(**dict(payload,bind_ip='0.0.0.0',label='Wildcard')),actor))
                    self.assertEqual(exc.exception.status_code,422)
                    with self.assertRaises(HTTPException) as exc:
                        asyncio.run(main.update_stream(first,StreamInput(**dict(payload,bind_ip='10.0.0.222')),actor))
                    self.assertEqual(exc.exception.status_code,422)
                    con=db.connect()
                    try:
                        actual=con.execute('SELECT bind_ip FROM streams WHERE id=?',(first,)).fetchone()[0]
                        self.assertEqual(actual,'192.0.2.150')
                    finally:con.close()
                    updated=asyncio.run(main.update_stream(first,StreamInput(**dict(payload,bind_ip='192.0.2.150',target_port=2525)),actor))
                    self.assertTrue(updated['ok'])
                    con=db.connect()
                    try:
                        self.assertEqual(con.execute('SELECT target_port FROM streams WHERE id=?',(first,)).fetchone()[0],2525)
                        self.assertEqual(con.execute('SELECT count(*) FROM streams').fetchone()[0],2)
                    finally:con.close()
                    asyncio.run(main.delete_stream(second,actor))
                    con=db.connect()
                    try:self.assertEqual(con.execute('SELECT count(*) FROM streams').fetchone()[0],1)
                    finally:con.close()

if __name__=='__main__':unittest.main()
