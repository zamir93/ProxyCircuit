# ProxyCircuit v0.2.0 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Test database migration in a new interpreter to avoid sharing globals."""
import subprocess
import sys
import tempfile
import os
from pathlib import Path
import unittest

class MigrationTest(unittest.TestCase):
    def test_existing_hosts_receive_tls_column(self):
        with tempfile.TemporaryDirectory() as d:
            code = r'''import sqlite3
from app.settings import DB
DB.parent.mkdir(parents=True, exist_ok=True)
con = sqlite3.connect(DB)
con.execute("CREATE TABLE hosts (id TEXT PRIMARY KEY, domain TEXT, upstream_scheme TEXT, upstream_host TEXT, upstream_port INTEGER)")
con.execute("INSERT INTO hosts VALUES ('a', 'pc.example.de', 'https', '192.168.50.150', 9443)")
con.commit();con.close()
from app.db import init_db, connect
init_db(); init_db()
con=connect()
assert 'upstream_tls_name' in [r[1] for r in con.execute('PRAGMA table_info(hosts)')]
assert con.execute('SELECT domain FROM hosts WHERE id="a"').fetchone()[0] == 'pc.example.de'
con.close()
'''
            env = dict(os.environ, RPMGR_DATA_DIR=d, RPMGR_ACME_DIR=d+'/acme')
            result = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
