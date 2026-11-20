# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
import ast
import json
import socket
import unittest
from pathlib import Path
from unittest.mock import patch
from app.port_binding import local_addresses, find_live_conflicts

ROOT=Path(__file__).resolve().parents[1]

class ReleaseHotfixTests(unittest.TestCase):
    def test_db_not_packaged(self):
        self.assertFalse(list(ROOT.rglob('*.sqlite3')))
        self.assertFalse(list(ROOT.rglob('*.db')))

    def test_web_save_is_structural_only(self):
        tree=ast.parse((ROOT/'app/main.py').read_text())
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='assert_bindings']
        self.assertTrue(any(any(k.arg=='sockets' and isinstance(k.value,ast.List) and not k.value.elts for k in c.keywords) for c in calls))
        self.assertIn('preflight=assert_bindings(streams)',(ROOT/'app/worker.py').read_text())

    def test_iproute2_fallback(self):
        data=[{'ifname':'eth0','addr_info':[{'family':'inet','local':'192.0.2.150'}]}]
        from subprocess import CompletedProcess
        with patch('app.port_binding.psutil.net_if_addrs',side_effect=OSError(97,'AF not supported')), patch('app.port_binding.subprocess.run',return_value=CompletedProcess([],0,json.dumps(data),'')):
            self.assertIn('192.0.2.150',[a['address'] for a in local_addresses()])

    def test_unknown_listener_still_blocks_worker(self):
        result=find_live_conflicts([{'protocol':'tcp','listen_port':30033,'bind_ip':'0.0.0.0'}],sockets=[{'protocol':'tcp','port':30033,'bind_ip':'0.0.0.0','process':'Prozess nicht lesbar','pid':None}],managed={('tcp',30033,'0.0.0.0')})
        self.assertTrue(result['conflicts'])

if __name__=='__main__': unittest.main()
