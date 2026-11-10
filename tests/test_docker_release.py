# ProxyCircuit GitHub release smoke tests - Mohammad Zamir Akbari
from pathlib import Path
from unittest.mock import patch
import os
from app import worker

ROOT = Path(__file__).resolve().parents[1]


def test_docker_runtime_uses_nginx_signal():
    with patch.dict(os.environ, {'RPMGR_RUNTIME': 'docker'}), patch.object(worker, 'cmd') as runner:
        worker.reload_nginx()
        runner.assert_called_once_with(['nginx', '-s', 'reload'])


def test_debian_runtime_uses_systemctl():
    with patch.dict(os.environ, {'RPMGR_RUNTIME': 'debian'}), patch.object(worker, 'cmd') as runner:
        worker.reload_nginx()
        runner.assert_called_once_with(['systemctl', 'reload', 'nginx'])


def test_compose_does_not_expose_admin_globally():
    text = (ROOT / 'compose.yaml').read_text()
    assert '127.0.0.1:9443:9443' in text
    assert '/var/run/docker.sock' not in text


def test_private_material_is_excluded_from_docker_context():
    ignored = (ROOT / '.dockerignore').read_text()
    for item in ('*.sqlite3', '*.key', '*.pem', '.env'):
        assert item in ignored
