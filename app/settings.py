# ProxyCircuit v0.2.3 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Environment-derived file locations; no hidden hard-coded credentials."""
import os
from pathlib import Path

BASE = Path(os.environ.get('RPMGR_DATA_DIR', '/var/lib/rpmgr'))
DB = BASE / 'rpmgr.sqlite3'
CERTS = BASE / 'certs'
DEPLOY = BASE / 'deploy'
ACME = Path(os.environ.get('RPMGR_ACME_DIR', '/var/www/rpmgr-acme'))
ADMIN_CERT = Path(os.environ.get('RPMGR_ADMIN_CERT', '/etc/rpmgr/admin.crt'))
ADMIN_KEY = Path(os.environ.get('RPMGR_ADMIN_KEY', '/etc/rpmgr/admin.key'))
NGINX_HTTP = Path(os.environ.get('RPMGR_NGINX_HTTP', '/etc/nginx/conf.d/rpmgr-managed.conf'))
NGINX_STREAM = Path(os.environ.get('RPMGR_NGINX_STREAM', '/etc/nginx/rpmgr-stream.conf'))
PLUGINS = Path(os.environ.get('RPMGR_PLUGINS', '/opt/rpmgr/plugins'))
FALLBACK_DIR = Path(os.environ.get('RPMGR_FALLBACK_DIR', '/var/www/rpmgr-fallback'))
DEV = os.environ.get('RPMGR_DEV', '0') == '1'
