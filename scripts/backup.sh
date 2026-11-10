#!/bin/bash
# ProxyCircuit v0.2.0 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
# Contains private keys. Store backup archives securely and off-host.
set -Eeuo pipefail
umask 077
if [ "$(id -u)" -ne 0 ]; then echo 'Als root ausführen.' >&2;exit 1; fi
DEST=/var/backups/rpmgr
mkdir -p "$DEST";chmod 0700 "$DEST"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/var/lib/rpmgr" "$STAGE/etc"
if [ -f /var/lib/rpmgr/rpmgr.sqlite3 ]; then
  python3 - "$STAGE/var/lib/rpmgr/rpmgr.sqlite3" <<'PY'
import sqlite3,sys
src=sqlite3.connect('file:/var/lib/rpmgr/rpmgr.sqlite3?mode=ro',uri=True)
dst=sqlite3.connect(sys.argv[1]);src.backup(dst);dst.close();src.close()
PY
fi
[ ! -d /var/lib/rpmgr/certs ] || cp -a /var/lib/rpmgr/certs "$STAGE/var/lib/rpmgr/"
[ ! -d /etc/letsencrypt ] || cp -a /etc/letsencrypt "$STAGE/etc/"
NAME="rpmgr-$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n').tar.gz"
tar -C "$STAGE" -czf "$DEST/$NAME" .
chmod 0600 "$DEST/$NAME"
tar -tzf "$DEST/$NAME" >/dev/null
# Keep 7 latest archives on this LXC. Off-host copy recommended.
ls -1t "$DEST"/rpmgr-*.tar.gz 2>/dev/null | tail -n +8 | while read -r f; do rm -f -- "$f"; done
echo "Backup erstellt: $DEST/$NAME"
