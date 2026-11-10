#!/usr/bin/env bash
# ProxyCircuit Docker entrypoint, no systemd and no mounted Docker socket.
# Author: Mohammad Zamir Akbari | https://zamir.akbari.org
set -Eeuo pipefail
umask 027
export PYTHONPATH=/opt/rpmgr RPMGR_RUNTIME=docker

for dir in /var/lib/rpmgr /var/lib/rpmgr/deploy /var/lib/rpmgr/certs; do
  install -d -m 0750 -o rpmgr -g rpmgr "$dir"
done
for dir in /var/www/rpmgr-acme /var/www/rpmgr-fallback /etc/rpmgr /etc/letsencrypt /var/log/nginx; do
  install -d -m 0755 "$dir"
done
# Volumes initialized by Docker are root-owned. Only the application data needs rpmgr ownership.
chown -R rpmgr:rpmgr /var/lib/rpmgr

if [[ ! -s /etc/rpmgr/admin.crt || ! -s /etc/rpmgr/admin.key ]]; then
  echo '[ProxyCircuit] Generate self-signed private admin TLS certificate ...'
  openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 365 \
    -subj '/CN=proxycircuit.local' \
    -addext 'subjectAltName=DNS:proxycircuit.local,IP:127.0.0.1' \
    -keyout /etc/rpmgr/admin.key -out /etc/rpmgr/admin.crt >/dev/null 2>&1
fi
chown root:rpmgr /etc/rpmgr/admin.crt /etc/rpmgr/admin.key
chmod 0640 /etc/rpmgr/admin.crt /etc/rpmgr/admin.key

# The database is always initialized by the unprivileged service account.
runuser -u rpmgr -- /opt/rpmgr/venv/bin/python -c 'from app.db import init_db; init_db()'

nginx -t
nginx

if ! /opt/rpmgr/venv/bin/python -m app.worker; then
  echo '[ProxyCircuit] Initial Nginx configuration failed. Stopping before opening admin service.' >&2
  nginx -s quit || true
  exit 1
fi

/opt/rpmgr/venv/bin/python /opt/rpmgr/docker/apply_loop.py &
watch_pid=$!
/opt/rpmgr/docker/renew-loop.sh &
renew_pid=$!
runuser -u rpmgr -- /opt/rpmgr/venv/bin/uvicorn app.main:app \
    --host 0.0.0.0 --port 9443 \
    --ssl-keyfile /etc/rpmgr/admin.key --ssl-certfile /etc/rpmgr/admin.crt \
    --workers 1 --timeout-keep-alive 5 &
ui_pid=$!

shutdown() {
  trap - TERM INT
  echo '[ProxyCircuit] Shutting down ...'
  kill "$ui_pid" "$watch_pid" "$renew_pid" 2>/dev/null || true
  nginx -s quit 2>/dev/null || true
  wait "$ui_pid" "$watch_pid" "$renew_pid" 2>/dev/null || true
}
trap shutdown TERM INT EXIT

# The container terminates if a critical component exits; compose restarts it.
wait -n "$watch_pid" "$ui_pid" "$renew_pid" || true
exit 1
