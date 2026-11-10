#!/bin/bash
# ProxyCircuit v0.2.3 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
# ProxyCircuit: dedicated NEW Debian LXC only.
set -Eeuo pipefail
umask 027
if [ "$(id -u)" -ne 0 ]; then echo 'Bitte als root ausführen.' >&2; exit 1; fi
. /etc/os-release
if [ "${ID:-}" != debian ]; then echo 'Dieser Installer unterstützt ausschließlich Debian 12/13.' >&2; exit 1; fi
case "${VERSION_ID:-}" in 12|13) ;; *) echo 'Debian 12 oder 13 erforderlich.' >&2; exit 1;; esac
if [ ! -d /run/systemd/system ]; then echo 'systemd muss im LXC-Container laufen.' >&2; exit 1; fi
if [ -d /data/nginx/proxy_host ] || [ -f /opt/npm/docker-compose.yml ]; then
  echo 'Bestehender Nginx Proxy Manager erkannt! Bitte einen NEUEN LXC-Container verwenden.' >&2; exit 1
fi
SOURCE="$(cd "$(dirname "$0")/.." && pwd)"
if [ ! -f "$SOURCE/app/main.py" ]; then echo 'Projektdateien nicht gefunden.' >&2; exit 1; fi
if [ -f /opt/rpmgr/.rpmgr-installed ]; then
  echo 'ProxyCircuit ist bereits installiert. Bitte scripts/update-debian.sh fuer Updates verwenden.' >&2;exit 1
fi
if [ -d /opt/rpmgr/app ] && [ ! -f /opt/rpmgr/.rpmgr-installed ]; then
  echo '/opt/rpmgr ist bereits belegt. Installation abgebrochen.' >&2;exit 1
fi
if [ -e /etc/nginx/rpmgr-stream.conf ] && [ ! -f /opt/rpmgr/.rpmgr-installed ]; then
  echo 'Nginx-Stream-Konfiguration vorhanden. Installation abgebrochen.' >&2;exit 1
fi
printf '\n[1/7] Debian-Abhängigkeiten installieren ...\n'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y nginx libnginx-mod-stream python3 python3-venv python3-pip \
  openssl certbot sqlite3 ca-certificates curl
if [ -d /etc/nginx/sites-enabled ]; then
  if find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 ! -name default | grep -q .; then
    echo 'Zusätzliche Nginx-Sites erkannt. Für Isolation bitte einen leeren Debian-LXC verwenden.' >&2;exit 1
  fi
fi
printf '\n[2/7] Benutzer, Verzeichnisse und Umgebung einrichten ...\n'
if ! id rpmgr >/dev/null 2>&1; then useradd --system --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr; fi
install -d -o root -g root -m 0755 /opt/rpmgr
cp -a "$SOURCE/app" /opt/rpmgr/
cp -a "$SOURCE/plugins" /opt/rpmgr/
cp "$SOURCE/requirements.txt" /opt/rpmgr/requirements.txt
cp "$SOURCE/README.md" /opt/rpmgr/README.md
chown -R root:root /opt/rpmgr/app /opt/rpmgr/plugins /opt/rpmgr/requirements.txt
python3 -m venv /opt/rpmgr/venv
/opt/rpmgr/venv/bin/python -m pip install --no-cache-dir -r /opt/rpmgr/requirements.txt
# The service account must traverse Python virtualenv files created with umask 027.
chmod -R a+rX /opt/rpmgr/venv
runuser -u rpmgr -- /opt/rpmgr/venv/bin/python - <<'PY_DEPENDENCY_CHECK'
import fastapi, paramiko, zeroconf, websockets
if not getattr(websockets, "__version__", None):
    raise RuntimeError("websockets ohne __version__: Uvicorn inkompatibel")
from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol
PY_DEPENDENCY_CHECK
for sub in '' deploy certs; do install -d -o rpmgr -g rpmgr -m 0750 "/var/lib/rpmgr${sub:+/$sub}"; done
install -d -o root -g root -m 0755 /var/www/rpmgr-acme /var/www/rpmgr-fallback
install -d -o root -g root -m 0755 /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /var/cache/nginx
install -d -o root -g rpmgr -m 0750 /etc/rpmgr
install -d -o root -g root -m 0755 /var/backups/rpmgr
chmod 0700 /var/backups/rpmgr

printf '\n[3/7] Lokales HTTPS-Zertifikat für das Admin-Panel ...\n'
if [ ! -s /etc/rpmgr/admin.key ] || [ ! -s /etc/rpmgr/admin.crt ]; then
  HOSTIP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -n "$HOSTIP" ]; then
    openssl req -x509 -nodes -newkey rsa:3072 -days 365 -sha256 \
      -keyout /etc/rpmgr/admin.key -out /etc/rpmgr/admin.crt \
      -subj '/CN=proxycircuit.local' -addext "subjectAltName=IP:$HOSTIP" >/dev/null 2>&1
  else
    openssl req -x509 -nodes -newkey rsa:3072 -days 365 -sha256 \
      -keyout /etc/rpmgr/admin.key -out /etc/rpmgr/admin.crt \
      -subj '/CN=proxycircuit.local' >/dev/null 2>&1
  fi
fi
chown root:rpmgr /etc/rpmgr/admin.key /etc/rpmgr/admin.crt
chmod 0640 /etc/rpmgr/admin.key /etc/rpmgr/admin.crt

printf '\n[4/7] Nginx-Konfigurationsisolation ...\n'
cp -an /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.pre-rpmgr.$(date +%Y%m%d%H%M%S)"
# Top-level include after http {}. Debian's stream module is loaded through modules-enabled.
if ! grep -Fq 'include /etc/nginx/rpmgr-stream.conf;' /etc/nginx/nginx.conf; then
  printf '\n# Managed by ProxyCircuit; top-level stream configuration\ninclude /etc/nginx/rpmgr-stream.conf;\n' >> /etc/nginx/nginx.conf
fi
if [ -L /etc/nginx/sites-enabled/default ]; then rm /etc/nginx/sites-enabled/default; fi
printf 'stream { }\n' > /etc/nginx/rpmgr-stream.conf
printf '# Managed HTTP configuration pending first apply\n' > /etc/nginx/conf.d/rpmgr-managed.conf
chmod 0644 /etc/nginx/rpmgr-stream.conf /etc/nginx/conf.d/rpmgr-managed.conf

printf '\n[5/7] systemd-Dienste installieren ...\n'
cat > /etc/systemd/system/rpmgr-ui.service <<'UNIT'
[Unit]
Description=ProxyCircuit HTTPS administration
After=network-online.target nginx.service
Wants=network-online.target
[Service]
Type=simple
User=rpmgr
Group=rpmgr
SupplementaryGroups=adm
WorkingDirectory=/opt/rpmgr
Environment=PYTHONPATH=/opt/rpmgr
ExecStart=/opt/rpmgr/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 9443 --ssl-keyfile /etc/rpmgr/admin.key --ssl-certfile /etc/rpmgr/admin.crt --workers 1 --timeout-keep-alive 5
Restart=on-failure
RestartSec=3
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/rpmgr
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/rpmgr-apply.service <<'UNIT'
[Unit]
Description=ProxyCircuit privileged configuration apply
After=nginx.service network-online.target
[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=/opt/rpmgr
Environment=PYTHONPATH=/opt/rpmgr
ExecStart=/opt/rpmgr/venv/bin/python -m app.worker
TimeoutStartSec=310
UMask=0027
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/nginx /var/lib/rpmgr /var/www/rpmgr-acme /var/www/rpmgr-fallback /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /var/log/nginx /var/cache/nginx /run
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/rpmgr-apply.path <<'UNIT'
[Unit]
Description=Watch for ProxyCircuit configuration changes
[Path]
PathExistsGlob=/var/lib/rpmgr/deploy/pending-*.json
Unit=rpmgr-apply.service
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/rpmgr-backup.service <<'UNIT'
[Unit]
Description=ProxyCircuit daily backup
[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/rpmgr-backup
UNIT
cat > /etc/systemd/system/rpmgr-backup.timer <<'UNIT'
[Unit]
Description=Daily Reverse Proxy Manager backup
[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
install -m 0750 "$SOURCE/scripts/backup.sh" /usr/local/sbin/rpmgr-backup
install -m 0750 "$SOURCE/scripts/restore.sh" /usr/local/sbin/rpmgr-restore
cat > /usr/local/sbin/rpmgr-admin <<'SCRIPT'
#!/bin/bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo 'Als root ausführen.' >&2;exit 1;fi
exec runuser -u rpmgr -- env PYTHONPATH=/opt/rpmgr /opt/rpmgr/venv/bin/python -m app.cli "$@"
SCRIPT
chmod 0750 /usr/local/sbin/rpmgr-admin
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/rpmgr-reload-nginx <<'SCRIPT'
#!/bin/sh
# Reload only after successful ACME renewal and config validation.
/usr/sbin/nginx -t && /bin/systemctl reload nginx && /bin/systemctl start rpmgr-apply.service
SCRIPT
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/rpmgr-reload-nginx

printf '\n[6/7] Nginx starten und initiale Konfiguration aktivieren ...\n'
systemctl daemon-reload
systemctl enable --now nginx
systemctl start rpmgr-apply.service || { journalctl -u rpmgr-apply.service -n 30 --no-pager;exit 1; }
# First root worker may create the SQLite database; grant ownership to service account.
if [ -f /var/lib/rpmgr/rpmgr.sqlite3 ]; then
  chown rpmgr:rpmgr /var/lib/rpmgr/rpmgr.sqlite3
  chmod 0600 /var/lib/rpmgr/rpmgr.sqlite3
fi
systemctl enable --now rpmgr-ui.service rpmgr-apply.path rpmgr-backup.timer
systemctl enable --now certbot.timer >/dev/null 2>&1 || true
printf '\n[7/7] Admin-Zugang anlegen ...\n'
if [ -t 0 ]; then
  if ! rpmgr-admin create-admin --user admin; then
    echo 'Admin konnte nicht erstellt werden. Manuell: sudo rpmgr-admin create-admin --user admin'
  fi
else
  echo 'Nicht-interaktive Installation: Admin manuell erstellen: sudo rpmgr-admin create-admin --user admin'
fi
touch /opt/rpmgr/.rpmgr-installed
HOSTIP="$(hostname -I 2>/dev/null | awk '{print $1}')"
printf '\n============================================================\n'
printf 'ProxyCircuit installiert.\n'
printf 'Admin-Panel: https://%s:9443\n' "${HOSTIP:-LXC-IP}"
printf 'Selbstsigniertes Admin-Zertifikat: einmalige Browser-Warnung ist normal.\n'
printf 'Nginx-Proxys: 80/TCP, 443/TCP (sobald Zertifikat zugewiesen).\n'
printf 'Port 9443 nur aus vertrauenswürdigen Netzen zugänglich machen!\n'
printf 'Status: systemctl status rpmgr-ui rpmgr-apply.path nginx\n'
printf 'Mehr Details: /opt/rpmgr/README.md oder beigelegte README im ZIP.\n'
printf '============================================================\n'
