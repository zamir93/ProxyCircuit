#!/usr/bin/env bash
# ProxyCircuit v0.2.3 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
# Safe in-place update for existing ProxyCircuit installations on Debian LXC.
set -Eeuo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then echo 'Bitte als root im ProxyCircuit-Container ausfuehren.' >&2; exit 1; fi
if [ "$#" -ne 0 ]; then
  echo 'Verwendung: bash scripts/update-debian.sh (keine host-spezifischen Reparaturflags)' >&2
  exit 2
fi
SOURCE="$(cd "$(dirname "$0")/.." && pwd)"
TARGET='/opt/rpmgr'
NGINX_CONFIG='/etc/nginx/conf.d/rpmgr-managed.conf'
NGINX_STREAM='/etc/nginx/rpmgr-stream.conf'
DB='/var/lib/rpmgr/rpmgr.sqlite3'
if [ ! -f "$TARGET/.rpmgr-installed" ] || [ ! -f "$TARGET/app/main.py" ]; then
  echo 'Keine bestehende ProxyCircuit-Installation gefunden.' >&2; exit 1
fi
if ! grep -Fq '0.2.3-beta' "$SOURCE/app/__init__.py"; then
  echo 'Updatepaket unvollstaendig oder Versionsfehler.' >&2; exit 1
fi
if systemctl is-active --quiet rpmgr-apply.service; then
  echo 'Der Konfigurationsarbeiter ist noch aktiv. Bitte spaeter erneut versuchen.' >&2; exit 1
fi
nginx -t
if command -v rpmgr-backup >/dev/null 2>&1; then
  echo 'Erstelle zuerst ein gesondertes Vollbackup mit Zertifikaten ...'
  rpmgr-backup
fi
install -d -m 0700 /var/backups/rpmgr
BACKUP="$(mktemp -d /var/backups/rpmgr/proxycircuit-0.2.3-XXXXXXXX)"
cp -a "$TARGET/app" "$BACKUP/app"
[ ! -f "$TARGET/README.md" ] || cp -a "$TARGET/README.md" "$BACKUP/README.md"
[ ! -f "$NGINX_CONFIG" ] || cp -a "$NGINX_CONFIG" "$BACKUP/nginx-managed.conf"
[ ! -f "$NGINX_STREAM" ] || cp -a "$NGINX_STREAM" "$BACKUP/nginx-stream.conf"
if [ -f "$DB" ]; then
  sqlite3 "$DB" ".backup '$BACKUP/rpmgr.sqlite3'"
  chmod 0600 "$BACKUP/rpmgr.sqlite3"
fi

rollback() {
  local status=$?
  trap - ERR
  echo "Update fehlgeschlagen (Exit $status). Stelle Anwendung, Datenbank und Nginx wieder her." >&2
  systemctl stop rpmgr-ui.service 2>/dev/null || true
  cp -a "$BACKUP/app/." "$TARGET/app/" 2>/dev/null || true
  [ ! -f "$BACKUP/README.md" ] || cp -a "$BACKUP/README.md" "$TARGET/README.md" || true
  if [ -f "$BACKUP/rpmgr.sqlite3" ]; then
    sqlite3 "$DB" ".restore '$BACKUP/rpmgr.sqlite3'" 2>/dev/null || true
    chown rpmgr:rpmgr "$DB" || true
    chmod 0600 "$DB" || true
  fi
  [ ! -f "$BACKUP/nginx-managed.conf" ] || cp -a "$BACKUP/nginx-managed.conf" "$NGINX_CONFIG" || true
  [ ! -f "$BACKUP/nginx-stream.conf" ] || cp -a "$BACKUP/nginx-stream.conf" "$NGINX_STREAM" || true
  nginx -t && systemctl reload nginx || true
  systemctl start rpmgr-ui.service 2>/dev/null || true
  systemctl start rpmgr-apply.path 2>/dev/null || true
  echo "Backup unter: $BACKUP" >&2
  exit "$status"
}
# Dependency stage while the existing UI still runs: fail safely before stopping services.
echo 'Neue Python-Abhaengigkeiten vorab installieren (SSH, mDNS, WebSocket) ...'
"$TARGET/venv/bin/python" -m pip install --disable-pip-version-check --no-cache-dir -r "$SOURCE/requirements.txt"
# Resolve the Uvicorn/websockets API compatibility BEFORE stopping the UI.
# An incomplete/unreadable websockets package may lack __version__, which Uvicorn imports.
# umask 077 can prevent the unprivileged rpmgr account from reading newly
# installed modules, so grant read/traversal to virtualenv files first.
chmod -R a+rX "$TARGET/venv"
runuser -u rpmgr -- "$TARGET/venv/bin/python" - <<'PY_DEPENDENCY_CHECK'
import fastapi, paramiko, zeroconf, websockets
if not getattr(websockets, "__version__", None):
    raise RuntimeError("websockets ohne __version__: Uvicorn inkompatibel")
from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol
print("WebSocket/Uvicorn-Abhaengigkeiten OK:", websockets.__version__)
PY_DEPENDENCY_CHECK
trap rollback ERR

echo '[1/5] Webdienst und Konfigurationswatcher fuer das Update anhalten ...'
systemctl stop rpmgr-apply.path
systemctl stop rpmgr-ui.service

echo '[2/5] Anwendung mit Rollen, SSL-Erneuerung und Domainverwaltung einspielen ...'
cp -a "$SOURCE/app/." "$TARGET/app/"
[ -f "$TARGET/app/default_page.html" ] || { echo "Standardseiten-Vorlage fehlt" >&2; false; }
chown -R root:root "$TARGET/app"
chmod -R a+rX "$TARGET/app"
cp -a "$SOURCE/README.md" "$TARGET/README.md"

echo '[3/5] Bestehende SQLite-Datenbank ohne Datenverlust migrieren ...'
runuser -u rpmgr -- env PYTHONPATH="$TARGET" "$TARGET/venv/bin/python" -c 'from app.db import init_db; init_db()'

# The root worker is sandboxed with ProtectSystem=strict.
# Add only the public fallback directory to its existing writable paths.
install -d -o root -g root -m 0755 /var/www/rpmgr-fallback
install -d -o root -g root -m 0755 /etc/systemd/system/rpmgr-apply.service.d
cat > /etc/systemd/system/rpmgr-apply.service.d/fallback-page.conf <<'SYSTEMD_FALLBACK'
[Service]
ReadWritePaths=/var/www/rpmgr-fallback
SYSTEMD_FALLBACK
systemctl daemon-reload
echo '[4/5] Standardseite und Nginx-Konfiguration generieren, testen und aktivieren ...'
systemctl start rpmgr-apply.service
nginx -t
systemctl start rpmgr-apply.path

echo '[5/5] Admin-Webdienst starten und Version pruefen ...'
systemctl start rpmgr-ui.service
ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl --silent --show-error --fail --insecure --max-time 3 https://127.0.0.1:9443/api/version 2>/dev/null | grep -Fq '0.2.3-beta'; then
    ok=1
    break
  fi
  sleep 1
done
[ "$ok" -eq 1 ]
systemctl is-active --quiet nginx
systemctl is-active --quiet rpmgr-ui.service
trap - ERR
printf '\nProxyCircuit v0.2.3-beta erfolgreich aktualisiert.\nBackup: %s\n' "$BACKUP"
printf 'Bestehende Zertifikate und Domainregeln wurden beibehalten; neue Funktionen wurden migriert.\n'
printf 'Hinweis: Adminzugang nur per HTTPS und moeglichst nur aus LAN/VPN verwenden.\n'
