#!/bin/bash
# ProxyCircuit v0.2.0 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
# Restore only your own trusted rpmgr-backup archives; requires root.
set -Eeuo pipefail
umask 077
if [ "$(id -u)" -ne 0 ]; then echo 'Als root ausführen.' >&2;exit 1;fi
FILE="${1:-}"
if [ -z "$FILE" ] || [ ! -r "$FILE" ]; then echo 'Aufruf: rpmgr-restore /pfad/backup.tar.gz' >&2;exit 1;fi
if ! tar -tzf "$FILE" > /tmp/rpmgr-restore-list.$$; then echo 'Backup beschädigt' >&2;exit 1;fi
trap 'rm -f /tmp/rpmgr-restore-list.$$' EXIT
# Only allow expected paths and reject traversal. Symlink archives must be trusted.
if grep -Ev '^\./$|^\./etc/$|^\./etc/letsencrypt(/.*)?$|^\./var/$|^\./var/lib/$|^\./var/lib/rpmgr(/.*)?$' "/tmp/rpmgr-restore-list.$$" | grep -q .; then
  echo 'Nicht zugelassene Pfade im Backup' >&2;exit 1
fi
if grep -Eq '\.\./|^/' "/tmp/rpmgr-restore-list.$$"; then echo 'Unsichere Backup-Pfade!' >&2;exit 1;fi
if ! grep -q '^\./var/lib/rpmgr/rpmgr.sqlite3$' "/tmp/rpmgr-restore-list.$$"; then echo 'SQLite-Datenbank fehlt im Backup.' >&2;exit 1;fi
printf 'WARNUNG: Datenbank und Zertifikate werden ersetzt. Fortfahren? [ja/NEIN] '
read -r CONFIRM
if [ "$CONFIRM" != ja ]; then echo 'Abgebrochen';exit 1;fi
systemctl stop rpmgr-ui.service
# Existing state protected before restore; restore with the backend stopped.
/usr/local/sbin/rpmgr-backup
mkdir -p /var/lib/rpmgr
# Existing database replaced; certificate files restored as supplied.
tar -xzf "$FILE" -C /
chown -R rpmgr:rpmgr /var/lib/rpmgr
chmod 0750 /var/lib/rpmgr /var/lib/rpmgr/certs /var/lib/rpmgr/deploy || true
chmod 0600 /var/lib/rpmgr/rpmgr.sqlite3
systemctl start rpmgr-apply.service || true
systemctl start rpmgr-ui.service
printf 'Wiederherstellung durchgeführt. Nginx prüfen: journalctl -u rpmgr-apply -n 60\n'
