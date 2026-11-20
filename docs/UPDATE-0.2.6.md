# ProxyCircuit v0.2.6 – Testen, Update und Rollback

**System:** Debian 12/13 LXC / Proxmox, bestehendes Python/FastAPI/NGINX/SQLite-Projekt. **Nicht für UGREEN-UPK.**

## 1. Vorab: nichts am Produktivsystem ändern

- Produktivcontainer: **dem ProxyCircuit-Container auf Proxmox `pve` (192.0.2.9)**, Proxy-IP `192.0.2.150`, derzeit eine frühere ProxyCircuit-Version.
- Isolierter Docker-Test: **einem getrennten Testcontainer auf Proxmox `proxmox` (192.0.2.4)**, IP `192.0.2.80`; TeamSpeak und bestehende Beta-Container müssen unberührt bleiben.
- **Vor jedem produktiven Eingriff:** Proxmox-Snapshot/CT-Backup, aktueller SQLite-Dump und `/etc/letsencrypt` sowie `/var/lib/rpmgr/certs` extern sichern; freien Speicher prüfen. Kein Live-Update ohne Freigabe.

## 2. Isolierter erster Docker-Test auf einem getrennten Testcontainer

Entpacke das Quellcode-/Docker-Paket in `/opt/proxycircuit-v026/ProxyCircuit`, dann:

```bash
cd /opt/proxycircuit-v026/ProxyCircuit

docker compose -p pc-v026-smoke -f compose.v026-smoke.yaml config --quiet
docker compose -p pc-v026-smoke -f compose.v026-smoke.yaml build
docker compose -p pc-v026-smoke -f compose.v026-smoke.yaml up -d
docker compose -p pc-v026-smoke -f compose.v026-smoke.yaml ps
curl -ksS --retry 12 --retry-connrefused --retry-delay 2 https://127.0.0.1:19446/api/version
```

Erwartet `{"version":"0.2.6-beta"}`; der Docker-Container bindet nur den **Loopback-Admin-Port 19446**, **keine** öffentlichen 80/443 und **keine** Host-WireGuard-/NET_ADMIN-Rechte. Der Testcontainer hat einen eigenen Volume-Satz. Für ein Login im Test muss der Admin separat angelegt werden:

```bash
docker exec -it -u rpmgr -w /opt/rpmgr proxycircuit-v026-smoke \
  /opt/rpmgr/venv/bin/python -m app.cli create-admin --user admin
```

**Achtung:** Docker verwendet den Container-Netzwerk-Namespace; eine auf dem Host `192.0.2.80` vorhandene Adresse steht dort nicht notwendigerweise als lokale Bind-IP zur Verfügung. Echte Mail-/DNS-Portregeln daher erst in einem **separaten nativen Debian-Test-LXC** prüfen.

## 3. Produktivserver – nur Vorprüfung

Auf Windows das vollständige ZIP per SCP an einen geeigneten Proxmox-/LXC-Server übertragen; in **dem ProxyCircuit-Container** unter `/root/` entpacken.

```bash
cd /root/ProxyCircuit
bash scripts/update-debian.sh --check
```

Diese Aktion führt **keine Migration, keinen Restart und keinen Reload** aus. Sie liest die DB, NGINX-Konfiguration, vorhandene Portbelegungen, IP-Adressen und meldet erkannte Konflikte. Wenn zuvor eine Wildcard-Regel `0.0.0.0:25` mit Postfix kollidierte, wird dies gemeldet; keinesfalls Postfix stoppen.

## 4. Erst nach Freigabe produktiv aktualisieren

```bash
# In dem ProxyCircuit-Container; nur nach erfolgreichem Backup/Snapshot und Abnahme im Test.
cd /root/ProxyCircuit
bash scripts/update-debian.sh --apply
```

Dabei wird ein Backup von App, Datenbank, NGINX-Includes und Zertifikaten angelegt. Neue Spalte `streams.bind_ip` wird für alte Regeln mit `0.0.0.0` befüllt. Danach kann im Admin-Panel `TRANSPORTLAYER → TCP/UDP Portregeln → Bearbeiten` die konkrete lokale IP zugewiesen werden, z. B. `192.0.2.150`.

**Beispiel SMTP KeyHelp:** TCP `192.0.2.150:25` → `192.0.2.236:25` (10s Connect, 300s Proxy). Vorher prüfen, dass diese LAN-IP tatsächlich lokal vorhanden ist. Die externe Firewall/NAT-Regel bleibt ein eigener Schritt.

## 5. Nach Update prüfen

```bash
curl -ksS https://127.0.0.1:9443/api/version
nginx -t
systemctl is-active nginx rpmgr-ui.service rpmgr-apply.path
journalctl -u rpmgr-apply.service -n 80 --no-pager
ss -lntup | grep -E '(:25|:465|:587|:993|:53|:443|:80)'
```

Unter `Diagnose & Monitoring` die tatsächlich aktive Konfiguration und den Verlauf prüfen. Domain `admin.example.org` mit **SNI** untersuchen; erwartet wird bei erreichbarem gesperrtem C-Mail-Backend eventuell `HTTP 401` – **das Zertifikat muss trotzdem zu `admin.example.org` passen**. Ein einzelner TCP-Connect beweist nicht die Funktionsfähigkeit des SMTP-/IMAP-Protokolls. Bei jeder Portregel `Verbindung prüfen` verwenden.

## 6. Rollback

**Vollständiges Upgrade-Rollback:** Bei einem Upgradefehler versucht das Skript, Quelldateien und SQLite-Backup wiederherzustellen. Prüfe immer Service-/Nginx-Status nach einem Fehler; vorherigen CT-Snapshot bei unvollständigem Rollback manuell zurückspielen.

**Nur Live-NGINX-Konfiguration (kein DB-Rollback):** Root-Snapshot-ID aus `/var/lib/rpmgr/deploy/status.json` oder aus der Historie lesen. Testen, ohne etwas zu verändern:

```bash
cd /opt/rpmgr
/opt/rpmgr/venv/bin/python -m app.worker --check-live-restore SNAPSHOT_ID
```

Nach genauer Prüfung und nur mit expliziter Freigabe:

```bash
cd /opt/rpmgr
/opt/rpmgr/venv/bin/python -m app.worker --restore-live SNAPSHOT_ID --apply
```

**Wichtig:** Die Live-Wiederherstellung verändert die gespeicherten Wunschregeln **nicht**. Beim nächsten Deploy könnten die fehlerhaften Wunschregeln erneut zur Aktivierung anstehen. Korrigiere sie vorher oder stelle das vollständige DB-Backup wieder her.

## 7. Optionale Administrator-MFA

Im Admin-Panel: `Benutzer & Rechte → TOTP-MFA → Authenticator einrichten`; Geheimnis in einer Authenticator-App manuell hinterlegen; Code bestätigen. Künftige Logins benötigen Passwort und Einmalcode. Ein bereits verwendeter Code kann nicht erneut eingesetzt werden; nach dem Einrichten ggf. nächsten 30-Sekunden-Code abwarten. Bei Verlust des Geräts per **lokaler Root-Konsole**:

```bash
rpmgr-admin disable-mfa --user admin
```

Die Datenbank und Backups enthalten den geheimen TOTP-Schlüssel; Backups verschlüsselt und mit restriktiven Dateirechten verwahren.

## 8. Veröffentlichung

Der Quellcode bleibt lokal. **GitHub wird jetzt nicht geändert.** Erst nach bestandenem Test, technischer Abnahme und deiner Freigabe wird ein Commit/Release im vorhandenen Projekt `zamir93/ProxyCircuit` vorbereitet.
