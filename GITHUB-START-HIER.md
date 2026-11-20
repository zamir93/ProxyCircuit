# ProxyCircuit v0.2.6 Beta - GitHub-Paket ohne Produktivdaten

**Autor:** Mohammad Zamir Akbari, https://zamir.akbari.org

Dieses Paket enthaelt den vollstaendigen Projektquellcode, aber **keine produktive SQLite-Datenbank**, keine Benutzer, Passwoerter, Zertifikatsschluessel, VPN-Privatschluessel oder Live-Konfiguration. Die Datenbank wird durch den Installer auf dem jeweiligen Zielserver neu erstellt; ein Administrator wird separat angelegt.

## Veröffentlichen

1. ZIP lokal entpacken. **Den Inhalt des Verzeichnisses `ProxyCircuit/`** im Repository ablegen (nicht die ZIP als einzige Datei hochladen).
2. Die Lizenz in `LICENSE-NOTICE.md` bewusst festlegen. Aktuell sind alle Rechte vorbehalten, das Repository ist also nicht automatisch freie Open-Source-Software.
3. `git status` und GitHub-Diff auf geheime Daten kontrollieren, erst dann pushen.
4. Release `v0.2.6-beta` als Pre-release anlegen. ZIP / tar.gz als Release-Anhaenge bereitstellen.

## Neue Debian-Installation

Nur auf einem eigenen **frischen Debian-12/13-System mit systemd** testen. `sudo bash scripts/install-debian.sh` installiert NGINX, die Dienste und die neue Datenbank. Danach interaktiv: `sudo rpmgr-admin create-admin --user admin`.

## Upgrade

Auf einem bereits eingesetzten System vorher ein separates Backup/Snapshot. `sudo bash scripts/update-debian.sh --check` fuehrt die Vorpruefung aus; `--apply` aktualisiert anschliessend die App und ihre restriktiven systemd-Konfigurationen. **Nicht in einem produktiven Netz ungeprueft ausfuehren.**

## Fehlerkorrekturen dieser GitHub-Ausgabe

- Bind-IP-Erkennung: AF_NETLINK erlaubt, iproute2-Fallback enthalten.
- Speichern: nur strukturelle Regelpruefung; Portkonflikte werden weiterhin vor einer NGINX-Aktivierung vom privilegierten Worker blockiert.
- `rpmgr-apply.service`: beschraenkte Schreibberechtigung fuer `/var/lib/nginx` im isolierten NGINX-Test.

Die geplanten eigenstaendigen Windows-/Linux-/Android-VPN-Clients mit AD-Anbindung sind **nicht** Bestandteil dieses Releases.
