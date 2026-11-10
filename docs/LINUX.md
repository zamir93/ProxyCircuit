# Linux-/Debian-Installation – ProxyCircuit v0.2.3 Beta

Der bestehende **native Installer ist für Debian 12/13 mit systemd** vorgesehen. Testet man ihn auf Ubuntu, Alpine oder einem Docker-Container, bricht er bewusst ab. Für diese Plattformen ist keine unverändert unterstützte Native-Installation dokumentiert; Docker siehe `DOCKER.md`.

## Erstinstallation in leerem Debian 12/13 LXC oder dediziertem Debian-Server

```bash
# Als root im ZIEL-Linux (nicht auf dem Proxmox-Host):
cd /root/ProxyCircuit
bash scripts/install-debian.sh

# Falls nicht interaktiv installiert:
rpmgr-admin create-admin --user admin

systemctl status rpmgr-ui.service nginx rpmgr-apply.path --no-pager
curl -ksS https://127.0.0.1:9443/api/version
```

Der Installer richtet Nginx, SQLite, Zertifikatsverwaltung, Konfigurationsdienst, Backup-Timer und HTTPS-Administration auf Port 9443 ein. Keine zweite Nginx-Instanz parallel auf denselben Ports betreiben. Administrationsport durch Firewall/VPN begrenzen.

## Update einer vorhandenen Debian-Installation

```bash
# Vorher: Snapshot oder Vollbackup anlegen, Datenbanken und Zertifikate sichern.
cd /root/ProxyCircuit
bash scripts/update-debian.sh
curl -ksS https://127.0.0.1:9443/api/version
```

**Achtung:** Der Updatepfad wurde ursprünglich für die Beta-Versionslinie entwickelt. Erst mit Testcontainer, anschließend Produktion, nicht auf einem fremden Proxy-Host testen.

## CLI und Fehlerdiagnose

```bash
rpmgr-admin reset-password --user admin
nginx -t
journalctl -u rpmgr-ui.service -n 50 --no-pager
journalctl -u rpmgr-apply.service -n 50 --no-pager
```

## Allgemeines Linux

Das Programm verwendet Python 3, Nginx, SQLite, systemd für Worker-/Serviceverwaltung und Certbot. Eine systemd-freie Native-Installation außerhalb von Docker ist **noch nicht implementiert**. Die Quelle kann als Ausgangspunkt für weitere Linux-Distributionen dienen, gilt dort jedoch nicht als getestet.
