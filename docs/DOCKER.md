# Docker Compose – ProxyCircuit v0.2.3 Beta

**Experimentelles Docker-Beispiel für Linux Docker Engine + Docker Compose v2.** Ein Docker-End-to-End-Test war in der Build-Umgebung mangels Docker-Daemon **nicht** möglich. Zuerst auf einem separaten Testserver durchführen.

## Voraussetzungen

- Linux mit Docker Engine und `docker compose`
- Freie Host-Ports 80/tcp und 443/tcp
- DNS und NAT auf die IP des Docker-Hosts, wenn öffentlich zugänglich
- SSH/VPN-Tunnel für den Admin-Port 9443
- Keine andere Proxy-Software, die Port 80/443 bereits belegt

## Installation

```bash
# Im entpackten Repository-Verzeichnis:
docker compose build
docker compose up -d
docker compose ps
docker compose logs --tail=80 proxycircuit

# Admin ohne festes Standardpasswort erstellen (interaktiv):
docker compose exec -it proxycircuit \
  runuser -u rpmgr -- /opt/rpmgr/venv/bin/python -m app.cli create-admin --user admin

# Dienst direkt auf dem Docker-Host prüfen:
curl -ksS https://127.0.0.1:9443/api/version
```

Admin über verschlüsselten SSH-Tunnel auf dem Arbeitsplatz öffnen:

```bash
ssh -L 9443:127.0.0.1:9443 <linux-benutzer>@<docker-host>
# Im lokalen Browser: https://127.0.0.1:9443
```

Das Zertifikat des Admin-Panels ist anfangs selbstsigniert. Für eine vertrauenswürdige Verbindung hinter eigenem HTTPS-Reverse-Proxy oder über VPN ein geeignetes Zertifikat und SNI einrichten.

## Betriebsmodell

Der Container enthält Nginx, die unprivilegierte FastAPI-UI, einen lokalen Root-Konfigurations-Worker und einen Certbot-Renew-Loop. Es wird **kein** `systemd` und **kein** Mount des Docker-Sockets verwendet. Der Root-Worker ist erforderlich, um Nginx-Konfiguration und Zertifikate zu verwalten. Docker ist daher separat vom Standard-Debian-Installer implementiert.

Die 6 persistenten Docker-Volumes speichern SQLite-Datenbank, Zertifikate, Let's-Encrypt-Daten, HTTP-01-Webroot, Standardseite und Logdateien. **Vor Updates alle Volumes extern sichern.** Das Debian-Backup-Skript ist nicht automatisch der Docker-Backup-Mechanismus.

## TCP/UDP-Weiterleitungen

Zusätzliche Stream-Ports sind nicht automatisch publiziert. Beispiel für TeamSpeak-UDP zusätzlich unter `ports:` in `compose.yaml`:

```yaml
      - '9987:9987/udp'
```

`docker compose up -d` danach erneut ausführen. mDNS-Multicast und Wake-on-LAN-Broadcast können im Docker-Bridge-Netz eingeschränkt sein. Für diese Funktionen ist ein gesondert geprüftes LAN-Konzept nötig; Container nicht allein dafür unkontrolliert privilegieren.

## Diagnose

```bash
docker compose ps
docker compose logs --tail=120 proxycircuit
docker compose exec proxycircuit nginx -t
docker compose exec proxycircuit /opt/rpmgr/venv/bin/python -m app.worker
docker compose exec proxycircuit curl -ksS https://127.0.0.1:9443/api/version
```

## Sicherheitsgrenzen

- Der Docker-Hostport 9443 ist bewusst nur an `127.0.0.1` gebunden; nicht unbedacht weltweit veröffentlichen.
- Web-SSH, Scanner und Forward-Proxy nur in eigenen/autorisierten Netzen nutzen.
- Zertifikate und SQLite-Datenbank nie ins Git-Repository übernehmen.
- Vor Einsatz mit produktiven Domänen das Verhalten von ACME, WebSockets, UDP und TLS prüfen.
