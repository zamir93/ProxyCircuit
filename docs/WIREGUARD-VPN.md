# ProxyCircuit VPN v0.2.4 Beta – WireGuard-Standorte

**Autor:** Mohammad Zamir Akbari · https://zamir.akbari.org  
**Status:** Konfigurations-/Provisionierungs-Beta, bewusst **ohne automatisches VPN-Deployment**.

## Architektur und Vertrauensgrenzen

```text
Öffentliche Domain (DNS) ───▶ ProxyCircuit (Reverse Proxy / Control Plane)
                                   │  IP-Routing über LAN-Gateway (manuell)
                                   ▼
                            WireGuard-Hub (separate VM)
                                   ║  WireGuard UDP, verschlüsselt
                            Remote-Gateway (anderer Standort)
                                   │  LAN-Forwarding + Rückroute/SNAT
                                   ▼
                          Remote-Dienst 192.168.20.10:8080
```

Das Web-Panel verwaltet **öffentliche Schlüssel**, private IPv4-Netze, Gateways und Domain-Zuordnungen.
Es speichert **keine WireGuard-Private-Keys**, startet **kein** `wg-quick`, führt **keine** Firewall- oder Betriebssystem-Routenänderungen aus und gibt **keine** tatsächliche VPN-Erreichbarkeit vor.

**Sicherheit:** Wir empfehlen eine eigene Debian-VM als VPN-Hub. Der vorhandene ProxyCircuit-Container und TeamSpeak-Container benötigen weder Root-/NET_ADMIN-Rechte noch einen Docker-Socket-Zugriff für das VPN-Modul.

## Vorbereitung – sicherer Einrichtungsablauf

1. **Separate** Debian-VM für Hub und je einen Linux-Router/VM am Remote-Standort vorbereiten, WireGuard installieren: `sudo apt update && sudo apt install wireguard-tools`.
2. Auf **jeder Gateway-Maschine selbst** ein eigenes Schlüsselpaar erzeugen (niemals in ProxyCircuit oder GitHub hochladen):

   ```bash
   sudo install -d -m 0700 /etc/wireguard
   sudo sh -c 'umask 077; wg genkey > /etc/wireguard/pc-vpn.key; wg pubkey < /etc/wireguard/pc-vpn.key > /etc/wireguard/pc-vpn.pub'
   sudo cat /etc/wireguard/pc-vpn.pub
   ```

3. In **ProxyCircuit → VPN-Standorte** zuerst Hub-Interface (Standard `wg-pc0`), Hub-IP (z.B. `10.77.77.1/24`), **öffentlichen** Hub-Endpunkt (DNS/IP), UDP-Port, Hub-Public-Key sowie optional die LAN-IP der separaten Gateway-VM eintragen.
4. Remote-Standort hinzufügen: Name, **Public Key des Remote-Gateways**, Peer-Tunnel-IP (z.B. `10.77.77.2`) und optional dessen öffentlichen Endpunkt/UDP-Port.
5. Gewünschte **private Remote-Netzroute** wie `192.168.20.0/24` hinzufügen. Überschneidende Netze werden abgelehnt. Überlappende Netze zwischen den *realen* Standorten ebenfalls separat prüfen!
6. `Gateway-Plan JSON exportieren` wählen (`proxycircuit-wireguard-plan.json`). Dieser Export enthält keine privaten Schlüssel. Nur an autorisierte Gateway-Administratoren übertragen.

## Offline-Gateway-Konfiguration erzeugen

`tools/wireguard_gateway.py` ist ein **eigenständiges Python-3-Standardbibliothek-Werkzeug**. Auf die Gateway-VM werden ausschließlich dieses Skript und der JSON-Plan kopiert, nicht der gesamte ProxyCircuit-Server. Benötigt: Python 3.11+ und `wg` aus `wireguard-tools`. Für die sichere Schlüsselpaar-Prüfung muss das `wg`-Programm auf dem Gateway verfügbar sein.

Hub (private Key bleibt nur auf Hub-VM):

```bash
sudo python3 tools/wireguard_gateway.py \
  --plan proxycircuit-wireguard-plan.json --role hub \
  --private-key-file /etc/wireguard/pc-vpn.key \
  --output /etc/wireguard/wg-pc0.conf
```

Remote-Gateway (seine eigene Site-ID aus JSON einsetzen):

```bash
sudo python3 tools/wireguard_gateway.py \
  --plan proxycircuit-wireguard-plan.json --role spoke --site-id SITE_ID \
  --private-key-file /etc/wireguard/pc-vpn.key \
  --output /etc/wireguard/wg-pc0.conf
```

Das Tool prüft die Übereinstimmung der Public Keys über `wg pubkey`, erzwingt Private-Key-Dateirechte und erstellt neue Konfigurationsdateien ausschließlich mit Modus `0600` (kein Überschreiben). Es **startet nichts** und verwendet **keine Shell** für Nutzereingaben.

Nach Sichtprüfung der generierten Konfigurationen, der Gateways, Router, Firewall und zulässigen Routen, **manuell auf den Gateways** (nicht im ProxyCircuit-Container):

```bash
sudo wg-quick up wg-pc0
sudo wg show wg-pc0
sudo systemctl enable wg-quick@wg-pc0
```

Zurücknehmen: `sudo wg-quick down wg-pc0`; die `systemctl enable`-Option erst verwenden, wenn der Tunnel vollständig geprüft ist. Die WireGuard-Seite des Hubs benötigt eingehend **UDP 51820** (oder deinen eingetragenen Port), z. B. via Firewall/NAT. Eine Portweiterleitung 80/443 zum VPN-Gateway ist **nicht** erforderlich.

**Wichtig:** Auf dem Remote-Gateway muss IPv4-Forwarding aktiviert und die Firewall für den konkreten erlaubten Quell-/Zielverkehr freigeschaltet werden. Das Remote-LAN braucht eine **Rückroute zur Hub-Quelladresse** oder eine sorgfältig eingegrenzte SNAT-Regel. Falls der Reverse Proxy auf einer separaten Maschine steht, braucht er eine **Route zum Remote-Netz über die LAN-IP der Hub-VM**; auch das Remote-Netz benötigt eine passende Rückroute. Bei Docker wird das Quellnetz des Docker-Bridge-Namespace separat berücksichtigt. Keine pauschalen `0.0.0.0/0`-Routen oder unkontrolliertes Masquerading.

## Domain-Anbindung

Eine öffentliche Domain muss per DNS-A-Record auf die öffentliche Reverse-Proxy-Adresse zeigen. Neue VPN-Domains werden in ProxyCircuit standardmäßig **deaktiviert** erzeugt; sie zeigen auf die private Ziel-IP/Port des entfernten Dienstes.

Nach erfolgreichem WireGuard-Tunnel- und Firewall-Test: Ziel aus dem Netzwerk-Namespace des **Reverse Proxys** mit `curl`, `ip route get` und ggf. TLS-Namen prüfen; ggf. SSL-Zertifikat in ProxyCircuit zuweisen und Domain erst danach aktivieren. Die VPN-Maske ändert keine existierenden Domains oder Zertifikate automatisch.

## Einschränkungen dieser Beta

- Nur IPv4-/RFC1918-Remote-Netze; kein IPv6, keine dynamische Standortentdeckung.
- Kein automatisches `wg-quick`, kein privilegierter Remote-Agent, keine automatische Schlüsseldistribution/Rotation.
- Hub-/Remote-Konfiguration **muss** manuell aktiviert und regelmäßig gepflegt werden. Das UI zeigt bewusst *konfiguriert* statt *verbunden*.
- Die Portal-API führt keine automatisch extern erreichbaren IP-/Port-Scans durch. Bestehende Proxy-Domain-Diagnose kann benutzt werden, sobald Routing eingerichtet ist.
- Vor produktiver Anwendung: unabhängiger Sicherheitsreview, Firewall-Prüfung, Test mit zwei eigenen WireGuard-Gateways, DNS-/Zertifikatstest und Backup.

**Keine automatische Änderung an dem ProxyCircuit-Container, LXC 135, Nginx, Router/NAT oder bestehenden Proxy-Domainregeln.**

## Ergänzung v0.2.5 – sichere Inbetriebnahme-Vorprüfung

Vor jeder manuellen Tunnelaktivierung zunächst im Panel lokale Netze speichern und **Vorprüfung ausführen**. Den JSON-Bericht mit Konfigurations-SHA256 sichern. Für getrennte Linux-WireGuard-Gateways zusätzlich das lesende `tools/vpn_gateway_preflight.py` verwenden. Details und isolierter Docker-Test: [VPN-PREFLIGHT-0.2.5.md](VPN-PREFLIGHT-0.2.5.md). **Kein automatischer Tunnelstart in v0.2.5.**
