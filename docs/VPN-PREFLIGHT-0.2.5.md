# ProxyCircuit v0.2.5 Beta – VPN-Vorprüfung und sichere Testinstallation

**Autor:** Mohammad Zamir Akbari · https://zamir.akbari.org

## Sicherheitsgrenzen

v0.2.5 prüft nur Konfigurationen und lokale Gateway-Voraussetzungen. **Es startet keinen WireGuard-Tunnel, setzt keine Route und verändert keine Firewall.** Die Benutzeroberfläche hat keine WireGuard-Privatschlüssel. Alle neuen VPN-Domains bleiben initial deaktiviert. Aussagen wie „bereit für Gateway-Test“ bedeuten **nicht verbunden**.

## Sicherer Docker-Smoketest (separater Linux-/Docker-Testhost)

Die Projekt-Datei `compose.vpn-smoke.yaml` startet eine eigene Instanz und verwendet **nur Port 19445 auf 127.0.0.1** des Docker-Hosts. Sie publiziert keine produktiven HTTP-/HTTPS-Ports. Es wird der Compose-Projektname `pc-v025-smoke` benutzt: Dadurch werden keine Docker-Volumes von v0.2.3/v0.2.4 oder TeamSpeak verwendet.

```bash
cd ProxyCircuit
docker compose -p pc-v025-smoke -f compose.vpn-smoke.yaml config --quiet
docker compose -p pc-v025-smoke -f compose.vpn-smoke.yaml build
docker compose -p pc-v025-smoke -f compose.vpn-smoke.yaml up -d
docker compose -p pc-v025-smoke -f compose.vpn-smoke.yaml ps
curl -ksS --retry 12 --retry-connrefused --retry-delay 2 https://127.0.0.1:19445/api/version
```

Erwartete API-Version: `{"version":"0.2.5-beta"}`. Beim Docker-Build können kurzzeitig CPU/RAM/Plattenplatz genutzt werden. Bei LXC nur testen, wenn dort bereits Docker sicher funktioniert und ein aktuelles Backup existiert.

Ein **neues Test-Administratorkonto** (mit eigenem Passwort) erstellen:

```bash
docker compose -p pc-v025-smoke -f compose.vpn-smoke.yaml exec -it proxycircuit \
  runuser -u rpmgr -- /opt/rpmgr/venv/bin/python -m app.cli create-admin --user admin
```

Wenn `admin` bereits existiert, ist `reset-password --user admin` erforderlich; `create-admin` setzt ein vorhandenes Passwort nicht automatisch zurück.

Weboberfläche per SSH-Tunnel vom Windows-/Linux-Arbeitsplatz erreichbar (Beispiel; `<IP>` ersetzen):

```bash
ssh -N -L 19445:127.0.0.1:19445 root@<IP-DES-DOCKER-HOSTS>
```

Browser: `https://127.0.0.1:19445/` (Testzertifikat ist selbstsigniert). Admin-Port **nicht ins öffentliche Internet weiterleiten**.

## Im Admin-Panel

Unter **VPN-Standorte → VPN-Inbetriebnahme prüfen**:

1. Lokale LAN-Netze als kanonische RFC1918-CIDRs eintragen, beispielsweise `192.168.10.0/24` (bitte **reale** lokale Netze verwenden, nicht raten).
2. Hub-Adresse, Hub-Public-Key, Hub-Endpunkt und Remote-Peers eintragen.
3. Private Remote-Routen anlegen; überlappende lokale und entfernte Netzbereiche werden abgewiesen.
4. **Vorprüfung ausführen** – Blocker, Warnungen und den Konfigurations-Fingerprint prüfen.
5. **Bericht als JSON** sichern. Der Fingerprint zeigt, zu welcher Konfiguration die Prüfung gehört. Keine Geheimnisse enthalten.
6. **Gateway-Plan JSON exportieren**; nur an berechtigte Betreiber der separaten WireGuard-Gateway-VM geben.

Die Checks sind **statisch**; DNS, Firewall/NAT, echte Handshakes, Schlüsselbesitz und Routing müssen unabhängig geprüft werden.

## Read-only Gateway-Vorprüfung

Kopiere nur diese Dateien auf deine **eigene** Gateway-VM:

- `tools/wireguard_gateway.py`
- `tools/vpn_gateway_preflight.py`
- den JSON-Export des VPN-Plans

Auf der Gateway-VM (Python 3.11+, `iproute2` empfohlen):

```bash
python3 tools/vpn_gateway_preflight.py \
  --plan proxycircuit-wireguard-plan.json --role hub \
  --local-net 192.168.10.0/24
```

Für einen Remote-Standort statt Hub:

```bash
python3 tools/vpn_gateway_preflight.py \
  --plan proxycircuit-wireguard-plan.json --role spoke \
  --site-id <SITE-ID-AUS-JSON> --local-net 192.168.20.0/24
```

Das Skript prüft das Planformat, lokal bekannte/verbundene Netze, vorhandene Interfaces sowie am Hub einen möglicherweise belegten UDP-Listenport – ohne `sudo`, `wg-quick`, `iptables`, `ip route add`, `ip link add` oder Docker-Socket. Exit-Code 2 bedeutet **Blocker oder ungültiger Plan**. Meldung `ready_for_manual_test` ist **keine** Bestätigung für einen lebenden VPN-Tunnel.

**Wichtig:** Das Skript kann nicht garantieren, dass DNS/NAT/Rückroute korrekt sind; dies ist erst nach dem Aufbau eines eigenen Testtunnels feststellbar.

## Aufräumen – ausschließlich Testinstanz

**Nur nach Abschluss des Tests:**

```bash
docker compose -p pc-v025-smoke -f compose.vpn-smoke.yaml down --volumes
```

Das löscht ausschließlich die diesem Testprojekt zugeordneten Container/Volumes (Testdaten werden unwiederbringlich gelöscht). Vorhandene ProxyCircuit-Versionen und TeamSpeak-Container haben andere Compose-Projektnamen und sind davon nicht betroffen. Kein `docker system prune -a` verwenden.

## Bekannte Grenzen

- Kein automatisches `wg-quick up/down`, keine privilegierten Containerrechte.
- Kein authentifizierter Remote-Agent oder gesicherte Telemetrie.
- Nur IPv4 RFC1918, keine überlappenden Standortnetze und kein IPv6.
- Testcontainer bisher nicht auf der realen Infrastruktur des Anwenders ausgeführt.

## API

- `GET /api/vpn/local-networks` – lokale Netze, nur Admin.
- `PUT /api/vpn/local-networks` – lokale CIDRs speichern, nur Admin + CSRF.
- `GET /api/vpn/preflight` – Blocker/Warnungen, SHA256 des Konfigurationsstands, **keine** Aktivierung, nur Admin.

Die bisherigen API-Endpunkte, Proxy-Domains, Zertifikate und Rolle-/Sitzungsregeln bleiben bestehen.
