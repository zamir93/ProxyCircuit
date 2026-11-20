# ProxyCircuit – Priorisierte Produkt-Roadmap

**Projekt:** ProxyCircuit | **Autor:** Mohammad Zamir Akbari | **Website:** https://zamir.akbari.org  
**Ausgangsbasis:** v0.2.4 Beta (VPN-Konfigurationsverwaltung)  
**Erster Entwicklungsmeilenstein:** v0.2.5 Beta (sichere Vorprüfung, keine Tunnelaktivierung)  
**Stand:** 11. November 2026

## Strategie

ProxyCircuit ist die **Steuerungsoberfläche**, nicht der privilegierte VPN-Router. VPN-Tunnel laufen auf **separaten** WireGuard-Gateways. Die bestehende ProxyCircuit-Installation (dem ProxyCircuit-Container) und der TeamSpeak-LXC mit Docker-Testcontainern (LXC 135) werden durch diese Entwicklung nicht verändert. Neue Module müssen getrennt aktualisierbar sein, sensible Schlüssel dürfen nicht in die Verwaltungsdatenbank und produktive Netzwerkänderungen benötigen einen ausdrücklichen Freigabeprozess.

**Definition of Done für jede Phase:** automatisierte Unit-/Integrationstests, Negativtests für Berechtigungen und ungültige Netzwerkdaten, aktualisierte Dokumentation, Migration ohne Datenverlust, prüfbares Rollback, isolierter Test ohne Auswirkungen auf bestehende Dienste. GitHub-CI-Erfolg ersetzt keinen realen Standorttest.

## Priorisierte acht Erweiterungen

| Prio | Thema | Zielrelease* | Abhängigkeit | Nutzwert | Abnahmebedingungen |
|---|---|---|---|---|---|
| **P0 / 1** | **Site-to-Site-VPN-Automatisierung** | v0.2.5–v0.2.7 | WireGuard-Gateways, Schlüsselverwaltung | Einrichtungsfehler verhindern, Tunnel kontrolliert aktivieren | Dry-run ohne Root/NET_ADMIN; sicherer Gateway-Agent mit Freigabe/Backup/Rollback; echter Handshake mit zwei getrennten Test-Gateways |
| **P0 / 2** | **Intelligenter VPN-Router & Netzwerkplanung** | v0.2.5–v0.2.7 | P0/1 | Saubere private IP-Routen, kein Standortkonflikt | CIDR-Überlappung erkennen; Gateway-/Rückrouten vorab prüfen; nur explizit erlaubte Netze; kein `0.0.0.0/0` durch Voreinstellung |
| **P1 / 3** | **Live-VPN-Monitoring** | v0.2.6–v0.2.7 | vertrauenswürdige Gateway-Metriken | Online/Offline, Handshake-Alter, RX/TX, Alarmierung | Telemetrie authentifiziert, zeitlich begrenzt; Unbekannt ≠ Online; Alarme bei Timeout; keine Private Keys übertragen |
| **P1 / 4** | **Remote-Domain-Manager** | v0.2.7 | Route + Tunnelstatus + TLS | Öffentliche Domain zu privater VPN-Ziel-IP | Bestehende Domains nicht überschreiben; neue bleiben deaktiviert; Aktivierung nur nach Erreichbarkeits-, TLS- und Routingprüfung |
| **P1 / 5** | **Firewall & Zero-Trust-Regeln** | v0.2.8 | Gateway-Agent, Rollenmodell | Zugriff nach Standort, Benutzer, Ziel/IP und Port | Default-deny; Simulation vor Übernahme; Regel-Diff; 2-Personen-Freigabe für kritische Änderungen; Rollback getestet |
| **P2 / 6** | **Remote-Agent Linux/Docker/Windows** | v0.2.9 | gesicherte Geräteidentität, Rollen | Remote-Hostzustand und Dienststatus zentral sehen | mTLS/kurzlebige Tokens; keine freie Shell als Standard; eingeschränkte Aktionen, Audit und Rate-Limits; Update signiert |
| **P2 / 7** | **VPN-Clients mit QR-Code** | v0.3.0 | Schlüssel-/Rechteverwaltung | Android, iOS, Windows, Linux anbinden | Schlüssel lokal auf Gerät, QR-Code nur zeitlich begrenzt sichtbar; Widerruf/Rotation; Gerätebegrenzung; IPv6-Plan |
| **P3 / 8** | **Proxmox-/Docker-Dashboard** | v0.3.1 | Remote-Agent + API-Scopes | Knoten, VMs, LXC, Container überwachen | API-Token mit Minimalrechten; read-only zunächst; Host-/LXC-RAM sauber unterscheiden; Alarm- & Fehlerprotokoll |

\* Releases sind **Planungsziele**, keine Zusage von Fertigstellungsdaten. Abhängigkeiten, Sicherheitsreview und echte Testhardware bestimmen die weitere Reihenfolge.

## Konkret: v0.2.5 Beta – jetzt implementierter erster Teil

**VPN-Readiness & Gateway Dry-run**

1. **Lokale LAN-Netze:** RFC1918-Netze, maximal 16 CIDRs, dedupliziert und gegen Remote-Routen sowie Tunnelnetz geprüft. **Datenbankmigration ist additiv**.
2. **Readiness-API:** `GET /api/vpn/preflight` liefert strukturierte Blocker/Warnungen/Infos sowie einen SHA256-Fingerabdruck des geprüften Konfigurationsstands. Die API **prüft keine echte Konnektivität**.
3. **UI-Workflow:** Admin-Bereich „VPN-Inbetriebnahme prüfen“ mit Ergebnissen und JSON-Bericht. Änderungen mit authentifizierter HTTPS-Sitzung und CSRF-Prüfung.
4. **Gateway-CLI (separat):** `tools/vpn_gateway_preflight.py` prüft einen exportierten Plan lokal auf einer Gateway-Maschine, liest nur Kernel-Routen, Interfaces und UDP-Listener und meldet Konflikte. Keine Änderungen an Firewall, Routing, Containern oder Schlüsseln.
5. **Isolierte Docker-Testumgebung:** `compose.vpn-smoke.yaml` mit eigenem Projekt, eigenem Volume-Satz und nur einem lokalen Admin-Port. Keine Freigabe von 80/443, keine WireGuard-UDP-Ports, keine `NET_ADMIN`-Capability und kein Docker-Socket.
6. **Erhaltene v0.2.4-Funktionen:** Hub-, Standort-, Routen- und Domainverwaltung, sichere Offline-Erzeugung von WireGuard-Konfigurationen.

**Nicht Bestandteil von v0.2.5:** automatische Gateway-Installation, echte Tunnel-/Routenaktivierung, Live-Handshake-Abfrage, Firewall-Deployment, Client-QR-Codes, Remote-Agenten, Proxmox-Verwaltung. Diese Funktionen werden nicht als bereits umgesetzt angezeigt.

## Folgende Meilensteine und Qualitäts-Gates

### Gate A – zwei eigene isolierte Test-Gateways (v0.2.6)

- WireGuard-Hub und Remote-Gateway als getrennte VMs bereitstellen; IPs/Subnetze außerhalb produktiver Netze.
- Gesicherter, minimal privilegierter Gateway-Agent mit bidirektionaler Authentifizierung; ausschließlich vordefinierte Aktionen.
- Testablauf: Plan → Dry-run → Backup → ausdrückliche Zustimmung → Konfiguration atomar bereitstellen → Tunnel starten → Handshake und erlaubten Dienst testen → kontrolliertes Rollback.
- **Stop-Kriterium:** Ein fehlgeschlagener Test lässt bestehende Tunnel/Firewall/TeamSpeak/ProxyCircuit unverändert.

### Gate B – Routing, Monitoring und Domainfreigabe (v0.2.7)

- Mehrere IPv4-Netze, Policy-Routing, Rückrouten und begrenzte Firewallregeln testen.
- Gateway-Telemetrie als signierte/zugangsgeschützte Daten, mit Zeitstempel, Unbekannt-Zustand und Timeout.
- Domain-Erreichbarkeit aus dem **tatsächlichen Proxy-Netzwerk-Namespace**, Host-Header/TLS/SNI prüfen; erst danach explizit aktivieren.

### Gate C – Security Review (v0.2.8)

- Nutzer-/Standort-/Subnetz-/Portrechte nach Default-deny; CSRF, RBAC, Audit, Backup und Rollback testen.
- Bedrohungsmodell: kompromittierter Peer, gestohlener Agent-Token, manipulierte Route, DNS-Rebinding, Web-SSH-Missbrauch, CI- und Update-Supply-Chain.

### Gate D – Agents und Plattformintegration (v0.2.9–v0.3.1)

- Remote-Agenten zuerst **nur lesend**; signierte Releases und gestufte Updates.
- Clientprofile mit eigenem Schlüsselmanagement und Widerruf.
- Proxmox-/Docker-Schnittstellen mit streng minimalen Berechtigungen; vorhandene produktive Cluster nicht für Entwicklungstests benutzen.

## Offene Architekturentscheidungen

- Gateway-Agent: eigener isolierter systemd-Dienst auf Debian-VM, keine Privilegien in der ProxyCircuit-Weboberfläche.
- Authentifizierung und signiertes Planformat, Schlüsselspeicher, Rotation, Wiederherstellung.
- Überlappende Kundennetze: zunächst **ablehnen**, später bewusstes NAT/VRF-Design pro Mandant.
- IPv6, Hochverfügbarkeit, DNS-Auflösung und NAT-Traversal gesondert planen.
- Dokumentierte Restore- und Failover-Verfahren vor produktiver automatischer Aktivierung.

## Sichere Testumgebung

`docs/VPN-PREFLIGHT-0.2.5.md` beschreibt das neue isolierte Docker-Profil und die lesende Gateway-CLI. Alle im Test angelegten Daten liegen in ausdrücklich getrennten Docker-Volumes und können separat entfernt werden.
