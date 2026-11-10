# ProxyCircuit v0.2.3-beta — öffentliche Beta

**Veröffentlichungsstand:** GitHub-Quellpaket, Debian/Linux-Installer, experimenteller Docker-Compose-Build.

## Enthalten
- Reverse-Proxy-Domains (HTTP/HTTPS) einschließlich TLS-SNI, Backend-Diagnose und Zertifikatsverwaltung
- TCP/UDP-Weiterleitungen, Rollen und Admin-Panel
- Web-SSH, Netzwerk-Werkzeuge und mobile Darstellung
- Kategorisierte Domain-Tabs und kompakte Monitoring-Kacheln
- HTML-Standardseite bei 404/502/503/504, über Admin-Panel editierbar
- README, Installationsanleitungen, Screenshots und Tests

## Voraussetzungen / Hinweise
- **Beta**, kein Produktiv- oder Sicherheitszertifikat. Kein Nachweis aller Umgebungen.
- Debian-Systeminstallation: Debian 12/13, systemd, dedizierter Host oder LXC, root.
- Docker: separate Startlogik ohne systemd; Docker Engine und Compose erforderlich. In dieser Paketierungsumgebung stand **keine Docker Engine** für einen End-to-End-Start bereit.
- Port 80/443 muss exklusiv frei sein. Docker-Bridge erfordert Freigabe zusätzlicher TCP/UDP-Ports für Streams; mDNS-Multicast kann eingeschränkt sein.
- Das Repository enthält **keine** produktiven Nutzerdaten, Zertifikate oder Schlüssel.

## Vor einem echten GitHub-Release
- Repository erstellen/auswählen und ZIP-Inhalt pushen
- Lizenz mit Rechteinhaber festlegen
- Docker auf eigenem Testhost starten und Netzwerk-/Zertifikatsfunktionen verifizieren
- GitHub Release mit Tag `v0.2.3-beta` anlegen
