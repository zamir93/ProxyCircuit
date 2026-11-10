# ProxyCircuit v0.2.1 Beta — Änderungsprotokoll

© 2026 Mohammad Zamir Akbari · https://zamir.akbari.org

- Rollenbasierte Mehrbenutzerverwaltung (Administrator, Bearbeiter, Leser) mit scrypt-Passwörtern und Session-Widerruf.
- Such-, Status- und Gruppenfilter, klappbare Hauptdomain-/Subdomain-Hierarchien, editierbare Kategorien.
- Checkboxen, atomare Domain-Massenaktionen, optionale Bereinigung nicht gemeinsam genutzter Zertifikate.
- Per-Klick-ACME-Erneuerung; manuelle PEM-Zertifikate lassen sich durch neu validierte Paare ersetzen.
- Eigener Upstream-HTTP-Host-Header pro Domain.
- Sicherheitsbewusste Backend-Diagnose: echte GET-Antworten, SNI, TLS/CA, Port, Netzwerkroute, DNS, TeamSpeak-/SIP-Erkennung.
- Alle aktiven Hosts im Monitoring, Vorvalidierung vor DB-Commit, SQLite- und Nginx-Backup plus Rollback bei Updates.
- 36 Regressionstests im Projektpaket.

Grenzen: öffentliches NAT/DNS, live certbot auf dem Zielsystem, alte NPM-Sonder-Configs und alle Upstreams werden nicht automatisch repariert. Beta, nicht als vollständige Produktionsfreigabe ausgeben.
