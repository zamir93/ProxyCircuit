# ProxyCircuit v0.2.1 Beta — TLS- und Domain-Diagnose

Autor: Mohammad Zamir Akbari | https://zamir.akbari.org

- Lese-Diagnose zeigt die tatsaechlich geladene Nginx-Proxyregel inklusive TLS-Servernamen, CA-Pfad und Verifikationsmodus.
- Liest Zertifikat-Metadaten (DNS SAN, IP SAN, Ablaufdatum und SHA256-Fingerprint) auch bei nicht vertrauenswuerdiger Zertifikatskette.
- Diagnostischer GET bei Backend-TLS-Fehlern identifiziert HTTP-Status und Seitentitel des erreichten virtuellen Hosts, ohne Anmeldedaten und ohne dauerhafte Abschaltung der Zertifikatspruefung.
- Erkennt Unterschiede zwischen Datenbank und Nginx-Konfiguration.
- Keine Aenderung an vorhandenen Proxy-Regeln, Datenbankstruktur oder Zertifikatsvertrauen durch diese Diagnose.
