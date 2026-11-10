# ProxyCircuit v0.2.3 Beta

Autor: Mohammad Zamir Akbari | https://zamir.akbari.org

## Neue Funktionen

- **Domain-Kategorie-Tabs** in Proxy-Domains und Monitoring: Alle, benutzerdefinierte Kategorien und Hauptdomains mit Anzahl pro Kategorie.
- **Kompakte Kachelansicht** fuer Domains; Umschalten zur bisherigen Tabelle, Suche, Filter, Auswahl, Bearbeitung und Vollanalyse bleiben vorhanden.
- **Kategorisierte Monitoring-Kacheln** mit lesbarem Online-, Offline- und TLS-Status und Suchfeld.
- **Editierbare Standardseite** unter Verwaltung > Standardseite. HTML und CSS koennen bearbeitet, in einer isolierten Vorschau betrachtet, gespeichert und zurueckgesetzt werden. Nur Administratoren koennen speichern.
- Die Standardseite bleibt in der bestehenden SQLite-Datenbank gespeichert und damit in den normalen Backups.
- Nginx zeigt die HTML-Seite bei **unbekannten HTTP-Hosts (404)** und bei **502/503/504 von konfigurierten Hosts**. Der HTTP-Fehlerstatus bleibt korrekt bestehen. Gesunde Backends liefern weiterhin deren eigentlichen Inhalt.
- Eine separate 443-Default-Site behandelt unbekannte HTTPS-Hosts mit dem vorhandenen lokalen Admin-Zertifikat. Ein passendes Zertifikat fuer den unbekannten Host ist dadurch nicht garantiert; bei mismatch zeigt der Browser vor der HTML-Seite eine TLS-Warnung.
- Fehlerseiten mit `no-store`, `noindex`, restriktiver Content-Security-Policy und internem Nginx-Dateipfad.
- Erweiterung des systemd-Sandboxes fuer den Root-Konfigurationsworker nur um das oeffentliche Standardseiten-Verzeichnis `/var/www/rpmgr-fallback`.

## Daten und Sicherheit

- Bestehende Domainregeln, SSL-Zertifikate, Benutzer und sonstige Daten werden nicht umbenannt oder entfernt.
- Die HTML-Quelle liegt als Einstellung in `site_settings` (SQLite), das gerenderte Dokument unter `/var/www/rpmgr-fallback/__proxycircuit_error_page.html`.
- Keine Ausfuehrung von JavaScript, Web-Formularen, iframes oder eingebetteten Objekten in der Standardseite.
- Admin-API nur mit Session, Rolle `admin` und CSRF-Schutz fuer Aenderungen.
- TLS-Pruefung zu HTTPS-Backends bleibt eingeschaltet.

## Einschraenkungen

- DNS, Router/NAT, eine Serververbindung und bei HTTPS ein gueltiges Zertifikat bleiben Voraussetzungen. Eine HTML-Seite kann kein fehlendes DNS oder ungueltiges TLS-Zertifikat reparieren.
- Die Vorschau im Editor ist absichtlich in einem Sandbox-Iframe ohne Skriptausfuehrung.
- Bereits ausgelieferte Seiten mit HTTP 200 und falschem Inhalt (falsches Zielbackend) gelten nicht als Proxy-Fehler und werden nicht ersetzt.

## Installation

Nur im bestehenden ProxyCircuit LXC CT 150, nach dem Hochladen ins Verzeichnis `/root`:

```bash
cd /root
unzip -tq ProxyCircuit-v0.2.3-beta.zip && \
unzip -o ProxyCircuit-v0.2.3-beta.zip && \
cd /root/ProxyCircuit-v0.2.3-beta && \
bash scripts/update-debian.sh && \
curl -ksS https://127.0.0.1:9443/api/version
```

Erwartete Version: `{"version":"0.2.3-beta"}`.

Vorher zusaetzlich einen Proxmox-Snapshot bzw. ein CT-Backup erstellen. Das Skript sichert selbst Datenbank, Zertifikate und den alten Anwendungscode vor dem Update. Ein Update ist nicht gaenzlich risikofrei.
