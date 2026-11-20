# ProxyCircuit v0.2.6 Beta – Bind-IP, sicherer Deploy und Diagnose

Autor/Entwickler: **Mohammad Zamir Akbari** · https://zamir.akbari.org

## Implementiert

1. **Bind-IP für TCP und UDP:** IPv4/IPv6, `0.0.0.0` (alle IPv4-Interfaces), `::` (IPv6-Wildcard), lokale Interface-Adressen per Admin-API, Auswahl in Hinzufügen-/Bearbeiten-Dialogen, Datenbankmigration. Alte Portregeln erhalten zunächst `0.0.0.0`.
2. **Adressbewusste Konflikte:** Zwei getrennte IPs können denselben TCP- oder UDP-Port verwenden; Wildcard-/IPv6-Überlappung wird blockiert. Fremde Prozesse wie Postfix werden nur gelesen und niemals beendet. Eine konkrete Adresse wird auf dem Proxy-Host geprüft, bevor eine Regel aktiv wird.
3. **Sichere Aktivierung:** Generierte HTTP-/Stream-Konfiguration isoliert prüfen, Live-Includes atomar ersetzen, vollständiges `nginx -t`, Reload, neue Worker-Generation nachweisen und tatsächliche Listener mit korrekter Bind-IP prüfen. Bind-Fehler aus dem NGINX-Log erkennen. Bei Fehler NGINX-Includes/Fehlerseite zurückrollen und Zustand melden.
4. **Versionierung:** Sichere Root-Snapshots der NGINX-Dateien, Datenbank-Aktivierungsverlauf, SHA256 und begrenzter diff-basierter Konfigurationsvergleich. Manuelle Wiederherstellung einer Live-NGINX-Version nur per Root-CLI; gespeicherte Datenbankregeln werden bei dieser Aktion nicht überschrieben.
5. **TLS/HTTPS-Diagnose:** Aktuell ausgeliefertes Zertifikat mit korrektem SNI prüfen, SAN/Domain-Abgleich, Ablaufdatum, SHA256-Fingerabdruck und HTTP-Status. HTTP 401 gilt als erreichbarer geschützter Dienst, nicht als Routingfehler.
6. **Monitoring:** NGINX-Haupt-/Worker-Prozesse, Aktivierungszustand, Portdiagnose, Portkonflikte und Backend-Erreichbarkeit im Bereich „Diagnose & Monitoring“.
7. **Sicherheit:** Vorhandene RBAC-/CSRF-/Audit-Sicherung erhalten. Optionales TOTP-MFA für Administratoren mit Replay-Schutz, Setup und Deaktivierung per Authenticator. Notfall-Deaktivierung nur über lokale CLI.
8. **Sicherer Upgradepfad:** `scripts/update-debian.sh --check` (read-only) / `--apply` (mit Backup und automatischem Code-/SQLite-Rollback bei Upgradefehler); Kollision bestehender gewünschter Portregeln verhindert nicht den Zugang zur neuen Admin-Oberfläche, sofern die letzte NGINX-Konfiguration weiterhin aktiv ist.
9. **Bestehende Funktionen:** Zielpfade, HTTP/HTTPS, WebSocket, ACME, VPN-Vorprüfung, Plugins, Web-SSH und Netzwerk-Werkzeuge bleiben im Quellcode erhalten.

## Wichtige Grenzen

- NGINX kann mit `nginx -t` erfolgreich validieren und beim Reload trotzdem fehlschlagen. Diese Version prüft nach dem Reload Worker und Socketbelegung. Produktionsverhalten muss trotzdem auf dem echten Debian-LXC verifiziert werden.
- Ein „gespeicherter“ Datensatz ist bei einem fehlerhaften Reload **nicht automatisch aktiv**. Die Datenbank hält den gewünschten Zustand für Korrekturen vor.
- Manuelles Zurücksetzen einer alten Live-NGINX-Konfiguration ändert die gewünschten DB-Regeln nicht; nächster Deploy kann sie überschreiben. Für vollständige Wiederherstellung Datenbank-/Zertifikatsbackup nutzen.
- Live-WireGuard-Tunnelautomatisierung und vollständige Protokolltests (SMTP/IMAP/DNS) sind **nicht** Bestandteil dieser Version. Keine angegebene 1:1-Funktionsparität zur separaten UGOS-Anwendung.
- Keine automatische Veränderung von Proxmox, KeyHelp, Postfix, TeamSpeak oder vorhandenen Docker-Containern.

## Teststatus

**113 automatisierte Tests bestanden**, darunter neue Tests für lokale IPs, SQLite-Migration, Wildcard-Konflikte, NGINX-Rollback nach falsch positivem Reload, TLS-SNI-Zertifikate und TOTP-Login. Siehe `docs/TESTBERICHT-0.2.6.md`.
