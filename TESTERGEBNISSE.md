# ProxyCircuit v0.2.1 Beta – Prüfung vor Auslieferung

Autor: Mohammad Zamir Akbari · https://zamir.akbari.org

Die folgenden Prüfungen wurden am Quellpaket ausgeführt:

- 37 Python-Unittests: bestanden. Enthalten sind API-Anmeldung, serverseitige HTTP-Login-Sperre, Rollen-/Sitzungsrechte, Host- und Stream-CRUD, Massenaktionen, gemeinsame Zertifikate, Zertifikatsersetzung, ACME-Aufträge, Datenbankmigration, Nginx-Generator und Backend-Diagnosen.
- `node --check` für `app/static/app.js` und `app/static/features.js`: bestanden.
- `node tests/test-login.js`: bestanden.
- `bash -n` für Installations-, Update-, Backup- und Restore-Skripte: bestanden.
- Oberfläche mit browserbasiertem UI-Smoke-Test geprüft: Hauptdomain-Gruppen, Filter, Mehrfachauswahl, Rollenverwaltung; keine JavaScript-Laufzeitfehler im geprüften Ablauf.

**Nicht getestet:** Installation im realen Proxmox LXC CT 150, Zertifikatsausstellung mit echtem Let's Encrypt, externe NAT-Regeln, angeschlossene Zielserver und erfolgreiche Wiederherstellung auf deinem Produktionssystem. Dies ist eine Beta-Version; Backup und Proxmox-Snapshot vor dem Update sind erforderlich.

## Wichtig zur NPM-Migration

Der Import aus NPM wurde bereits separat durchgeführt. Dieses Update importiert die 75 alten Hosts **nicht erneut** und überschreibt keine bestehenden Domains. Einzelne 502-Fehler können weiterhin bestehen, wenn die echten Backends nicht erreichbar sind, selbstsignierte oder abgelaufene TLS-Zertifikate verwenden oder Sonderkonfigurationen fehlen. Die neue Diagnose soll die Ursache pro Host transparent anzeigen und bei der Korrektur helfen – nicht unsichere Zertifikatsprüfungen ausschalten.
