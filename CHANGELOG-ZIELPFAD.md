# ProxyCircuit v0.2.5 Beta – optionale Zielpfad-Unterstützung

- `upstream_path` in Weboberfläche, API, SQLite und Nginx-Renderer
- Automatische SQLite-Migration ohne Änderungen an vorhandenen Host-IDs oder SSL-Zertifikaten
- Standard `/` rendert bisherige `proxy_pass`-Direktive unverändert
- Strenge Pfadvalidierung ohne freie Nginx-Direktiven
- GET-Diagnose prüft den tatsächlichen Backend-Pfad
- Eigene Docker-Testumgebung `compose.path-test.yaml` mit Host-Port `9446`
- Kein echter Zugriff auf das produktive ProxyCircuit-Testcontainer-System bei der Erstellung

Dokumentation: `docs/UPSTREAM_PATH.md`
