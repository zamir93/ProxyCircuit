# Proxy-Domain: Separater Zielpfad (Upstream Path)

Author: **Mohammad Zamir Akbari** – https://zamir.akbari.org

## Beispiel

- Domain: `inventory.example.org`
- Protokoll: `HTTP`
- Ziel-IP/Hostname: `192.168.10.3` (**ohne** Verzeichnis oder `http://`)
- Zielport: `80`
- **Zielpfad (optional):** `/lager_inventar_system/`
- Öffentliche URL: `https://inventory.example.org/` (nur mit gültigem SSL-Zertifikat)
- Backend-URL: `http://192.168.10.3:80/lager_inventar_system/`

Der sichere Nginx-Renderer verwendet:

```nginx
location / {
    proxy_pass http://192.168.10.3:80/lager_inventar_system/;
    # Die anderen, von ProxyCircuit generierten Header/TLS/Timeout-Einstellungen bleiben erhalten.
}
```

Beim öffentlichen Aufruf von `/assets/logo.png` leitet Nginx an
`/lager_inventar_system/assets/logo.png` weiter und behält Query-Parameter bei.
Der Zielpfad `/` (Standard) behält den bisherigen `proxy_pass` **ohne** URI-Suffix.

## Hinweise und Einschränkungen

- Dies ist **Pfad-Weiterleitung**, keine allgemeine HTML-/JavaScript-Umschreibung.
  Hartcodierte absolute URLs wie `/lager_inventar_system/login.php`, `Location`-Header oder
  Cookies mit festem `Path=/lager_inventar_system/` können in der Anwendung Anpassungen
  der öffentlichen Basis-URL erfordern. Wenn möglich, die Anwendungs-Basis-URL auf
  `https://inventory.example.org/` konfigurieren.
- Der Pfad ist ein **Verzeichnispräfix**. Erlaubte Zeichen: `A-Z`, `a-z`, `0-9`, `/`, `_`, `-`, `.`, `~`.
  Kein `..`, doppelte Schrägstriche, URL-Schemas, Query/Hash, Escape- oder %-Kodierung.
- Vorhandene Domains werden per idempotenter SQLite-Migration mit `/` vorbelegt.
- Nginx-Konfiguration ist generiert, nicht manuell bearbeiten. Erst im
  **Testcontainer** testen, dann mit Backup/Restore-Plan in Produktion übernehmen.
- Änderungen an der produktiven dem ProxyCircuit-Container wurden bei der Paketerstellung nicht durchgeführt.
