# ProxyCircuit v0.2.6 Beta – Testbericht

**Stand:** 20.11.2026 · **Entwickler:** Mohammad Zamir Akbari · https://zamir.akbari.org

## Tatsächlich ausgeführte Tests

- **113 Python-Unittestfälle bestanden**; außerdem **117 pytest-Tests bestanden (18 Subtests)** (`python3 -m unittest discover -s tests -q`).
- **JavaScript-Syntax:** `node --check app/static/app.js`, zusätzlich bestehende Frontend-Skripte geprüft.
- **Python-Syntax:** `python3 -m compileall -q app`.
- **Shell-Syntax:** `bash -n scripts/*.sh docker/*.sh`.
- **Nginx-HTTP-Staging-Syntax** über echte isolierte `nginx -t`-Konfiguration geprüft.
- **NGINX-Stream-Syntax**: Das benötigte `libnginx-mod-stream` ist in der Build-Umgebung nicht installiert; vollständiger Stream-Test ist bis zum isolierten Testhost **offen**. Die generierte Syntax ist durch Renderer-Unit-Tests geprüft.
- **Docker-Livebetrieb**: hier kein Docker-Daemon verfügbar; Docker-Compose-Profil wird statisch geprüft, aber nicht als real gestartet ausgewiesen.

## Neue Regressionstests

1. SQLite-Upgrade aus altem `UNIQUE(protocol,listen_port)`-Schema erhält Regel-ID, Ziele, Ports und bietet neue `bind_ip`-Spalte.
2. IPv4/IPv6-Normalisierung; Eingabeinjektionen werden abgewiesen.
3. Gleicher Port auf verschiedenen spezifischen lokalen IPv4-Adressen erlaubt.
4. Wildcard-Bindungen und überlappende Regeln werden abgewiesen.
5. IPv4/IPv6-Wildcards konservativ geprüft.
6. Postfix auf `127.0.0.1:25`/`::1:25` blockiert keine unabhängige lokale `192.0.2.150:25`-Bindung.
7. Postfix-Lokalloopback und NGINX-Wildcard auf demselben IPv4-Port werden als Konflikt erkannt.
8. Bereits von ProxyCircuit verwaltete NGINX-Sockets werden als bestehende Managed-Listener erkannt (Warnung), nicht mit fremden Prozessen verwechselt.
9. UDP-/TCP-Portbelegungen getrennt.
10. Renderer generiert korrekte `listen`-Zeilen für IPv4, IPv6, UDP.
11. Isolierter NGINX-`-t`-Staging-Test; ungültige Konfiguration wird abgewiesen.
12. Gespeicherte NGINX-Snapshots lassen sich lesen; unzulässige ID wird abgewiesen.
13. Erfolg des Reload-Befehls allein genügt nicht: fehlende Listener/neue NGINX-Worker werden erkannt.
14. NGINX-Logfehler nach Reload werden erkannt.
15. **Rollback-Simulation:** Selbst wenn Reload den Exitcode `0` liefert, wird bei fehlgeschlagener Runtime-Verifikation der alte HTTP-/Stream-/Fallback-Dateistand wiederhergestellt, und `activation_failed` dokumentiert.
16. **Echter lokaler TLS-SNI-Test:** erwartetes `admin.example.org`-Zertifikat + HTTP 401 werden als erreichbar gewertet.
17. **Falsches TLS-Zertifikat:** `proxycircuit.local` für `admin.example.org` wird als mismatch erkannt.
18. **Echte FastAPI- und SQLite-CRUD-Integration:** Anlegen, Bearbeiten, zwei Bind-IPs gleicher Port, Rollback einer fehlgeschlagenen Änderung, Löschen.
19. **TOTP RFC6238:** bekannter Standardtestvektor, Setup/Confirm, Passwort ohne OTP wird abgewiesen, Replay des gleichen Codes abgewiesen.

## Nicht nachgewiesen

- Produktiver Reload auf ProxyCircuit-Testcontainer mit Postfix/KeyHelp und dem tatsächlichen Port 25.
- Durchgängiger SMTP-/IMAP-/DNS-Diensttest und echte öffentlich erreichbare C-Mail-Domain.
- Echtes WireGuard-Tunnel-Setup, unabhängige UGREEN-UPK-Installation.
- Vollständiges Browser-Layout auf realer Hardware; CSS/JS-Syntax ist keine Browser-Abnahme.
- Zertifikatsrotation für tatsächlich vorhandene ACME-Domains in Produktion.
- NGINX-Stream-Runtime im Build-Container (Stream-Modul fehlt dort).

**Bewertung:** Funktionsfähiger, lokal getesteter **Beta-Quellcode-Kandidat**. Erst nach isolierter Docker-/LXC-Probe und Freigabe darf das produktive ProxyCircuit-Testcontainer aktualisiert werden.
