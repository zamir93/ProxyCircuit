# ProxyCircuit 0.2.2 Beta

Autor: Mohammad Zamir Akbari – https://zamir.akbari.org

- Neue responsive Smartphone-Navigation und Formulare.
- Authentifizierte CIDR-Rechner und sechs Administrator-Netzwerktools.
- Web-SSH-Terminal mit WebSocket, Serverfingerprint-Pinning und begrenzten Sessions.
- Keine Änderungen an Nginx-Proxydomains, vorhandenen Zertifikaten oder Datenbankstruktur.
- Update-Skript installiert neue Python-Abhängigkeiten vor Unterbrechung des Webdienstes und überprüft Version/NGINX nach Aktualisierung.

## Korrektur (2026-11-10)
- Behebt Absturz von `rpmgr-ui.service`: Unvollstaendige oder fuer den Dienstnutzer unlesbare `websockets`-Installation konnte zum ImportError fuer `__version__` fuehren. Die Abhaengigkeit ist konservativ auf `websockets>=13,<16` beschraenkt; Preflight prueft das tatsaechliche Importverhalten.
- Upgrade prueft Uvicorn/WebSocket-Importe unter dem unprivilegierten Dienstkonto, noch bevor rpmgr-ui beendet wird.
- Neue Pakete werden vor dem Neustart lesbar fuer den Dienstnutzer gemacht.
