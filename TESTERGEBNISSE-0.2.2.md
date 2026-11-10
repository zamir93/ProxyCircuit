# ProxyCircuit v0.2.2 Beta – Testbericht

Autor: Mohammad Zamir Akbari – https://zamir.akbari.org

## Testumfang

- 49 automatisierte Python-Tests: alte Domain-, SSL-, Import-, Migration-, Rollback-nahe und Diagnosetests, plus die neuen Netzwerktests. Keine realen externen Ziele wurden für Scanner-Tests angesprochen.
- Backend-Rollen/CSRF: Autorisierte Admin-Tools; Reader darf nur den CIDR-Rechner nutzen. Öffentliche IP/CIDR-Scans, große Scans, Duplikate und fehlerhafte Ports werden abgewiesen.
- Wake-on-LAN: Paketlänge, Magic-Packet-Präfix und Broadcast-Ziel mit Mock-Socket überprüft.
- SSH-WebSocket: Origin- und Benutzerrollen-Schutz, Session-Cookie, korrekter CSRF-Anmeldeablauf und simulierte verschlüsselte SSH-Sitzung.
- HTML/CSS/JS: Headless-Chromium-Test mit simuliertem API-Backend, Desktop-Bereiche, CIDR-Interaktion, SSH-Ansicht und mobile Navigation. Bei 390 px Viewport kein horizontales Seitenscrolling und keine JavaScript-Ausnahmen.
- Python: `compileall`; JavaScript: `node --check` (app.js, features.js, utilities.js); Update-Skript: `bash -n`.

## Grenzen

- Echte SSH-Anmeldungen an einen Zielserver und reale mDNS-Pakete sind **hier nicht Ende-zu-Ende geprüft**. Der Testcontainer hat keinen Internetzugang zum Nachinstallieren von paramiko/zeroconf. Der Update-Assistent im Zielcontainer installiert sie vor der Dienstunterbrechung oder bricht bei Installationsfehler vor dem Stoppen der Dienste ab.
- Live-Tests auf dem Proxmox-Knoten oder innerhalb CT 150 wurden nicht ausgeführt. Das Update ist **nicht auf dem Nutzer-Server installiert**.
- Für SSH über den Domain-Proxy muss die Proxy-Domain WebSockets weiterleiten. Direkt auf dem sicheren Admin-Port 9443 entfällt dieser zusätzliche Proxy-Hop.
- mDNS setzt Multicast UDP/5353 im LXC-Netzsegment voraus, nicht garantiert in jedem VLAN.
- Das Web-SSH-Terminal ist eine einfache Textkonsole mit Befehlseingabe; kein vollständig ANSI-/vt100-kompatibler Terminalemulator.
