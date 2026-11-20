# ProxyCircuit v0.2.4 Beta – WireGuard VPN-Standortverwaltung

- VPN-Standorte als neue integrierte Adminseite mit Hub, Remote-Peers, Routing und Domainbindung.
- Validierte, private IPv4-/CIDR-Routen, Prüfung auf Überschneidungen und peer-spezifische Eindeutigkeit.
- Public-Key-only WireGuard-Export und offline Gateway-Generator ohne private Schlüssel in der Webanwendung.
- Neue VPN-Backend-Domains werden deaktiviert angelegt, bis der Tunnel getestet wurde.
- Rollen und CSRF-Prüfung für alle Veränderungen; bestehende Benutzer-/Domain-/SSL-Daten bleiben erhalten.
- Keine automatischen Tunnels, Firewall-/Routing- oder Portforwarding-Änderungen.
- Tests mit isolierter Datenbank, Missbrauchsszenarien und Offline-Konfiguration.

Einschränkung: **WireGuard-Live-Verbindung muss separat auf eigenen Gateways konfiguriert und getestet werden.**
