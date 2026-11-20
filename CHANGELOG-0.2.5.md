# ProxyCircuit v0.2.5 Beta – Änderungsprotokoll

**11. November 2026 · Autor: Mohammad Zamir Akbari · https://zamir.akbari.org**

- VPN-Readiness-API `GET /api/vpn/preflight`: statische Konfigurationsprüfung mit strukturierten Blockern, Warnungen und SHA256-Fingerprint.
- Lokale LAN-Netze `GET/PUT /api/vpn/local-networks`: strikte private CIDR-Validierung, max. 16 Netze, nicht überlappend.
- Bestehende VPN-Routen werden bei neuen LAN-Netzen und neue Remote-Routen gegen gespeicherte lokale Netze geprüft.
- Admin-Panel: Formular für lokale Netze, Vorprüfung, JSON-Berichtexport; responsives Layout.
- Separates Gateway-Skript: Read-only-Inspektion lokaler Routen, WireGuard-Interface und UDP-Listener; keine Systemänderungen.
- `compose.vpn-smoke.yaml`: isoliertes Docker-Projekt, nur Admin-Port localhost:19445, eigene Datenvolumes.
- `docs/ROADMAP.md`: vollständige priorisierte Roadmap der acht geplanten Erweiterungen.
- Additive SQLite-Migration; keine Änderungen an produktiven Proxy-Domains/SSL, WireGuard-Schlüsseln, Firewall oder NAT.

**Nicht enthalten:** echter Site-to-Site-Handshake, automatische Tunnelaktivierung, Proxmox-/Docker-Agenten, Zero-Trust-Firewall, mobile VPN-Clients.
