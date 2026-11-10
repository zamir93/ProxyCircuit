# ProxyCircuit v0.2.3 Beta | Testbericht

Autor: Mohammad Zamir Akbari | https://zamir.akbari.org

- **56 automatische Tests erfolgreich** (`PYTHONPATH=. pytest -q`).
- Nginx-Konfiguration mit temporaerem Zertifikat syntaktisch geprueft.
- Mit einem echten, separat gestarteten Nginx-Prozess getestet:
  - Unbekannte HTTP-Domain: `404`, die gestaltete HTML-Standardseite wird geliefert.
  - Offline-Backend: `502`, die gestaltete HTML-Standardseite wird geliefert.
  - Erreichbares Backend: `200`, unveraenderter Backend-Inhalt wird geliefert.
- API-Tests: Gespeicherte HTML-Seite lesen, mit CSRF speichern, unerlaubte Skripte ablehnen, Standardvorlage zuruecksetzen.
- Desktop- und Mobilbrowser mit simulierten API-Antworten: Kategorien in Domainliste und Monitoring, Kachel-/Tabellenwechsel, HTML-Editor und Vorschau funktionieren ohne JavaScript-Fehler.
- Mobile Darstellung: kein globaler horizontaler Ueberlauf bei 390 px Viewport.
- Web-SSH und mDNS aus v0.2.2 wurden in dieser Version nicht gegen reale Ziele getestet.
- **Nicht** auf dem produktiven Container CT 150 installiert oder dort getestet.
- Ein Browser-Test ueber einen lokalen HTTPS-Testserver war in der Testumgebung durch eine Browserrichtlinie blockiert. UI-Tests wurden daher mit Mock-API im Browser ausgefuehrt, API- und Nginx-Verhalten separat real getestet.
