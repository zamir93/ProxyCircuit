# ProxyCircuit v0.2.3 Beta — Verifizierter Testbericht

**Projekt:** ProxyCircuit — Self-hosted Reverse Proxy & Network Platform  
**Version:** `v0.2.3-beta`  
**Status:** **BETA — GitHub-CI erfolgreich; Docker-Installation und Webzugriff im Test erfolgreich**  
**Prüfdatum:** 11. November 2026  
**Autor:** Mohammad Zamir Akbari  
**Projekt-Repository:** https://github.com/zamir93/ProxyCircuit  
**Release:** https://github.com/zamir93/ProxyCircuit/releases/tag/v0.2.3-beta

[![Tests / Build — main](https://github.com/zamir93/ProxyCircuit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zamir93/ProxyCircuit/actions/workflows/ci.yml)

> **Nachweisbasis:** Die nachfolgenden Resultate beruhen auf den GitHub-Actions-Screenshots sowie den Proxmox-/Docker-Konsolenprotokollen und dem Browser-Screenshot des durchgeführten Tests. Nicht separat getestete Funktionen werden ausdrücklich nicht als bestanden ausgewiesen.

## 1. Testergebnis auf einen Blick

| Prüfung | Ergebnis | Beleg / Bemerkung |
| --- | --- | --- |
| GitHub Actions `python-tests` auf `main` | **BESTANDEN** | Neuester Prüfablauf nach den CI-Korrekturen mit grünem Haken |
| GitHub Actions `docker-build` auf `main` | **BESTANDEN** | Grün in den GitHub-Actions-Durchläufen |
| Docker-Image auf Proxmox-LXC gebaut | **BESTANDEN** | `proxycircuit:0.2.3-beta-test`, Build erfolgreich abgeschlossen |
| Docker-Container gestartet | **BESTANDEN** | `proxycircuit-beta-test` mit Status `healthy` |
| Nginx-Konfiguration im Docker-Container | **BESTANDEN** | `nginx -t`: Syntax OK, Test erfolgreich |
| Webdienst / API | **BESTANDEN** | `GET /api/version` erfolgreich, Antwort `{"version":"0.2.3-beta"}` |
| Administratorzugang erstellt | **BESTANDEN** | `create-admin --user admin` erfolgreich; kein Passwort dokumentiert |
| Weboberfläche im Browser | **BESTANDEN** | Dashboard geladen und Anmeldung als Administrator im LAN bestätigt |
| Direkter LAN-Zugriff ohne SSH-Tunnel | **BESTANDEN** | HTTPS über den veröffentlichten Testport 9443 erreicht |
| Gleichzeitig betriebene TeamSpeak-Dienste | **BESTANDEN** | Drei bestehende TeamSpeak-Manager-Docker-Container liefen beim Test weiter |
| Archivintegrität (Linux/Docker-Paket) | **BESTANDEN** | SHA-256-Check auf dem LXC mit `OK` bestätigt |
| Native Neuinstallation auf Debian 12/13 | **NICHT IN DIESEM TEST GEPRÜFT** | Linux-Installationsskript nicht auf einem separaten frischen System ausgeführt |
| Vollständige Funktion aller Proxy- und Netzwerkwerkzeuge | **NICHT IN DIESEM TEST GEPRÜFT** | Web-SSH, mDNS, Portweiterleitung, Zertifikatserneuerung usw. nicht einzeln end-to-end bestätigt |

## 2. GitHub Actions — automatisierte Prüfungen

Im ersten öffentlichen CI-Lauf traten **zwei testumgebungsbedingte Nginx-Berechtigungsfehler** auf:

- Zugriff auf `/var/log/nginx/access.log` ohne ausreichende Rechte.
- Binden des privilegierten Ports `80` im nicht privilegierten GitHub-Runner.

Die Testkonfiguration wurde korrigiert: Die Nginx-Tests verwenden keine gesperrte globale Zugriffsprotokolldatei und weichen für den Default-Listener auf lokale, nicht privilegierte Testports aus. **Die produktiven ProxyCircuit-Listener wurden dadurch nicht umgestellt.** Danach waren sowohl `python-tests` als auch `docker-build` grün. Die Workflow-Actions wurden anschließend aktualisiert; auch danach meldete der Nutzer beide Jobs als erfolgreich.

**Präzision:** Das letzte vollständig übermittelte Fehlerprotokoll wies `59 passed, 1 failed` aus. Die späteren grünen GitHub-Durchläufe beweisen den erfolgreichen Gesamtjob, aber die exakte Testzahl aus dessen finalem `pytest`-Log wurde hier nicht erneut ausgelesen. Deshalb wird keine ungeprüfte Anzahl als endgültige `passed`-Zahl behauptet.

**CI-Status live abrufen:** https://github.com/zamir93/ProxyCircuit/actions/workflows/ci.yml

## 3. Reale Docker-Testumgebung

| Merkmal | Testumgebung |
| --- | --- |
| Virtualisierung | Proxmox VE, LXC-Container mit vorhandenem Docker |
| CPU | 2 Kerne |
| Arbeitsspeicher-Limit des LXC | 2 GiB |
| Root-Dateisystem | 20 GB; vor dem Test etwa 8,1 GB frei |
| Docker Compose | `v5.7.0` |
| Docker-Image | `proxycircuit:0.2.3-beta-test` |
| Container | `proxycircuit-beta-test` |
| Testport für Administration | `9443/tcp` im LAN |
| Sonstige Testports | HTTP `18080` und HTTPS `18443`, beide nur auf Loopback gebunden |
| Vorhandene Dienste | TeamSpeak und drei Docker-Manager-Dienste |

Die interne Test-IP und Zugangsdaten werden in diesem öffentlichen Dokument nicht veröffentlicht.

### Erfolgreich beobachtete Startausgaben

```text
Image proxycircuit:0.2.3-beta-test Built
Container proxycircuit-beta-test Started
nginx: configuration file /etc/nginx/nginx.conf test is successful
[ProxyCircuit] Nginx-Konfiguration erfolgreich geprüft und aktiviert
Application startup complete.
Uvicorn running on https://0.0.0.0:9443
STATUS: healthy
{"version":"0.2.3-beta"}
```

Die erste HTTP-Abfrage unmittelbar nach `docker compose up` schlug fehl, solange der Container noch `health: starting` meldete. Nach dem Start war der Container `healthy`, die API antwortete korrekt und das Dashboard wurde im Browser geöffnet.

Der spätere direkte HTTPS-LAN-Aufruf funktionierte **ohne SSH-Tunnel**. Das Testzertifikat war selbstsigniert; die Browseranzeige „Nicht sicher“ war deshalb zu erwarten. Das ist **keine Freigabe für einen öffentlichen, ungeschützten Adminzugang**.

### Archivprüfung

Folgende SHA-256-Prüfsumme wurde beim Download auf den LXC überprüft und mit `OK` bestätigt:

```text
1edd6f62ba4e43c9738770cd92a3c1d869d271c0d54aea1e57121f2aa6c580c1  ProxyCircuit-Linux-Docker-v0.2.3-beta.tar.gz
```

Die Prüfsummendatei des GitHub-Releases enthält zusätzlich:

```text
ba5557b47e62d813b13f7a54d4841307228cb83acb313c8577751cfa6131c5bf  ProxyCircuit-GitHub-v0.2.3-beta.zip
```

Der ZIP-Wert stimmt mit der GitHub-Anzeige überein; das GitHub-ZIP wurde in diesem LXC-Test nicht separat erneut gehasht.

## 4. Bekannte Einschränkungen und offene Punkte

1. **RAM-Anzeige:** Das Dashboard zeigt ungefähr 25 GB Host-RAM, obwohl der LXC auf 2 GiB begrenzt ist. Die Ressourcenerkennung sollte künftig cgroup-/Container-Limits verwenden.
2. **HTTPS-Testzertifikat:** Selbstsigniertes Zertifikat erzeugt eine Browserwarnung. Für produktive Zugriffe sind ein gültiges Zertifikat und LAN-/VPN-Zugriffskontrolle sinnvoll.
3. **Experimentelles Docker-Deployment:** Der erfolgreiche Start und das Dashboard belegen nicht, dass alle Funktionen und die gesamte Update-/Restore-Strecke vollständig geprüft wurden.
4. **Tag und `main` unterscheiden sich:** Die ersten fehlerhaften CI-Testkonfigurationen gehörten zum ursprünglichen Release-Stand. Die anschließenden Test- und Workflow-Korrekturen wurden auf `main` vorgenommen. **Der bereits veröffentlichte Tag `v0.2.3-beta` und seine Archive wurden nicht nachträglich aktualisiert.** Der erfolgreiche aktuelle CI-Status darf deshalb nicht als rückwirkender Testbeleg für jeden Inhalt des Tags ausgelegt werden.
5. **Produktive Nutzung:** Keine produktive Freigabe allein auf Basis dieser Testläufe. Weitere Tests für Upgrades, Zertifikatsverwaltung, Domainrouting, UDP/TCP und Netzwerkanalyse sind empfehlenswert.

## 5. Gesamtfazit

**Erfolgreich verifiziert:** ProxyCircuit `v0.2.3-beta` ließ sich aus dem veröffentlichten Linux-/Docker-Paket auf einem bestehenden Docker-Host bauen, als eigenständiger Container starten, auf `healthy` prüfen, per API als richtige Version identifizieren und im Browser als Administrator nutzen. Die bestehenden TeamSpeak-Manager-Container liefen dabei weiter. Die neuesten GitHub-Actions-Prüfungen auf `main` waren erfolgreich.

**Freigabestatus:** **Öffentliche Beta / experimentelles Docker-Deployment** — technischer Start- und CI-Test bestanden; noch keine vollständige Produktivfreigabe.

---

*© 2026 Mohammad Zamir Akbari · https://zamir.akbari.org*
