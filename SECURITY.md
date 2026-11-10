# Sicherheit / Security

ProxyCircuit verwaltet öffentlich erreichbare Dienste und private Schlüssel. Bitte **keine** produktiven Daten, Passwörter, Zertifikatsschlüssel, SSH-Keys, vollständigen Logs oder Netzwerkpläne in öffentliche Issues oder Pull Requests hochladen.

## Sicherer Betrieb
- Verwaltung (Port 9443) nur über LAN/VPN oder einen getrennten, gut abgesicherten HTTPS-Zugang bereitstellen.
- Vor Updates ein vollständiges Offline-Backup bzw. einen LXC-Snapshot erstellen.
- SSH-, Scanner- und Forward-Proxy-Werkzeuge nur in autorisierten Netzen nutzen.
- Keine automatische Sicherheitszusage: Beta, keine externe Sicherheitsprüfung.
- Docker Container darf nicht durch Mounten von `/var/run/docker.sock` privilegiert werden.

## Meldung von Schwachstellen
Sicherheitsrelevante Funde zunächst **privat** an den Projekteigentümer melden, nicht öffentlich als reproduzierbare Exploit-Anleitung veröffentlichen. Kontakt: https://zamir.akbari.org
