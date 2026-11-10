# GitHub veröffentlichen – ProxyCircuit v0.2.3-beta

Die Quelldateien sind für ein **neues** Repository vorbereitet. Hier erfolgt noch **kein automatischer Upload** zu einem fremden GitHub-Konto.

## Vorher

1. GitHub-Konto / Ziel-Repository auswählen (empfohlener Repositoryname: `ProxyCircuit`).
2. Sichtbarkeit und Lizenz entscheiden. `LICENSE-NOTICE.md` weist aktuell auf **alle Rechte vorbehalten** hin; die Wahl einer freien Lizenz ist Sache des Rechteinhabers.
3. Dokumentation, Demo-Screenshots und Code vor dem ersten Public-Push persönlich überprüfen.
4. Sicherstellen, dass keine persönlichen Daten, TLS-Schlüssel oder produktiven Server-Backups enthalten sind.

## Repository aus dem entpackten Ordner veröffentlichen

```bash
cd ProxyCircuit
git init
git branch -M main
git add .
git commit -m "Initial public beta: ProxyCircuit v0.2.3-beta"

# GitHub zuerst in Weboberfläche als leeres Repository ohne README erstellen.
# Die beiden Platzhalter unten durch eigene Werte ersetzen:
git remote add origin https://github.com/DEIN-GITHUB-NAME/ProxyCircuit.git
git push -u origin main

git tag -a v0.2.3-beta -m "ProxyCircuit public beta v0.2.3"
git push origin v0.2.3-beta
```

Alternativ mit bereits installierter, authentifizierter GitHub CLI:

```bash
cd ProxyCircuit
git init && git branch -M main
git add . && git commit -m "ProxyCircuit v0.2.3-beta"
gh repo create ProxyCircuit --private --source=. --remote=origin --push
# Sichtbarkeit erst nach Datenschutz-, Lizenz- und Security-Check ändern.
git tag -a v0.2.3-beta -m "ProxyCircuit public beta"
git push origin v0.2.3-beta
```

Anschließend auf GitHub unter **Releases → Draft a new release** den Tag `v0.2.3-beta` auswählen und die Hinweise aus `RELEASE_NOTES.md` einfügen. Das Release als **Pre-release** markieren. Optional das ZIP und TAR.GZ aus dem Paket als Release-Assets hochladen.

## Warum keine Docker-Registry-Datei?

Das Repository enthält ein vollständiges Build-Beispiel (`docker/Dockerfile`, `compose.yaml`), **kein vorgebautes und getestetes öffentliches Docker-Image**. Ein veröffentlichter Image-Tag setzt einen erfolgreichen echten Docker-Build und Tests auf einem Linux-Docker-Host voraus.
