# ProxyCircuit: Proxmox-Einführung und spätere Umstellung von CT 147 auf CT 148

## Phase 1 – Sicherheit des bisherigen CT 147

CT 147 meldete `ext4 emergency_ro`, Schreibfehler bei Nginx-Logs/PID und Erholung nach Neustart. Das ist ein **Speicher-/Dateisystemwarnsignal**, nicht nur eine Nginx-Konfigurationsstörung. Eine Vergrößerung von 10 auf 30 GB beseitigt einen I/O-/Read-only-Fehler nicht automatisch. Vor weiteren Schreibvorgängen: frisches Backup außerhalb des problematischen Volumes, Host-Logs (Speicher, I/O, ext4) prüfen, Disk-/Storage-Gesundheit und Container-Rootfs ermitteln. `fsck` niemals unbedacht auf einem eingehängten Produktionsdateisystem starten.

Beispiele zur **lesenden Diagnose auf dem Proxmox-Host**:

```bash
pct config 147
pvesm status
journalctl -k -b --no-pager | grep -Ei 'ext4|I/O error|read.only|buffer I/O|emergency_ro'
```

Die Hardware-/Storage-Ursache ist anhand der vorliegenden Informationen nicht abschließend identifiziert. Für weitere Schritte werden Storage-Typ (ZFS/LVM-thin/ext4 etc.), Host-Kernel-Logs und Gerätegesundheit benötigt.

## Phase 2 – neuer CT

- Im Proxmox-Webpanel prüfen, ob CT-ID 148 verfügbar ist.
- Debian 13 LXC anlegen, eigene **noch freie** IP (z. B. im 10.0.0.0/24-Netz, aber nicht 10.0.0.12), SSD-Storage mit geprüfter Gesundheit.
- Basiswerte: 1 vCPU, 1 GiB RAM, 10 GiB RootFS; Metriken unter Last beobachten.
- DNS für eigene Testdomain lokal auf neue IP setzen; bisherige öffentliche Weiterleitungen 80/443 zunächst nicht ändern.
- ZIP und Installationsskript **nur auf CT 148** starten.

## Phase 3 – Funktionsnachweis

1. `systemctl status rpmgr-ui nginx rpmgr-apply.path` und `nginx -t` im neuen CT.
2. Admin-Panel `https://NEUE-IP:9443` im internen LAN öffnen.
3. Eine unkritische Testdomain via Host-Header oder Split-DNS testen.
4. Test-Portregel auf einem hohen externen Port verifizieren; Host-Firewall/CT-Firewall getrennt prüfen.
5. Zertifikat und HTTPS testen; im isolierten Testfall PEM-Import statt öffentlicher HTTP-01-Challenge.
6. Root-Backup erstellen und Wiederherstellung **zuerst auf einem weiteren Testsystem** durchspielen.

## Phase 4 – Cutover

Erst nach Protokoll- und Rückfalltests werden Router-NAT für 80/443 und öffentliche DNS-/Upstream-Routen auf den neuen CT umgestellt. Beide CTs können auf **verschiedenen IPs** intern jeweils 80/443 verwenden, aber der **gleiche öffentliche IP:Port** kann nicht ohne zusätzliche Frontend-/Load-Balancer-Konfiguration gleichzeitig auf beide Systeme zeigen. Der alte CT 147 bleibt für den Rollback erhalten, bis Stabilität nachgewiesen ist.

Ports für SSH, UDP und andere nicht-HTTP-Dienste gesondert freigeben. Zusätzliche Ports sind nicht durch einen üblichen Domain-HTTP-Proxy abgedeckt.

---
© 2026 Mohammad Zamir Akbari · https://zamir.akbari.org · ProxyCircuit
