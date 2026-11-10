# ProxyCircuit 0.1.4 Beta

Author: Mohammad Zamir Akbari · https://zamir.akbari.org

- TLS upstream server name is configurable per HTTPS proxy host.
- Nginx always retains upstream certificate verification.
- Idempotent SQLite migration adds hosts.upstream_tls_name.
- Targeted CT150 repair option, with certificate and host checks.
- Full rollback backups for app, database and Nginx HTTP configuration.
- Existing 0.1.3 frontend login hotfix retained.
- No automatic public exposure, DNS changes or NPM migration.

Not production-tested on Proxmox; stage and verify before use.
