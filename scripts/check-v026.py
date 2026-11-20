#!/usr/bin/env python3
# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Read-only upgrade check: no SQLite migration, no port binding, no reload."""
import json
import sqlite3
from pathlib import Path
from app.port_binding import local_addresses, find_live_conflicts, rules_conflicts
from app.settings import DB


def main():
    print('ProxyCircuit v0.2.6 – PRODUKTIV-VORPRUEFUNG (READ ONLY)')
    print('Datenbank:',DB)
    if not DB.is_file():
        print('FEHLER: Bestehende SQLite-Datenbank nicht gefunden')
        return 1
    con=sqlite3.connect('file:'+str(DB)+'?mode=ro',uri=True)
    con.row_factory=sqlite3.Row
    try:
        integrity=con.execute('PRAGMA quick_check').fetchone()[0]
        print('SQLite quick_check:',integrity)
        columns={r[1] for r in con.execute('PRAGMA table_info(streams)')}
        rows=[dict(r) for r in con.execute('SELECT * FROM streams')]
        if 'bind_ip' not in columns:
            for row in rows:row['bind_ip']='0.0.0.0'
        print('Portregeln:',len(rows),'(Altregeln ohne Bind-IP erhalten 0.0.0.0)')
        active=[row for row in rows if row['enabled']]
        print('Lokale IPs:',', '.join(str(x['address']) for x in local_addresses())[:350])
        duplicates=rules_conflicts(active)
        checks=find_live_conflicts(active)
        for msg in duplicates+checks['conflicts']:
            print('KONFLIKT:',msg)
        for msg in checks['warnings']:
            print('Hinweis:',msg)
        if duplicates or checks['conflicts']:
            print('WARNUNG: Konflikt ist vor Aktivierung im neuen Admin-Panel zu korrigieren.')
        print('Anzahl Domains:',con.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]);
        print('Zertifikate:',con.execute('SELECT COUNT(*) FROM certificates').fetchone()[0]);
        print('Keine Aenderungen durch diese Pruefung.')
        return 0 if integrity=='ok' else 2
    finally:
        con.close()

if __name__=='__main__':
    raise SystemExit(main())
