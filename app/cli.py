# ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Local admin CLI. No insecure default password or web-based setup bypass."""
import argparse
import getpass
import sys
from .db import connect, init_db
from .security import hash_password

def main():
    parser=argparse.ArgumentParser(description='ProxyCircuit Admin-CLI')
    parser.add_argument('action', choices=['create-admin','reset-password'])
    parser.add_argument('--user', default='admin')
    args=parser.parse_args()
    if not args.user or len(args.user)>80:
        print('Ungültiger Benutzername', file=sys.stderr);return 1
    init_db()
    try:
        pw=getpass.getpass('Neues Administrator-Passwort (mind. 8 Zeichen): ')
        pw2=getpass.getpass('Passwort wiederholen: ')
    except (EOFError,KeyboardInterrupt):
        print('\nAbgebrochen',file=sys.stderr);return 1
    if pw != pw2:
        print('Passwörter stimmen nicht überein',file=sys.stderr);return 1
    try:h=hash_password(pw)
    except ValueError as exc:print(str(exc),file=sys.stderr);return 1
    con=connect()
    existing=con.execute('SELECT 1 FROM admins WHERE username=?',(args.user,)).fetchone()
    if args.action=='create-admin' and existing:
        print('Benutzer existiert bereits',file=sys.stderr);return 1
    if args.action=='reset-password' and not existing:
        print('Benutzer existiert nicht',file=sys.stderr);return 1
    con.execute('INSERT INTO admins(username,password_hash) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash',(args.user,h))
    con.execute('DELETE FROM sessions WHERE username=?',(args.user,))
    con.commit();con.close()
    print('Administrator-Zugang aktualisiert:',args.user)
    return 0

if __name__=='__main__':sys.exit(main())
