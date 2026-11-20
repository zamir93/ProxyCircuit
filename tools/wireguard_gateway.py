#!/usr/bin/env python3
# ProxyCircuit v0.2.4 Beta VPN | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Offline WireGuard config generator for dedicated gateways. Python standard library only.

Does NOT activate routes, forwarding, firewall, containers, or wg-quick.
Private keys are read from local gateway files; never sent to ProxyCircuit.
"""
from __future__ import annotations
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

RFC1918=tuple(ipaddress.ip_network(v) for v in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
HOST=re.compile(r'^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$')
IFACE=re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,14}$')


def safe_key(value: str):
    if not isinstance(value,str):raise ValueError('WG-Schluessel muss Text sein')
    try:secret=base64.b64decode(value,validate=True)
    except (ValueError,base64.binascii.Error) as exc:raise ValueError('Ungueltiger WireGuard Base64-Schluessel') from exc
    if len(secret)!=32 or base64.b64encode(secret).decode()!=value or not any(secret):
        raise ValueError('WireGuard-Schluessel muss 32 Byte und nicht leer sein')
    return value


def safe_net(value):
    try:net=ipaddress.ip_network(value,strict=True)
    except ValueError as exc:raise ValueError('Ungueltiger IPv4-CIDR') from exc
    if not isinstance(net,ipaddress.IPv4Network) or not any(net.subnet_of(r) for r in RFC1918):
        raise ValueError('Nur RFC1918-IPv4-Netze sind erlaubt')
    return net


def safe_ip(value):
    try:ip=ipaddress.ip_address(value)
    except ValueError as exc:raise ValueError('Ungueltige IPv4-Adresse') from exc
    if not isinstance(ip,ipaddress.IPv4Address) or not any(ip in r for r in RFC1918):
        raise ValueError('Nur RFC1918-IPv4-Adressen erlaubt')
    return ip


def safe_endpoint(value):
    if not value:return ''
    if not isinstance(value,str) or not HOST.fullmatch(value) or '..' in value or any(
        x.startswith('-') or x.endswith('-') for x in value.split('.')
    ):raise ValueError('Ungueltiger Hostname / Endpoint')
    if all(c.isdigit() or c=='.' for c in value):
        try:ipaddress.IPv4Address(value)
        except ValueError as exc:raise ValueError('Ungueltiger IPv4-Endpoint') from exc
    return value


def read_private_key(filename: Path) -> str:
    st=filename.stat()
    if filename.is_symlink() or not filename.is_file() or st.st_mode & 0o077:
        raise ValueError('Private-Key-Datei muss regulaer und Modus 0600/0400 sein')
    return safe_key(filename.read_text().strip())


def verify_pubkey(secret: str, expected: str):
    safe_key(expected)
    try:
        res=subprocess.run(['wg','pubkey'],input=secret+'\n',capture_output=True,text=True,timeout=5,check=True)
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        raise ValueError('wg pubkey benoetigt, Public/Private-Key-Paar kann nicht geprueft werden') from exc
    if res.stdout.strip()!=expected:
        raise ValueError('Private Key auf Gateway passt nicht zum gespeicherten Public Key')


def load_plan(path: Path):
    data=json.loads(path.read_text(encoding='utf-8'))
    if data.get('format')!='proxycircuit-wireguard-plan-v1':raise ValueError('Ungueltiges Planformat')
    raw=data['hub'];addr=ipaddress.ip_interface(raw['address']);
    if not isinstance(addr,ipaddress.IPv4Interface):raise ValueError('Hub nur IPv4')
    safe_net(str(addr.network))
    if addr.ip in (addr.network.network_address,addr.network.broadcast_address):
        raise ValueError('Hub darf keine Netz-/Broadcastadresse haben')
    if not IFACE.fullmatch(raw['interface']):raise ValueError('Ungueltiger Interface-Name')
    if not isinstance(raw['listen_port'],int) or not 1024<=raw['listen_port']<=65535:
        raise ValueError('Ungueltiger Hub-Port')
    pub=raw.get('public_key','')
    if pub:safe_key(pub)
    host=safe_endpoint(raw.get('endpoint',''))
    hub=SimpleNamespace(interface=raw['interface'],address=str(addr),listen_port=raw['listen_port'],
                        endpoint=host,public_key=pub)
    used_addr=set();all_routes=[];sites=[]
    for row in data['sites']:
        peer=safe_ip(row['tunnel_ip'])
        if peer not in addr.network or peer==addr.ip or peer in (addr.network.network_address,addr.network.broadcast_address):
            raise ValueError('Peer ausserhalb des Hub-VPN-Netzes')
        if peer in used_addr:raise ValueError('Peer-IP doppelt vergeben')
        used_addr.add(peer)
        pubkey=safe_key(row['public_key'])
        remote_host=safe_endpoint(row.get('endpoint_host',''))
        port=row.get('endpoint_port',51820)
        keepalive=row.get('keepalive',25)
        if not isinstance(port,int) or not 1<=port<=65535 or not isinstance(keepalive,int) or not 0<=keepalive<=120:
            raise ValueError('Ungueltige Peer-Port-/Keepalive-Angabe')
        label=row.get('name','')
        if not isinstance(label,str) or not 1<=len(label)<=80 or any(ord(c)<32 for c in label):
            raise ValueError('Ungueltiger Standortname')
        nets=[]
        for cidr in row['routes']:
            net=safe_net(cidr)
            if net.overlaps(addr.network) or any(net.overlaps(n) for n in all_routes):
                raise ValueError('Ueberlappende VPN-Routen')
            all_routes.append(net);nets.append(str(net))
        site=SimpleNamespace(name=label,public_key=pubkey,tunnel_ip=str(peer),endpoint_host=remote_host,
               endpoint_port=port,keepalive=keepalive,enabled=bool(row.get('enabled',True)))
        sites.append((site,nets,row['id']))
    return hub,sites


def render_hub(hub,sites,private):
    safe_key(private)
    lines=['# ProxyCircuit WireGuard-Hub | Nur manuell auf separatem Gateway aktivieren',
           '[Interface]',f'Address = {hub.address}',f'ListenPort = {hub.listen_port}',f'PrivateKey = {private}',
           '# Firewall, ip_forward und Remote-Rueckrouten separat einrichten.']
    for site,routes,_ in sites:
        if not site.enabled:continue
        lines+=['',f'# Remote-Standort: {site.name}','[Peer]',f'PublicKey = {site.public_key}',
                'AllowedIPs = '+', '.join([site.tunnel_ip+'/32']+routes)]
        if site.endpoint_host:lines.append(f'Endpoint = {site.endpoint_host}:{site.endpoint_port}')
        if site.keepalive:lines.append(f'PersistentKeepalive = {site.keepalive}')
    return '\n'.join(lines)+'\n'


def render_spoke(hub,site,private):
    safe_key(private)
    if not hub.endpoint or not hub.public_key:raise ValueError('Hub Endpoint/Public Key erforderlich')
    return '\n'.join(['# ProxyCircuit WireGuard-Remote Gateway, nur manuell aktivieren','[Interface]',
       f'Address = {site.tunnel_ip}/32',f'PrivateKey = {private}','','[Peer]',f'PublicKey = {hub.public_key}',
       f'Endpoint = {hub.endpoint}:{hub.listen_port}',
       f'AllowedIPs = {ipaddress.ip_interface(hub.address).ip}/32',
       f'PersistentKeepalive = {site.keepalive or 25}',
       '# Forwarding und LAN-Rueckroute getrennt konfigurieren.',''])


def write_conf(destination:Path,content:str):
    if destination.is_symlink() or destination.exists():
        raise ValueError('Ziel ist vorhanden oder Symlink; niemals ungeprueft ueberschreiben')
    destination.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as file:file.write(content)
    os.chmod(destination,0o600)


def main():
    parser=argparse.ArgumentParser(description='WireGuard-Konfiguration offline generieren (keine Aktivierung)')
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--role',choices=('hub','spoke'),required=True)
    parser.add_argument('--site-id',default='')
    parser.add_argument('--private-key-file',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        hub,sites=load_plan(args.plan)
        private=read_private_key(args.private_key_file)
        if args.role=='hub':
            verify_pubkey(private,hub.public_key)
            content=render_hub(hub,sites,private)
        else:
            site=next((s for s,_,sid in sites if sid==args.site_id),None)
            if site is None:raise ValueError('Remote-Site-ID im Export nicht gefunden')
            verify_pubkey(private,site.public_key)
            content=render_spoke(hub,site,private)
        write_conf(args.output,content)
        print('WireGuard-Konfiguration erstellt:',args.output,'(0600).')
        print('Kein Tunnel gestartet. Routing/Firewall manuell pruefen und wg-quick getrennt ausfuehren.')
        return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print('FEHLER:',str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
