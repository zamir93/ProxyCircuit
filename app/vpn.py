# ProxyCircuit v0.2.5 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""WireGuard control plane. No secrets, sudo, network commands or route changes in the web process."""
from __future__ import annotations

import base64
import json
import ipaddress
import re
import sqlite3
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from .security import require_admin, require_session
from .db import connect, audit, asdicts
from .vpn_preflight import readiness_report

router = APIRouter(prefix='/api/vpn', tags=['VPN'])
RFC1918 = tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
HOSTNAME = re.compile(r'^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$')
IFACE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,14}$')


def private_net(v: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(v.strip(), strict=True)
    except ValueError as exc:
        raise ValueError('Gueltiges kanonisches IPv4-CIDR erforderlich (z.B. 192.168.20.0/24)') from exc
    if not isinstance(net, ipaddress.IPv4Network) or not any(net.subnet_of(n) for n in RFC1918):
        raise ValueError('Nur RFC1918-IPv4-Netze sind erlaubt, kein 0.0.0.0/0')
    return net


def private_ip(v: str) -> ipaddress.IPv4Address:
    try:
        ip = ipaddress.ip_address(v.strip())
    except ValueError as exc:
        raise ValueError('Gueltige private IPv4-Adresse erforderlich') from exc
    if not isinstance(ip, ipaddress.IPv4Address) or not any(ip in net for net in RFC1918):
        raise ValueError('Nur private RFC1918-IPv4-Adressen sind erlaubt')
    return ip


def key(v: str) -> str:
    try:
        b = base64.b64decode(v, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError('WireGuard Public Key muss Base64-kodiert sein') from exc
    if len(b) != 32 or base64.b64encode(b).decode('ascii') != v:
        raise ValueError('WireGuard Public Key muss genau 32 Byte lang sein')
    if all(byte == 0 for byte in b):
        raise ValueError('Nullschluessel ist nicht zulaessig')
    return v


def endpoint(v: str) -> str:
    v = v.strip().lower()
    if not v:
        return ''
    if not HOSTNAME.fullmatch(v) or '..' in v or any(label.startswith('-') or label.endswith('-') for label in v.split('.')):
        raise ValueError('Nur IP-Adressen oder gueltige DNS-Namen ohne Port eingeben')
    # numeric IPv4 must not bypass DNS/hostname safety rules
    if all(c.isdigit() or c == '.' for c in v):
        try:
            ipaddress.IPv4Address(v)
        except ValueError as exc:
            raise ValueError('Ungueltige IPv4-Adresse') from exc
    return v


def name(v: str) -> str:
    v=v.strip()
    if not v or len(v)>80 or any(ord(c)<32 or c in '<>"\\' for c in v):
        raise ValueError('Name: 1-80 sichtbare Zeichen, kein HTML')
    return v


class HubConfig(BaseModel):
    interface: str = 'wg-pc0'
    address: str = '10.77.77.1/24'
    listen_port: int = Field(default=51820, ge=1024, le=65535)
    endpoint: str = ''
    public_key: str = ''
    gateway_lan_ip: str = ''

    @field_validator('interface')
    @classmethod
    def valid_iface(cls, v):
        if not IFACE.fullmatch(v): raise ValueError('WireGuard-Interface nicht erlaubt')
        return v

    @field_validator('address')
    @classmethod
    def valid_addr(cls, v):
        try:
            i = ipaddress.ip_interface(v)
            if not isinstance(i,ipaddress.IPv4Interface): raise ValueError()
            private_net(str(i.network))
            if i.ip in (i.network.network_address, i.network.broadcast_address): raise ValueError()
            return str(i)
        except ValueError as exc:
            raise ValueError('Private WireGuard-Interface-Adresse/CIDR erforderlich') from exc

    @field_validator('endpoint')
    @classmethod
    def valid_endpoint(cls, v):return endpoint(v)

    @field_validator('public_key')
    @classmethod
    def valid_pub(cls, v):return key(v) if v else ''

    @field_validator('gateway_lan_ip')
    @classmethod
    def valid_lan(cls, v):return str(private_ip(v)) if v else ''


class SiteInput(BaseModel):
    name: str = Field(min_length=1,max_length=80)
    public_key: str
    tunnel_ip: str
    endpoint_host: str = ''
    endpoint_port: int = Field(default=51820, ge=1, le=65535)
    keepalive: int = Field(default=25, ge=0, le=120)
    enabled: bool = True

    @field_validator('name')
    @classmethod
    def valid_name(cls,v):return name(v)
    @field_validator('public_key')
    @classmethod
    def valid_key(cls,v):return key(v)
    @field_validator('tunnel_ip')
    @classmethod
    def valid_tunnel(cls,v):return str(private_ip(v))
    @field_validator('endpoint_host')
    @classmethod
    def valid_host(cls,v):return endpoint(v)


class RouteInput(BaseModel):
    cidr: str
    @field_validator('cidr')
    @classmethod
    def valid_cidr(cls,v):return str(private_net(v))


class DomainInput(BaseModel):
    site_id: str
    route_id: str
    domain: str
    target_ip: str
    target_port: int = Field(ge=1,le=65535)
    protocol: str = 'http'

    @field_validator('domain')
    @classmethod
    def valid_domain(cls,v):
        from .validation import clean_domain
        return clean_domain(v)
    @field_validator('target_ip')
    @classmethod
    def valid_target(cls,v):return str(private_ip(v))
    @field_validator('protocol')
    @classmethod
    def valid_proto(cls,v):
        if v not in ('http','https'):raise ValueError('HTTP oder HTTPS erforderlich')
        return v


def ensure_vpn_schema(con):
    con.executescript('''
    CREATE TABLE IF NOT EXISTS vpn_hub (
      id INTEGER PRIMARY KEY CHECK (id=1), interface TEXT NOT NULL, address TEXT NOT NULL,
      listen_port INTEGER NOT NULL, endpoint TEXT NOT NULL DEFAULT '', public_key TEXT NOT NULL DEFAULT '',
      gateway_lan_ip TEXT NOT NULL DEFAULT ''
    );
    INSERT OR IGNORE INTO vpn_hub(id,interface,address,listen_port,endpoint,public_key,gateway_lan_ip)
      VALUES(1,'wg-pc0','10.77.77.1/24',51820,'','','');
    CREATE TABLE IF NOT EXISTS vpn_sites (
      id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL UNIQUE,
      tunnel_ip TEXT NOT NULL UNIQUE, endpoint_host TEXT NOT NULL DEFAULT '',
      endpoint_port INTEGER NOT NULL DEFAULT 51820, keepalive INTEGER NOT NULL DEFAULT 25,
      enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS vpn_routes (
      id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES vpn_sites(id) ON DELETE CASCADE,
      cidr TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS vpn_domains (
      host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
      site_id TEXT NOT NULL REFERENCES vpn_sites(id) ON DELETE RESTRICT,
      route_id TEXT NOT NULL REFERENCES vpn_routes(id) ON DELETE RESTRICT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_vpn_routes_site ON vpn_routes(site_id);
    CREATE INDEX IF NOT EXISTS idx_vpn_domains_site ON vpn_domains(site_id);
    CREATE TABLE IF NOT EXISTS vpn_local_networks (
      id INTEGER PRIMARY KEY CHECK (id=1), cidrs_json TEXT NOT NULL DEFAULT '[]'
    );
    INSERT OR IGNORE INTO vpn_local_networks(id,cidrs_json) VALUES(1,'[]');
    ''')


def _hub(con):return dict(con.execute('SELECT * FROM vpn_hub WHERE id=1').fetchone())


def _site(con, sid):
    row=con.execute('SELECT * FROM vpn_sites WHERE id=?',(sid,)).fetchone()
    if not row: raise HTTPException(404,'VPN-Standort nicht gefunden')
    return dict(row)


def _routes(con, site_id):
    return asdicts(con.execute('SELECT * FROM vpn_routes WHERE site_id=? ORDER BY cidr',(site_id,)))


def _validate_hub_site(con, tunnel_ip: str, ignore_id: str=''):
    h=ipaddress.ip_interface(_hub(con)['address'])
    ip=private_ip(tunnel_ip)
    if ip not in h.network or ip == h.ip or ip in (h.network.network_address, h.network.broadcast_address):
        raise HTTPException(422,'Peer-Tunnel-IP muss eindeutig im Hub-VPN-Netz liegen')
    if con.execute('SELECT 1 FROM vpn_sites WHERE tunnel_ip=? AND id<>?',(str(ip),ignore_id)).fetchone():
        raise HTTPException(409,'Peer-Tunnel-IP wird bereits verwendet')


def _validate_route(con, cidr, ignore_id=''):
    net=private_net(cidr)
    overlay=ipaddress.ip_interface(_hub(con)['address']).network
    for cidr in _local_networks(con):
        if net.overlaps(ipaddress.ip_network(cidr)):
            raise HTTPException(409, 'VPN-Route überschneidet ein lokales LAN-Netz')
    if net.overlaps(overlay):
        raise HTTPException(422,'Standortnetz darf nicht mit dem VPN-Tunnelnetz ueberlappen')
    for row in con.execute('SELECT id,cidr FROM vpn_routes'):
        if row['id']!=ignore_id and net.overlaps(ipaddress.ip_network(row['cidr'])):
            raise HTTPException(409,'Netzbereich ueberschneidet sich mit einer bestehenden VPN-Route')
    return str(net)


def _mutate(actor, action, label, callback):
    con=connect()
    try:
        con.execute('BEGIN IMMEDIATE')
        result=callback(con)
        audit(con, actor, action, label)
        con.commit()
        return {'ok':True,'result':result,'applied':False}
    except sqlite3.IntegrityError as exc:
        con.rollback()
        raise HTTPException(409,'Name, Public Key oder Adresse bereits vergeben / Datensatz noch verknuepft') from exc
    except Exception:
        con.rollback()
        raise
    finally:con.close()




def _local_networks(con):
    return json.loads(con.execute('SELECT cidrs_json FROM vpn_local_networks WHERE id=1').fetchone()['cidrs_json'])


class LocalNetworksInput(BaseModel):
    networks: list[str] = Field(default_factory=list, max_length=16)

    @field_validator('networks')
    @classmethod
    def canonical_networks(cls, entries):
        seen=[]
        for entry in entries:
            net=private_net(entry)
            if any(net.overlaps(other) for other in seen):
                raise ValueError('Lokale Netze dürfen nicht doppelt oder überlappend sein')
            seen.append(net)
        return sorted(str(net) for net in seen)


@router.get('/local-networks')
def get_local_networks(session=Depends(require_admin)):
    con=connect()
    try: return {'networks':_local_networks(con), 'applied':False}
    finally: con.close()


@router.put('/local-networks')
def put_local_networks(payload:LocalNetworksInput,session=Depends(require_admin)):
    def cb(con):
        overlay=ipaddress.ip_interface(_hub(con)['address']).network
        routes=[ipaddress.ip_network(row['cidr']) for row in con.execute('SELECT cidr FROM vpn_routes')]
        for cidr in payload.networks:
            net=private_net(cidr)
            if net.overlaps(overlay):
                raise HTTPException(409, f'Lokales Netz {net} überschneidet Tunnelnetz {overlay}')
            for route in routes:
                if net.overlaps(route):
                    raise HTTPException(409, f'Lokales Netz {net} überschneidet VPN-Route {route}')
        con.execute('UPDATE vpn_local_networks SET cidrs_json=? WHERE id=1',
                    (json.dumps(payload.networks, separators=(',',':')),))
        return payload.networks
    return _mutate(session['username'],'vpn.local_networks.update',','.join(payload.networks),cb)


@router.get('/preflight')
def vpn_preflight(session=Depends(require_admin)):
    con=connect()
    try:
        hub=_hub(con)
        sites=asdicts(con.execute('SELECT * FROM vpn_sites ORDER BY id'))
        routes=asdicts(con.execute('SELECT * FROM vpn_routes ORDER BY id'))
        domains=asdicts(con.execute('''SELECT v.host_id,v.site_id,v.route_id,h.domain,h.upstream_host,h.upstream_port,
          h.upstream_scheme,h.enabled FROM vpn_domains v JOIN hosts h ON h.id=v.host_id ORDER BY h.domain'''))
        return readiness_report(hub,sites,routes,domains,_local_networks(con))
    finally: con.close()

@router.get('/overview')
def overview(session=Depends(require_session)):
    con=connect()
    try:
        sites=asdicts(con.execute('SELECT * FROM vpn_sites ORDER BY name'))
        routes=asdicts(con.execute('SELECT * FROM vpn_routes ORDER BY cidr'))
        domains=asdicts(con.execute('''SELECT v.host_id,v.site_id,v.route_id,h.domain,h.upstream_host,h.upstream_port,
             h.upstream_scheme,h.enabled FROM vpn_domains v JOIN hosts h ON h.id=v.host_id ORDER BY h.domain'''))
        return {'hub':_hub(con),'sites':sites,'routes':routes,'domains':domains,
                'local_networks':_local_networks(con), 'preflight_available':True,
                'mode':'configuration_only','active_tunnels_verified':False,
                'notice':'Tunnel werden nur auf einem getrennten WireGuard-Gateway aktiviert. Keine automatische Routenaenderung.'}
    finally:con.close()


@router.put('/hub')
def put_hub(payload:HubConfig,session=Depends(require_admin)):
    def cb(con):
        old=_hub(con)
        if con.execute('SELECT 1 FROM vpn_sites LIMIT 1').fetchone() and payload.address!=old['address']:
            raise HTTPException(409,'VPN-Netz kann bei bestehenden Standorten nicht geaendert werden')
        newnet=ipaddress.ip_interface(payload.address).network
        for local in _local_networks(con):
            if newnet.overlaps(ipaddress.ip_network(local)):
                raise HTTPException(409,'Hub-VPN-Netz ueberschneidet lokales LAN-Netz')
        for route in con.execute('SELECT cidr FROM vpn_routes'):
            if newnet.overlaps(ipaddress.ip_network(route['cidr'])):
                raise HTTPException(409,'Hub-VPN-Netz ueberschneidet sich mit einer Route')
        con.execute('''UPDATE vpn_hub SET interface=?,address=?,listen_port=?,endpoint=?,public_key=?,gateway_lan_ip=? WHERE id=1''',
            (payload.interface,payload.address,payload.listen_port,payload.endpoint,payload.public_key,payload.gateway_lan_ip))
        return 1
    return _mutate(session['username'],'vpn.hub.update',payload.interface,cb)


@router.post('/sites')
def add_site(payload:SiteInput,session=Depends(require_admin)):
    sid=uuid.uuid4().hex[:16]
    def cb(con):
        _validate_hub_site(con,payload.tunnel_ip)
        con.execute('''INSERT INTO vpn_sites(id,name,public_key,tunnel_ip,endpoint_host,endpoint_port,keepalive,enabled)
             VALUES(?,?,?,?,?,?,?,?)''',(sid,payload.name,payload.public_key,payload.tunnel_ip,
             payload.endpoint_host,payload.endpoint_port,payload.keepalive,int(payload.enabled)))
        return sid
    return _mutate(session['username'],'vpn.site.create',payload.name,cb)


@router.put('/sites/{sid}')
def edit_site(sid:str,payload:SiteInput,session=Depends(require_admin)):
    def cb(con):
        _site(con,sid);_validate_hub_site(con,payload.tunnel_ip,ignore_id=sid)
        con.execute('''UPDATE vpn_sites SET name=?,public_key=?,tunnel_ip=?,endpoint_host=?,endpoint_port=?,keepalive=?,enabled=? WHERE id=?''',
            (payload.name,payload.public_key,payload.tunnel_ip,payload.endpoint_host,payload.endpoint_port,
             payload.keepalive,int(payload.enabled),sid))
        return sid
    return _mutate(session['username'],'vpn.site.update',sid,cb)


@router.delete('/sites/{sid}')
def remove_site(sid:str,session=Depends(require_admin)):
    def cb(con):
        _site(con,sid)
        if con.execute('SELECT 1 FROM vpn_domains WHERE site_id=?',(sid,)).fetchone():
            raise HTTPException(409,'Zuerst VPN-Domain-Zuordnungen entfernen')
        con.execute('DELETE FROM vpn_sites WHERE id=?',(sid,))
        return sid
    return _mutate(session['username'],'vpn.site.delete',sid,cb)


@router.post('/sites/{sid}/routes')
def add_route(sid:str,payload:RouteInput,session=Depends(require_admin)):
    rid=uuid.uuid4().hex[:16]
    def cb(con):
        _site(con,sid);cidr=_validate_route(con,payload.cidr)
        con.execute('INSERT INTO vpn_routes(id,site_id,cidr) VALUES(?,?,?)',(rid,sid,cidr))
        return rid
    return _mutate(session['username'],'vpn.route.create',payload.cidr,cb)


@router.delete('/routes/{rid}')
def remove_route(rid:str,session=Depends(require_admin)):
    def cb(con):
        if not con.execute('SELECT 1 FROM vpn_routes WHERE id=?',(rid,)).fetchone():raise HTTPException(404,'Route fehlt')
        if con.execute('SELECT 1 FROM vpn_domains WHERE route_id=?',(rid,)).fetchone():
            raise HTTPException(409,'Route wird von VPN-Domains verwendet')
        con.execute('DELETE FROM vpn_routes WHERE id=?',(rid,))
        return rid
    return _mutate(session['username'],'vpn.route.delete',rid,cb)


@router.post('/domains')
def create_domain(payload:DomainInput,session=Depends(require_admin)):
    """Create a DISABLED existing ProxyCircuit web host and link to a private WG site."""
    uid=uuid.uuid4().hex[:16]
    def cb(con):
        site=_site(con,payload.site_id)
        route=con.execute('SELECT * FROM vpn_routes WHERE id=? AND site_id=?',(payload.route_id,site['id'])).fetchone()
        if not route:raise HTTPException(422,'Route gehoert nicht zum Standort')
        net=ipaddress.ip_network(route['cidr'])
        ip=private_ip(payload.target_ip)
        if ip not in net or ip in (net.network_address,net.broadcast_address):
            raise HTTPException(422,'Ziel-IP liegt nicht im freigegebenen Standortnetz')
        if con.execute('SELECT 1 FROM hosts WHERE domain=?',(payload.domain,)).fetchone():
            raise HTTPException(409,'Domain bereits vorhanden. Bestehende Domain bitte separat binden.')
        con.execute('''INSERT INTO hosts(id,domain,upstream_scheme,upstream_host,upstream_port,websocket,
             force_https,certificate_id,category,enabled) VALUES(?,?,?,?,?,1,0,NULL,?,0)''',
             (uid,payload.domain,payload.protocol,str(ip),payload.target_port,'VPN · '+site['name']))
        con.execute('INSERT INTO vpn_domains(host_id,site_id,route_id) VALUES(?,?,?)',(uid,site['id'],route['id']))
        return uid
    return _mutate(session['username'],'vpn.domain.create_disabled',payload.domain,cb)


class BindInput(BaseModel):
    host_id: str
    site_id: str
    route_id: str

@router.post('/bindings')
def bind_existing(payload:BindInput,session=Depends(require_admin)):
    def cb(con):
        _site(con,payload.site_id)
        row=con.execute('SELECT * FROM hosts WHERE id=?',(payload.host_id,)).fetchone()
        if not row:raise HTTPException(404,'Domain nicht gefunden')
        route=con.execute('SELECT * FROM vpn_routes WHERE id=? AND site_id=?',(payload.route_id,payload.site_id)).fetchone()
        if not route:raise HTTPException(422,'Route gehoert nicht zum Standort')
        try:
            target=private_ip(row['upstream_host'])
        except ValueError as exc:
            raise HTTPException(422,'Domain-Backend muss eine private IPv4-Adresse sein') from exc
        net=ipaddress.ip_network(route['cidr'])
        if target not in net or target in (net.network_address,net.broadcast_address):
            raise HTTPException(422,'Backend-IP liegt nicht in der ausgewaehlten Remote-Route')
        if con.execute('SELECT 1 FROM vpn_domains WHERE host_id=?',(payload.host_id,)).fetchone():
            raise HTTPException(409,'Domain bereits VPN-gebunden')
        con.execute('INSERT INTO vpn_domains(host_id,site_id,route_id) VALUES(?,?,?)',
                    (payload.host_id,payload.site_id,payload.route_id))
        return payload.host_id
    return _mutate(session['username'],'vpn.domain.bind',payload.host_id,cb)


@router.delete('/bindings/{host_id}')
def unbind(host_id:str,session=Depends(require_admin)):
    def cb(con):
        if con.execute('DELETE FROM vpn_domains WHERE host_id=?',(host_id,)).rowcount==0:
            raise HTTPException(404,'VPN-Bindung fehlt')
        return host_id
    return _mutate(session['username'],'vpn.domain.unbind',host_id,cb)


def exported_plan(con):
    hub=_hub(con)
    sites=asdicts(con.execute('SELECT * FROM vpn_sites WHERE enabled=1 ORDER BY name'))
    for site in sites:
        site['routes']=[r['cidr'] for r in con.execute('SELECT cidr FROM vpn_routes WHERE site_id=? ORDER BY cidr',(site['id'],))]
    return {'format':'proxycircuit-wireguard-plan-v1','hub':hub,'sites':sites,
            'local_networks':_local_networks(con),
            'warning':'Plan ohne private Schluessel, keine direkte Aktivierung. Gateway muss separat installiert, geroutet und abgesichert werden.'}


@router.get('/export')
def export_plan(session=Depends(require_admin)):
    con=connect()
    try:return exported_plan(con)
    finally:con.close()


@router.get('/preview')
def preview(session=Depends(require_admin)):
    con=connect()
    try:
        plan=exported_plan(con)
        hub=plan['hub']
        lines=[f"# Nur Vorschau! Privater Schluessel muss ausschliesslich auf dem Gateway liegen.",
               '[Interface]',f"Address = {hub['address']}",f"ListenPort = {hub['listen_port']}",
               'PrivateKey = <HUB_PRIVATE_KEY_ON_GATEWAY>']
        for site in plan['sites']:
            lines += ['',f"# Standort: {site['name']}",'[Peer]',f"PublicKey = {site['public_key']}",
                      'AllowedIPs = '+', '.join([site['tunnel_ip']+'/32']+site['routes'])]
            if site['endpoint_host']:lines.append(f"Endpoint = {site['endpoint_host']}:{site['endpoint_port']}")
            if site['keepalive']:lines.append(f"PersistentKeepalive = {site['keepalive']}")
        return {'template':'\n'.join(lines)+'\n','active':False,'note':'Kein wg-quick, keine Routen, keine Secrets in der Weboberflaeche.'}
    finally:con.close()
