# ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Opt-in LAN tools; require administrator access for all active network operations.

No raw shell execution endpoints, no public-network scanning, no arbitrary URL fetches.
"""
import asyncio
import base64
import hashlib
import ipaddress
import re
import secrets
import socket
import time
from contextlib import suppress
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from .db import connect, audit
from .security import COOKIE, require_admin, require_session

router = APIRouter(prefix='/api/utilities', tags=['utilities'])
LAN = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
SCAN_LOCK = asyncio.Semaphore(2)
SSH_SLOTS = asyncio.Semaphore(2)


def private_ipv4(raw: str) -> str:
    try:
        addr = ipaddress.IPv4Address(raw.strip())
    except (ValueError, AttributeError):
        raise HTTPException(422, 'Nur numerische IPv4-Adressen sind erlaubt')
    if not any(addr in net for net in LAN):
        raise HTTPException(422, 'Nur private IPv4-Adressen (RFC1918) sind erlaubt')
    return str(addr)


def port_number(raw: int) -> int:
    if type(raw) is not int or not (1 <= raw <= 65535):
        raise HTTPException(422, 'Ungueltiger Port')
    return raw


def record_tool(user: str, action: str, description: str) -> None:
    con = connect()
    try:
        with con:
            audit(con, user, action, description)
    finally:
        con.close()


class CIDRRequest(BaseModel):
    cidr: str = Field(min_length=3, max_length=80)


@router.post('/cidr')
def cidr_converter(payload: CIDRRequest, session=Depends(require_session)):
    try:
        net = ipaddress.ip_network(payload.cidr.strip(), strict=False)
    except ValueError as exc:
        raise HTTPException(422, 'Ungueltige CIDR-Adresse') from exc
    if net.version == 4:
        start = int(net.network_address) + (1 if net.num_addresses > 2 else 0)
        end = int(net.broadcast_address) - (1 if net.num_addresses > 2 else 0)
        hosts = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
        return dict(version=4, cidr=str(net), network=str(net.network_address),
                    netmask=str(net.netmask), wildcard=str(net.hostmask),
                    broadcast=str(net.broadcast_address), first=str(ipaddress.ip_address(start)),
                    last=str(ipaddress.ip_address(end)), addresses=net.num_addresses,
                    usable=hosts)
    return dict(version=6, cidr=str(net), network=str(net.network_address),
                netmask=str(net.netmask), wildcard='', broadcast='',
                first=str(net.network_address), last=str(net[-1]),
                addresses=str(net.num_addresses), usable=str(net.num_addresses))


class IPScanRequest(BaseModel):
    cidr: str = Field(min_length=6, max_length=32)
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443], max_length=6)


class PortScanRequest(BaseModel):
    host: str = Field(min_length=7, max_length=15)
    ports: list[int] = Field(min_length=1, max_length=128)


def scan_network(cidr: str):
    try:
        network = ipaddress.IPv4Network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise HTTPException(422, 'Ungueltiges IPv4-Netz') from exc
    if not any(network.subnet_of(lan) for lan in LAN):
        raise HTTPException(422, 'Nur private RFC1918-Netze erlaubt')
    if network.num_addresses > 256:
        raise HTTPException(422, 'Maximal 256 IP-Adressen je Scan (/24)')
    return network


def validate_ports(ports: list[int], max_count: int) -> list[int]:
    if not ports or len(ports) > max_count or len(set(ports)) != len(ports):
        raise HTTPException(422, f'1 bis {max_count} unterschiedliche Ports erforderlich')
    return [port_number(port) for port in ports]


async def tcp_probe(ip: str, port: int, timeout: float = 0.65) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        writer.close()
        with suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 0.25)
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def guarded_scan(tasks: list[tuple[str, int]]):
    async with SCAN_LOCK:
        limited = asyncio.Semaphore(32)
        async def probe(ip, port):
            async with limited:
                return ip, port, await tcp_probe(ip, port)
        return await asyncio.gather(*(probe(ip, port) for ip, port in tasks))


@router.post('/ip-scan')
async def ip_scanner(payload: IPScanRequest, session=Depends(require_admin)):
    network = scan_network(payload.cidr)
    ports = validate_ports(payload.ports, 6)
    hosts = [str(ip) for ip in network.hosts()]
    result = await guarded_scan([(host, port) for host in hosts for port in ports])
    found = {}
    for host, port, is_open in result:
        if is_open:
            found.setdefault(host, []).append(port)
    record_tool(session['username'], 'utility.ipscan', f'{network} / {len(ports)} TCP-Ports')
    return {'cidr': str(network), 'scanned_hosts': len(hosts), 'ports': ports,
            'method': 'TCP-Connect; kein ICMP', 'responsive':
            [{'ip': ip, 'open_ports': found[ip]} for ip in sorted(found, key=ipaddress.IPv4Address)]}


@router.post('/port-scan')
async def port_scanner(payload: PortScanRequest, session=Depends(require_admin)):
    host = private_ipv4(payload.host)
    ports = validate_ports(payload.ports, 128)
    result = await guarded_scan([(host, port) for port in ports])
    record_tool(session['username'], 'utility.portscan', f'{host} / {len(ports)} TCP-Ports')
    return {'host': host, 'scanned': len(ports), 'open': sorted(port for _, port, status in result if status),
            'closed_or_filtered': sorted(port for _, port, status in result if not status),
            'method': 'TCP-Connect; geschlossen und gefiltert nicht unterscheidbar'}


class WOLRequest(BaseModel):
    mac: str = Field(min_length=12, max_length=20)
    broadcast: str = Field(default='255.255.255.255', max_length=15)
    port: Literal[7, 9] = 9


@router.post('/wake-on-lan')
async def wake_on_lan(payload: WOLRequest, session=Depends(require_admin)):
    mac = payload.mac.replace(':', '').replace('-', '').replace('.', '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{12}', mac) or int(mac[:2], 16) & 1:
        raise HTTPException(422, 'Ungueltige MAC-Adresse (Unicast erwartet)')
    if payload.broadcast != '255.255.255.255':
        private_ipv4(payload.broadcast)
    packet = b'\xff' * 6 + bytes.fromhex(mac) * 16
    def send():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2)
            sock.sendto(packet, (payload.broadcast, payload.port))
    try:
        await asyncio.to_thread(send)
    except OSError as exc:
        raise HTTPException(502, f'Wake-on-LAN Versand fehlgeschlagen: {exc}') from exc
    record_tool(session['username'], 'utility.wol', f'Broadcast {payload.broadcast}:{payload.port}')
    return {'sent': True, 'message': 'Magic Packet versendet; Einschalten nicht verifiziert'}


def scan_mdns_sync(seconds: float = 4.0):
    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    except ImportError as exc:
        raise RuntimeError('zeroconf nicht installiert; Update-Abhaengigkeiten pruefen') from exc
    types = set()
    devices = {}
    class TypeListener(ServiceListener):
        def add_service(self, zc, service_type, name):
            if len(types) < 24 and (name.endswith('._tcp.local.') or name.endswith('._udp.local.')):
                types.add(name)
        def update_service(self, zc, service_type, name):
            pass
        def remove_service(self, zc, service_type, name):
            pass
    class HostListener(ServiceListener):
        def add_service(self, zc, service_type, name):
            if len(devices) >= 70:
                return
            try:
                info = zc.get_service_info(service_type, name, timeout=400)
                if info:
                    devices[(service_type, name)] = {'name': name[:140],
                       'type': service_type[:140], 'host': (info.server or '')[:140],
                       'addresses': info.parsed_addresses()[:8], 'port': info.port}
            except (OSError, ValueError):
                pass
        def update_service(self, zc, service_type, name):
            self.add_service(zc, service_type, name)
        def remove_service(self, zc, service_type, name):
            pass
    zc = Zeroconf()
    browsers = []
    try:
        browsers.append(ServiceBrowser(zc, '_services._dns-sd._udp.local.', TypeListener()))
        time.sleep(seconds / 2)
        for t in sorted(types)[:24]:
            try:
                browsers.append(ServiceBrowser(zc, t, HostListener()))
            except (ValueError, OSError):
                pass
        time.sleep(seconds / 2)
        return {'service_types': sorted(types), 'devices': sorted(devices.values(), key=lambda d:d['name']),
                'note': 'mDNS nutzt Multicast UDP 5353; LXC-/VLAN-Grenzen koennen Ergebnisse verhindern'}
    finally:
        for b in browsers:
            b.cancel()
        zc.close()


@router.post('/mdns')
async def mdns_scanner(session=Depends(require_admin)):
    async with SCAN_LOCK:
        try:
            result = await asyncio.wait_for(asyncio.to_thread(scan_mdns_sync), timeout=10)
        except (RuntimeError, OSError, asyncio.TimeoutError) as exc:
            raise HTTPException(503, f'mDNS-Suche nicht verfuegbar: {exc}') from exc
    record_tool(session['username'], 'utility.mdns', f'{len(result["devices"])} Geraete')
    return result


class ForwardProxyRequest(BaseModel):
    proxy_ip: str = Field(min_length=7, max_length=15)
    proxy_port: int = Field(ge=1, le=65535)
    host_id: str = Field(min_length=1, max_length=100)


def _test_http_proxy(proxy_ip: str, proxy_port: int, target: str, target_port: int, encrypted: bool):
    with socket.create_connection((proxy_ip, proxy_port), timeout=4) as sock:
        sock.settimeout(4)
        if encrypted:
            request = f'CONNECT {target}:{target_port} HTTP/1.1\r\nHost: {target}:{target_port}\r\nProxy-Connection: close\r\n\r\n'
        else:
            request = f'HEAD http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n'
        sock.sendall(request.encode('ascii'))
        response = bytearray()
        while b'\r\n' not in response and len(response) < 2048:
            part = sock.recv(256)
            if not part:
                break
            response.extend(part)
        first = bytes(response).split(b'\r\n', 1)[0].decode('latin1', 'replace')[:160]
        if not re.match(r'^HTTP/1\.[01] [0-9]{3}\b', first):
            raise ValueError('Keine gueltige HTTP-Proxy-Antwort erhalten')
        return first


@router.post('/forward-proxy')
async def debug_forward_proxy(payload: ForwardProxyRequest, session=Depends(require_admin)):
    ip = private_ipv4(payload.proxy_ip)
    port = port_number(payload.proxy_port)
    con = connect()
    try:
        host = con.execute('SELECT domain,certificate_id FROM hosts WHERE id=?', (payload.host_id,)).fetchone()
    finally:
        con.close()
    if host is None or not re.fullmatch(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}', host['domain']):
        raise HTTPException(404, 'Bekannte Proxy-Domain als Testziel auswaehlen')
    tls = bool(host['certificate_id'])
    try:
        status_line = await asyncio.to_thread(_test_http_proxy, ip, port, host['domain'], 443 if tls else 80, tls)
    except (OSError, ValueError) as exc:
        raise HTTPException(502, f'Forward-Proxy-Test fehlgeschlagen: {str(exc)[:180]}') from exc
    record_tool(session['username'], 'utility.forward_proxy', f'{ip}:{port} zu {host["domain"]}')
    status = int(status_line.split(' ')[1])
    return {'proxy': f'{ip}:{port}', 'target': host['domain'], 'method': 'CONNECT' if tls else 'HEAD',
            'response': status_line, 'proxy_responded': True,
            'connected': status == 200 if tls else 200 <= status < 400}


class SSHHostKeyRequest(BaseModel):
    host: str = Field(min_length=7, max_length=15)
    port: int = Field(default=22, ge=1, le=65535)


def _ssh_fingerprint(host: str, port: int):
    import paramiko
    connection = socket.create_connection((host, port), timeout=6)
    transport = paramiko.Transport(connection)
    try:
        transport.start_client(timeout=8)
        key = transport.get_remote_server_key()
        return {'algorithm': key.get_name(), 'fingerprint': 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')}
    finally:
        transport.close()


@router.post('/ssh/hostkey')
async def ssh_hostkey(payload: SSHHostKeyRequest, session=Depends(require_admin)):
    host = private_ipv4(payload.host)
    try:
        return await asyncio.wait_for(asyncio.to_thread(_ssh_fingerprint, host, payload.port), timeout=12)
    except (OSError, Exception) as exc:
        raise HTTPException(502, f'SSH-Hostkey-Abfrage fehlgeschlagen: {str(exc)[:160]}') from exc


def _ssh_start(host, port, username, password, fingerprint, columns, rows):
    import paramiko
    connection = socket.create_connection((host, port), timeout=6)
    t = paramiko.Transport(connection)
    try:
        t.start_client(timeout=8)
        key = t.get_remote_server_key()
        actual = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        if not secrets.compare_digest(actual, fingerprint):
            raise ValueError('SSH-Hostkey stimmt nicht mit dem bestaetigten Fingerprint ueberein')
        t.auth_password(username, password, fallback=False)
        if not t.is_authenticated():
            raise ValueError('SSH-Anmeldung fehlgeschlagen')
        channel = t.open_session(timeout=8)
        channel.get_pty(term='xterm', width=columns, height=rows)
        channel.invoke_shell()
        channel.settimeout(.5)
        return t, channel
    except Exception:
        t.close()
        raise


def _websocket_admin(ws: WebSocket):
    # WebSocket cookies are ambient: enforce same-origin and require CSRF in the first packet.
    host = ws.headers.get('host', '')
    if not host or ws.headers.get('origin') != 'https://' + host:
        return None
    token = ws.cookies.get(COOKIE, '')
    if not token:
        return None
    con = connect()
    try:
        row = con.execute('''SELECT s.username,s.csrf,s.expires,a.role,a.active FROM sessions s
              JOIN admins a ON a.username=s.username WHERE s.token_hash=?''',
              (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if row and row['active'] and row['role'] == 'admin' and row['expires'] > time.time():
            return dict(row)
        return None
    finally:
        con.close()


@router.websocket('/ssh/ws')
async def ssh_websocket(ws: WebSocket):
    session = _websocket_admin(ws)
    if session is None:
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        auth = await asyncio.wait_for(ws.receive_json(), timeout=12)
        if not isinstance(auth, dict) or auth.get('type') != 'connect' or not secrets.compare_digest(str(auth.get('csrf', '')), session['csrf']):
            await ws.close(code=1008)
            return
        host = private_ipv4(str(auth.get('host', '')))
        port = port_number(auth.get('port'))
        username = str(auth.get('username', ''))
        password = str(auth.get('password', ''))
        fingerprint = str(auth.get('fingerprint', ''))
        if not (re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,31}', username) and
                0 < len(password) <= 512 and re.fullmatch(r'SHA256:[a-zA-Z0-9+/]{43}', fingerprint)):
            await ws.send_json({'type':'error', 'message':'SSH-Zugangsdaten oder Hostkey ungueltig'})
            await ws.close(code=1008)
            return
        cols = min(180, max(40, int(auth.get('cols', 90))))
        rows = min(70, max(15, int(auth.get('rows', 25))))
        try:
            await asyncio.wait_for(SSH_SLOTS.acquire(), timeout=.5)
        except asyncio.TimeoutError:
            await ws.send_json({'type':'error', 'message':'Maximal zwei SSH-Sitzungen gleichzeitig'})
            await ws.close(code=1013)
            return
        try:
            transport, channel = await asyncio.wait_for(asyncio.to_thread(
                _ssh_start, host, port, username, password, fingerprint, cols, rows), timeout=18)
            record_tool(session['username'], 'utility.ssh_connect', f'{username}@{host}:{port}')
            await ws.send_json({'type':'ready', 'message':'SSH-Verbindung hergestellt (max. 15 Minuten)'})
            start = time.monotonic()
            async def output_loop():
                while not channel.closed and time.monotonic()-start < 900:
                    try:
                        output = await asyncio.to_thread(channel.recv, 4096)
                    except socket.timeout:
                        continue
                    if not output:
                        break
                    await ws.send_json({'type':'output', 'data':output.decode('utf-8','replace')})
            async def input_loop():
                while not channel.closed and time.monotonic()-start < 900:
                    try:
                        message = await asyncio.wait_for(ws.receive_json(), timeout=30)
                    except asyncio.TimeoutError:
                        continue
                    if not isinstance(message, dict):
                        continue
                    if message.get('type') == 'input':
                        value = str(message.get('data',''))
                        if len(value) <= 4096:
                            await asyncio.to_thread(channel.sendall, value.encode('utf-8'))
                    elif message.get('type') == 'resize':
                        width = min(180,max(40,int(message.get('cols',90))))
                        height = min(70,max(15,int(message.get('rows',25))))
                        await asyncio.to_thread(channel.resize_pty,width=width,height=height)
            tasks=[asyncio.create_task(output_loop()),asyncio.create_task(input_loop())]
            done,pending=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED, timeout=900)
            for task in pending:task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
        finally:
            if 'channel' in locals(): channel.close()
            if 'transport' in locals(): transport.close()
            SSH_SLOTS.release()
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as exc:
        with suppress(Exception):
            await ws.send_json({'type':'error','message': f'SSH: {str(exc)[:160]}'})
    finally:
        with suppress(Exception):
            await ws.close()
