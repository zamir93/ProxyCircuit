# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Address-aware port binding checks, without modifying other processes.

Two different IPv4 addresses may share a port; a wildcard overlaps both.
IPv6 wildcard is handled conservatively across families since the effective
IPV6_V6ONLY socket setting may be different on different installations.
"""
from __future__ import annotations
import ipaddress
import json
import subprocess
import re
import socket
from pathlib import Path

import psutil

from .settings import NGINX_STREAM

WILDCARDS = {'0.0.0.0', '::'}
RESERVED_TCP = {80, 443, 18081, 9443}
LISTENER_RE = re.compile(r'^\s*listen\s+(\[[0-9A-Fa-f:.]+\]:\d+|(?:\d{1,3}\.){3}\d+:\d+|\d+)(?:\s+udp)?\s*;', re.M)


def normalize_bind_ip(value):
    if value is None or value == '' or str(value).strip().lower() in ('all', 'alle'):
        return '0.0.0.0'
    if not isinstance(value, str) or value != value.strip():
        raise ValueError('Bind-IP muss eine IPv4- oder IPv6-Adresse sein')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError('Bind-IP muss eine IPv4- oder IPv6-Adresse sein (kein Hostname)') from exc


def local_addresses():
    """Assigned interface addresses only (with an iproute2 fallback for restricted psutil)."""
    result = []
    try:
        interfaces = psutil.net_if_addrs()
        pairs = [(interface, entry.family, entry.address)
                 for interface, entries in interfaces.items() for entry in entries]
    except OSError:
        # Some restricted systemd services cannot use psutil's netlink call.
        # AF_NETLINK remains enabled explicitly in the shipped systemd unit.
        output = subprocess.run(['/usr/sbin/ip', '-j', 'address', 'show'],
                                capture_output=True, text=True, check=True, timeout=5)
        pairs = []
        for interface in json.loads(output.stdout):
            name = interface.get('ifname', '')
            for addr in interface.get('addr_info', []):
                family = {'inet': socket.AF_INET, 'inet6': socket.AF_INET6}.get(addr.get('family'))
                if family and addr.get('local'):
                    pairs.append((name, family, addr['local']))
    for interface, family, raw in pairs:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        try:
            address = str(ipaddress.ip_address(raw.split('%', 1)[0]))
        except ValueError:
            continue
        result.append({'interface': interface, 'address': address,
                       'family': 'ipv6' if ':' in address else 'ipv4',
                       'loopback': ipaddress.ip_address(address).is_loopback})
    return sorted(result, key=lambda x: (x['loopback'], x['interface'], x['address']))


def assert_assigned(address, available=None):
    address = normalize_bind_ip(address)
    if address in WILDCARDS:
        return address
    assigned = {item['address'] for item in (available if available is not None else local_addresses())}
    if address not in assigned:
        raise ValueError(f'Bind-IP {address} ist nicht auf einer lokalen Netzwerkschnittstelle konfiguriert')
    return address


def overlaps(a, b):
    a, b = normalize_bind_ip(a), normalize_bind_ip(b)
    if a == b:
        return True
    # :: might accept IPv4-mapped connections (dual-stack), so err on the safe side.
    if a == '::' or b == '::':
        return True
    ip_a, ip_b = ipaddress.ip_address(a), ipaddress.ip_address(b)
    if ip_a.version != ip_b.version:
        return False
    if a == '0.0.0.0' or b == '0.0.0.0':
        return True
    return False


def rules_conflicts(rows):
    active = [dict(r) for r in rows if r.get('enabled', True)]
    errors = []
    for i, first in enumerate(active):
        for second in active[i + 1:]:
            if (first['protocol'] == second['protocol']
                    and int(first['listen_port']) == int(second['listen_port'])
                    and overlaps(first.get('bind_ip'), second.get('bind_ip'))):
                errors.append(f"{first['protocol'].upper()} {first['listen_port']}: "
                              f"{first.get('bind_ip') or '0.0.0.0'} und "
                              f"{second.get('bind_ip') or '0.0.0.0'} ueberschneiden sich "
                              f"({first['label']} / {second['label']})")
    return errors


def parse_managed_listeners(path=NGINX_STREAM):
    """Determine which active Nginx sockets are currently managed by us."""
    try:
        config = Path(path).read_text(encoding='utf-8')
    except OSError:
        return set()
    listeners = set()
    for match in LISTENER_RE.finditer(config):
        token = match.group(1)
        tail = config[match.end():match.end() + 1]  # only to keep source scanner bounded
        _ = tail
        is_udp = bool(re.search(r'\budp\s*;$', match.group(0)))
        if token.isdecimal():
            ip, port = '0.0.0.0', int(token)
        elif token.startswith('['):
            ip, port = token[1:].split(']:')
            port = int(port)
        else:
            ip, port = token.rsplit(':', 1)
            port = int(port)
        try:
            listeners.add(('udp' if is_udp else 'tcp', port, normalize_bind_ip(ip)))
        except ValueError:
            pass
    return listeners


def process_name(pid):
    if pid is None:
        return 'Prozess nicht lesbar'
    try:
        return psutil.Process(pid).name()[:70]
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return 'Prozess nicht lesbar'


def live_sockets(connections=None):
    """List actual TCP listeners / UDP bindings; never attempts to bind ports."""
    if connections is None:
        connections = psutil.net_connections(kind='inet')
    found = []
    for entry in connections:
        family = getattr(entry, 'family', None)
        socktype = getattr(entry, 'type', None)
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        if socktype == socket.SOCK_STREAM:
            if getattr(entry, 'status', None) != 'LISTEN':
                continue
            proto = 'tcp'
        elif socktype == socket.SOCK_DGRAM:
            proto = 'udp'
        else:
            continue
        loc = getattr(entry, 'laddr', None)
        if not loc:
            continue
        ip = loc.ip if hasattr(loc, 'ip') else loc[0]
        port = loc.port if hasattr(loc, 'port') else loc[1]
        try:
            ip = normalize_bind_ip(ip.split('%', 1)[0])
        except ValueError:
            continue
        pid = getattr(entry, 'pid', None)
        found.append({'protocol': proto, 'bind_ip': ip, 'port': int(port),
                      'pid': pid, 'process': process_name(pid)})
    return found


def find_live_conflicts(rows, *, sockets=None, managed=None):
    """Only foreign listeners block a deploy. Existing *managed* Nginx may be
    replaced by a reload, but an overlapping old socket requires an actual
    post-reload verification; nginx -t alone is insufficient.
    """
    sockets = live_sockets() if sockets is None else sockets
    managed = parse_managed_listeners() if managed is None else managed
    errors, warnings = [], []
    for row in rows:
        if not row.get('enabled', True):
            continue
        target = normalize_bind_ip(row.get('bind_ip'))
        proto, port = row['protocol'], int(row['listen_port'])
        for other in sockets:
            if other['protocol'] != proto or other['port'] != port:
                continue
            if not overlaps(target, other['bind_ip']):
                continue
            label = f"{proto.upper()} {target}:{port} kollidiert mit {other['bind_ip']}:{port} ({other['process']}, PID {other['pid'] or '?'})"
            is_nginx = 'nginx' in other['process'].lower()
            is_managed = is_nginx and any(p == proto and n == port and overlaps(ip, other['bind_ip']) for p, n, ip in managed)
            if is_managed:
                warnings.append('Bisheriger verwalteter Nginx-Listener: ' + label)
            else:
                errors.append(label)
    return {'conflicts': sorted(set(errors)), 'warnings': sorted(set(warnings))}


def assert_bindings(rows, *, sockets=None, managed=None, available=None):
    for row in rows:
        if row.get('enabled', True):
            assert_assigned(row.get('bind_ip'), available)
    duplicates = rules_conflicts(rows)
    if duplicates:
        raise ValueError('Portregel-Konflikt: ' + ' | '.join(duplicates)[:500])
    result = find_live_conflicts(rows, sockets=sockets, managed=managed)
    if result['conflicts']:
        raise ValueError('Port bereits belegt: ' + ' | '.join(result['conflicts'])[:500])
    return result
