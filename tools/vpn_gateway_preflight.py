#!/usr/bin/env python3
# ProxyCircuit v0.2.5 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Read-only inspection of a dedicated WireGuard gateway, with no network changes.

Requires only Python 3.11+. Checks planned routes against locally connected routes;
reports existing interfaces/listeners. Does NOT run wg-quick or change the firewall.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

try:
    from tools.wireguard_gateway import load_plan, safe_net
except ModuleNotFoundError:  # stand-alone script copied into its own directory
    from wireguard_gateway import load_plan, safe_net


def read_command(argv: list[str]) -> tuple[object | None, str | None]:
    """Allow-list only: ip and ss run read-only with fixed arguments; no shell."""
    allowed = [
        ['ip', '-j', '-4', 'route', 'show', 'scope', 'link'],
        ['ip', '-j', 'link', 'show'],
        ['ss', '-H', '-lun'],
    ]
    if argv not in allowed:
        raise ValueError('Unexpected command requested')
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            return None, f"{argv[0]} exit {result.returncode}"
        if argv[0] == 'ip':
            return json.loads(result.stdout), None
        return result.stdout, None
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return None, type(exc).__name__


def inspect(plan: dict, role: str, site_id: str = '', local_networks: list[str] | None = None,
            read=read_command) -> dict:
    """Validate an exported plan and inspect a gateway without mutating state."""
    hub, sites = load_plan_object(plan)
    issues=[]

    def flag(level, code, detail):
        issues.append({'level':level, 'code':code, 'detail':detail})

    if role not in ('hub', 'spoke'):
        raise ValueError('Role must be hub or spoke')
    selected = None
    if role == 'spoke':
        for site, routes, sid in sites:
            if sid == site_id and site.enabled:
                selected = (site, routes)
                break
        if selected is None:
            raise ValueError('Spoke-Site-ID nicht gefunden oder deaktiviert')
        if not hub.public_key or not hub.endpoint:
            flag('blocker','hub_missing_info','Hub-Public-Key und Hub-Endpoint sind fuer den Spoke notwendig.')
        targets = [ipaddress.ip_interface(hub.address).network]
    else:
        if not hub.public_key:
            flag('blocker','hub_missing_pubkey','Hub Public Key fehlt.')
        targets = [ipaddress.ip_network(cidr) for site, routes, _ in sites if site.enabled for cidr in routes]
        if not targets:
            flag('warning','no_remote_routes','Keine aktiven Remote-LAN-Routen in diesem Plan.')

    known_local = plan.get('local_networks', []) if role == 'hub' else []
    if not isinstance(known_local, list):
        raise ValueError('local_networks muss eine Liste sein')
    input_nets = [safe_net(x) for x in known_local + (local_networks or [])]
    for target in targets:
        for local in input_nets:
            if target.overlaps(local):
                flag('blocker','local_route_collision',f'Geplantes Ziel {target} ueberschneidet lokales Netz {local}.')

    routes, err = read(['ip','-j','-4','route','show','scope','link'])
    if err:
        flag('warning','route_check_unavailable',f'Lokale Kernel-Routen konnten nicht geprüft werden ({err}).')
    elif not isinstance(routes, list):
        flag('warning','route_check_invalid','Antwort von ip -j route konnte nicht gelesen werden.')
    else:
        for row in routes:
            if not isinstance(row,dict) or row.get('dev') in (hub.interface,'lo'):
                continue
            dst=row.get('dst')
            if not dst or dst=='default': continue
            try: net=ipaddress.ip_network(dst, strict=False)
            except ValueError: continue
            for target in targets:
                if target.overlaps(net):
                    flag('blocker','kernel_route_collision',f'Kernel-Route {net} auf {row.get("dev", "?")} ueberschneidet VPN-Ziel {target}.')

    links, err = read(['ip','-j','link','show'])
    if err:
        flag('warning','link_check_unavailable',f'Interfaces konnten nicht geprüft werden ({err}).')
    elif isinstance(links,list) and any(isinstance(row,dict) and row.get('ifname')==hub.interface for row in links):
        flag('warning','interface_exists',f'Interface {hub.interface} existiert bereits; vor einer Änderung den bestehenden Tunnel kontrollieren.')

    if role == 'hub':
        udp,err=read(['ss','-H','-lun'])
        if err:
            flag('warning','port_check_unavailable',f'UDP-Portbelegung konnte nicht geprüft werden ({err}).')
        elif isinstance(udp,str) and any(
            line.split()[4].rsplit(':',1)[-1]==str(hub.listen_port)
            for line in udp.splitlines() if len(line.split())>=5
        ):
            flag('warning','udp_port_listening',f'UDP-Port {hub.listen_port} wird bereits verwendet; Betreiber muss Prozess prüfen.')

    blockers=sum(item['level']=='blocker' for item in issues)
    warnings=sum(item['level']=='warning' for item in issues)
    return {'tool':'proxycircuit-vpn-gateway-preflight-v1',
            'role':role,'site_id':site_id if role=='spoke' else None,
            'status':'blocked' if blockers else 'review_required' if warnings else 'ready_for_manual_test',
            'blockers':blockers,'warnings':warnings,'checks':issues,
            'network_changed':False, 'tunnel_started':False, 'live_connection_verified':False,
            'note':'Nur Gateway-Vorprüfung. Ein echter Tunnel/Handshake wird hier nicht geprüft.'}


def load_plan_object(plan: dict):
    # Reuse the strict v0.2.4 parser by loading from a tiny, private, temporary
    # file only if necessary. Instead read_plan accepts Path; no secrets in plan.
    import tempfile
    import os
    fd, filename=tempfile.mkstemp(prefix='pc-vpn-plan-', suffix='.json')
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as out:
            json.dump(plan,out)
        return load_plan(Path(filename))
    finally:
        Path(filename).unlink(missing_ok=True)


def main(argv=None):
    parser=argparse.ArgumentParser(description='Sichere, lesende WireGuard-Gateway-Vorpruefung')
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--role',choices=('hub','spoke'),required=True)
    parser.add_argument('--site-id',default='')
    parser.add_argument('--local-net',action='append',default=[],help='Lokales LAN-CIDR (mehrfach moeglich)')
    args=parser.parse_args(argv)
    try:
        if args.plan.stat().st_size>1024*1024:
            raise ValueError('Plan ist zu gross')
        plan=json.loads(args.plan.read_text(encoding='utf-8'))
        report=inspect(plan,args.role,args.site_id,args.local_net)
        print(json.dumps(report,ensure_ascii=False,indent=2))
        return 2 if report['blockers'] else 0
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
        print('Vorprüfung fehlgeschlagen:',str(exc),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
