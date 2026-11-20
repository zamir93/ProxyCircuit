# ProxyCircuit v0.2.5 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Deterministic, side-effect-free VPN readiness review. Never claims a live tunnel.

This module intentionally does not open sockets, run binaries, alter routes or persist
secrets. Every result is a configuration review, not a connectivity assertion.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any


def _canonical_hash(hub: dict, sites: list[dict], routes: list[dict],
                    domains: list[dict], local_networks: list[str]) -> str:
    state = {'hub': hub,
             'sites': sorted(sites, key=lambda x: x['id']),
             'routes': sorted(routes, key=lambda x: x['id']),
             'domains': sorted(domains, key=lambda x: x['host_id']),
             'local_networks': sorted(local_networks)}
    payload = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def readiness_report(hub: dict, sites: list[dict], routes: list[dict],
                     domains: list[dict], local_networks: list[str]) -> dict[str, Any]:
    """Review current configuration and produce actionable, conservative checks.

    Data is read from an authenticated local DB context; this function has no I/O.
    """
    issues: list[dict] = []

    def flag(level: str, code: str, text: str, site_id: str = '') -> None:
        issues.append({'level': level, 'code': code, 'detail': text, 'site_id': site_id})

    overlay = ipaddress.ip_interface(hub['address']).network
    local_nets = [ipaddress.ip_network(x, strict=True) for x in local_networks]
    enabled_sites = [s for s in sites if s['enabled']]
    site_ids = {s['id'] for s in sites}
    route_by_id = {r['id']: r for r in routes}

    if not hub.get('public_key'):
        flag('blocker', 'hub_public_key_missing', 'Öffentlichen WireGuard-Schlüssel des Hubs eintragen.')
    if not hub.get('endpoint'):
        flag('blocker', 'hub_endpoint_missing', 'Öffentliche Hub-Adresse (DNS/IP) für Remote-Gateways fehlt.')
    if not enabled_sites:
        flag('blocker', 'no_active_site', 'Mindestens einen aktivierten VPN-Standort konfigurieren.')
    if not local_nets:
        flag('warning', 'local_nets_unspecified', 'Lokale LAN-Netze eintragen, um überlappende Routen zu erkennen.')
    if not hub.get('gateway_lan_ip'):
        flag('warning', 'gateway_lan_ip_missing', 'LAN-Adresse des separaten Hub-Gateways fehlt (ggf. manuelle Proxy-Route notwendig).')
    elif local_nets and not any(ipaddress.ip_address(hub['gateway_lan_ip']) in n for n in local_nets):
        flag('warning', 'gateway_outside_local_lan', 'Die Hub-Gateway-IP liegt nicht in den angegebenen lokalen Netzen.')

    for lan in local_nets:
        if lan.overlaps(overlay):
            flag('blocker', 'local_overlaps_overlay', f'Lokales Netz {lan} überschneidet das VPN-Tunnelnetz {overlay}.')

    seen = []
    for route in routes:
        net = ipaddress.ip_network(route['cidr'], strict=True)
        if route['site_id'] not in site_ids:
            flag('blocker', 'orphan_route', f'Route {net} hat keinen vorhandenen Standort.', route['site_id'])
        if net.overlaps(overlay):
            flag('blocker', 'route_overlaps_overlay', f'VPN-Route {net} überschneidet das Tunnelnetz.', route['site_id'])
        for lan in local_nets:
            if net.overlaps(lan):
                flag('blocker', 'remote_overlaps_local', f'Remote-Netz {net} überschneidet lokales Netz {lan}.', route['site_id'])
        for other, other_site in seen:
            if net.overlaps(other):
                flag('blocker', 'remote_routes_overlap', f'Remote-Netze {net} und {other} überschneiden sich.', route['site_id'])
        seen.append((net, route['site_id']))

    for site in enabled_sites:
        sroutes = [r for r in routes if r['site_id'] == site['id']]
        if not sroutes:
            flag('warning', 'site_has_no_lan_route', f"Standort {site['name']} hat noch keine private LAN-Route.", site['id'])
        if not site.get('endpoint_host'):
            flag('info', 'dynamic_peer', f"Standort {site['name']} ist ohne festen Endpoint (Remote-Peer muss Hub kontaktieren).", site['id'])

    for dom in domains:
        sid = dom.get('site_id')
        route = route_by_id.get(dom.get('route_id'))
        site = next((s for s in sites if s['id'] == sid), None)
        if not route or not site or route['site_id'] != sid:
            flag('blocker', 'broken_domain_binding', f"VPN-Domain {dom['domain']} hat eine ungültige Standort-/Routenbindung.", sid or '')
            continue
        try:
            ip = ipaddress.ip_address(dom['upstream_host'])
            net = ipaddress.ip_network(route['cidr'], strict=True)
            if ip not in net:
                flag('blocker', 'domain_outside_route', f"Ziel {dom['domain']} liegt außerhalb von {net}.", sid)
        except ValueError:
            flag('blocker', 'invalid_domain_target', f"Ziel-IP für {dom['domain']} ist ungültig.", sid)
        if not site['enabled']:
            flag('warning', 'domain_bound_to_disabled_site', f"Domain {dom['domain']} nutzt einen deaktivierten Standort.", sid)
        if dom['enabled']:
            flag('warning', 'active_domain_unverified', f"VPN-Domain {dom['domain']} ist bereits aktiv: Tunnel-/TLS-/Backend-Status separat prüfen.", sid)

    blockers = sum(item['level'] == 'blocker' for item in issues)
    warnings = sum(item['level'] == 'warning' for item in issues)
    return {
        'version': 'proxycircuit-vpn-preflight-v1',
        'status': 'blocked' if blockers else 'review_required' if warnings else 'ready_for_gateway_test',
        'blockers': blockers, 'warnings': warnings, 'checks': issues,
        'config_sha256': _canonical_hash(hub, sites, routes, domains, local_networks),
        'counts': {'sites': len(sites), 'active_sites': len(enabled_sites),
                   'routes': len(routes), 'domains': len(domains)},
        'local_networks': local_networks,
        'active_tunnels_verified': False, 'reachability_checked': False,
        'changes_applied': False,
        'next_step': 'Manuelle Prüfung auf einem separaten WireGuard-Gateway, erst danach kontrolliert aktivieren.',
    }
