# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Read-only operational verification. No external URL or command inputs accepted.

A 401 from a login-protected upstream is a valid HTTP response, not a route
failure. TLS certificate comparison verifies the *served* leaf via SNI.
"""
import hashlib
import ipaddress
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .port_binding import find_live_conflicts, live_sockets, normalize_bind_ip, overlaps
from .settings import DEPLOY, NGINX_STREAM
from .validation import clean_domain, cert_matches_domain


def inspect_served_tls(domain, ip='127.0.0.1', port=443, timeout=2.5):
    """Read metadata without trusting the certificate, and explicitly flag
    mismatches. The connection never carries login credentials or keys.
    """
    domain = clean_domain(domain)
    result={'domain':domain,'reachable':False,'certificate_matches':False,
            'http_status':None,'san':[],'subject':'','issuer':'','expires_at':None,
            'expired':None,'fingerprint_sha256':'','error':''}
    try:
        with socket.create_connection((ip,port),timeout=timeout) as sock:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname=False
            ctx.verify_mode=ssl.CERT_NONE  # metadata observation only; never used by proxy
            with ctx.wrap_socket(sock,server_hostname=domain) as tls:
                result['reachable']=True
                der=tls.getpeercert(binary_form=True)
                result['fingerprint_sha256']=hashlib.sha256(der).hexdigest().upper()
                parsed=subprocess.run(['openssl','x509','-inform','DER','-noout','-subject',
                                       '-issuer','-enddate','-ext','subjectAltName'],input=der,
                                      capture_output=True,timeout=4,check=False)
                if parsed.returncode==0:
                    info=parsed.stdout.decode('utf-8','replace')
                    result['san']=re.findall(r'DNS:([a-zA-Z0-9*_.-]+)',info)
                    match=re.search(r'^subject\s*=\s*(.*)$',info,re.M)
                    result['subject']=match.group(1)[:200] if match else ''
                    match=re.search(r'^issuer\s*=\s*(.*)$',info,re.M)
                    result['issuer']=match.group(1)[:200] if match else ''
                    result['certificate_matches']=any(cert_matches_domain(n.lower(),domain) for n in result['san'])
                    match=re.search(r'^notAfter=(.+)$',info,re.M)
                    if match:
                        try:
                            expiry=datetime.strptime(match.group(1).strip(),'%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                            result['expires_at']=expiry.isoformat()
                            result['expired']=expiry <= datetime.now(timezone.utc)
                        except ValueError:
                            pass
                tls.settimeout(timeout)
                tls.sendall((f'GET / HTTP/1.1\r\nHost: {domain}\r\n'
                             'User-Agent: ProxyCircuit-Diagnose/0.2.6\r\nConnection: close\r\n\r\n').encode('ascii'))
                line=tls.recv(1024).split(b'\r\n',1)[0].decode('latin-1','replace')
                if line.startswith('HTTP/'):
                    try:
                        result['http_status']=int(line.split()[1])
                    except (ValueError,IndexError):
                        pass
    except (OSError,ssl.SSLError,subprocess.TimeoutExpired) as exc:
        result['error']=str(exc)[:200]
    result['ok']=(result['reachable'] and result['certificate_matches'] and
                  result['expired'] is False and result['http_status'] is not None)
    result['note']='HTTPS-Metadaten ungeprueft gelesen; produktiver Proxy muss TLS weiterhin verifizieren.'
    return result


def diagnose_stream(row):
    proto=row['protocol'];port=int(row['listen_port']);ip=normalize_bind_ip(row.get('bind_ip'))
    result={'id':row['id'],'name':row['label'],'protocol':proto,'bind_ip':ip,
            'listen_port':port,'target':f"{row['target_host']}:{row['target_port']}",
            'active':bool(row['enabled']),'listen_detected':False,'backend_reachable':None,
            'service_verified':False,'notes':[]}
    found=live_sockets()
    result['listen_detected']=any(s['protocol']==proto and s['port']==port
                                  and s['bind_ip']==ip and 'nginx' in s['process'].lower()
                                  for s in found)
    conflicts=find_live_conflicts([row],sockets=found)
    result['port_conflicts']=conflicts['conflicts']
    if not row['enabled']:
        result['state']='disabled'
        return result
    if not result['listen_detected']:
        result['notes'].append('Keine aktive NGINX-Listen-Adresse gefunden; Reload-Status pruefen')
    if proto=='udp':
        result['state']='listen_only' if result['listen_detected'] else 'offline'
        result['notes'].append('UDP-Bindung sichtbar; ohne anwendungsspezifischen Test keine Aussage ueber End-to-End-Dienst')
        return result
    try:
        with socket.create_connection((row['target_host'],int(row['target_port'])),timeout=2.5) as conn:
            conn.settimeout(.35)
            result['backend_reachable']=True
            if int(row['target_port']) in (25,587,143,110):
                try:
                    banner=conn.recv(200).decode('utf-8','replace')
                    if banner.startswith(('220 ','* OK','+OK')):
                        result['service_banner_ok']=True
                except (OSError,TimeoutError):
                    pass
    except OSError as exc:
        result['backend_reachable']=False
        result['notes'].append('TCP-Verbindung zum Ziel fehlgeschlagen: '+str(exc)[:120])
    result['state']='online' if result['listen_detected'] and result['backend_reachable'] else 'offline'
    result['notes'].append('TCP-Connect beweist keine vollstaendige Protokollfunktion, insbesondere nicht SMTP/IMAP')
    return result


def nginx_process_info():
    processes=[]
    for p in psutil.process_iter(['pid','name','cmdline']):
        try:
            name=(p.info['name'] or '')
            if 'nginx' not in name.lower():
                continue
            parts=p.info['cmdline'] or []
            role='master' if any('master process' in a for a in parts) else 'worker'
            processes.append({'pid':p.info['pid'],'role':role})
        except (psutil.AccessDenied,psutil.NoSuchProcess):
            continue
    return processes[:200]


def operational_overview():
    import json
    status_file=DEPLOY/'status.json'
    try:
        status=json.loads(status_file.read_text()) if status_file.exists() else {}
    except (OSError,ValueError):
        status={}
    return {'nginx':{'processes':nginx_process_info(),
                     'running':bool(nginx_process_info())},
            'deployment':{'state':status.get('state','unknown'),
                          'message':status.get('message','Noch keine Aktivierung'),
                          'activated_at':status.get('activated_at') or status.get('last_good_at'),
                          'rollback_ok':status.get('rollback_ok'),
                          'request_id':status.get('id')},
            'listen_addresses':'siehe /api/network/listen-addresses',
            'note':'Prozessinformation ist nur eine lokale Momentaufnahme; NGINX-Status wird bei der Aktivierung separat verifiziert.'}
