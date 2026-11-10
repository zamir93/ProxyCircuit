# ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Read-only, security-preserving backend/TLS diagnostics for stored proxy hosts.

We do not disable certificate checks in Nginx. The optional certificate inspection
uses an unverified diagnostic TLS connection only to inspect metadata and suggest
repairs; never as a production proxy configuration.
"""
import errno
import http.client
import ipaddress
import re
import html
import socket
import ssl
import subprocess
from pathlib import Path

from .settings import NGINX_HTTP
from .validation import HostInput


def config_presence(domain: str, path=NGINX_HTTP):
    try:
        text = Path(path).read_text(encoding='utf-8')
    except OSError as exc:
        return {'readable': False, 'http': False, 'https': False, 'message': str(exc)[:200]}
    return {'readable': True, 'http': f'# HTTP host: {domain}\n' in text,
            'https': f'# HTTPS host: {domain}\n' in text}


def resolve_ipv4(domain):
    try:
        rows = socket.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return {'addresses': sorted({r[4][0] for r in rows}), 'error': ''}
    except OSError as exc:
        return {'addresses': [], 'error': str(exc)[:200]}


def certificate_info(host, port, name):
    """Best-effort CERTIFICATE METADATA ONLY; does not establish trust."""
    try:
        proc = subprocess.run(['openssl', 's_client', '-connect', f'{host}:{port}', '-servername', name,
                               '-showcerts'], input='', capture_output=True, text=True, timeout=4)
        data = proc.stdout
        a = data.find('-----BEGIN CERTIFICATE-----')
        b = data.find('-----END CERTIFICATE-----', a)
        if a < 0 or b < 0:
            return {}
        pem = data[a:b + len('-----END CERTIFICATE-----')]
        decoded = subprocess.run(['openssl', 'x509', '-noout', '-subject', '-issuer', '-dates',
                                  '-ext', 'subjectAltName', '-fingerprint', '-sha256'], input=pem, capture_output=True,
                                 text=True, timeout=3)
        if decoded.returncode:
            return {}
        text = decoded.stdout[:1800]
        dns_names = re.findall(r'DNS:([^,\s]+)', text)
        ip_addresses = re.findall(r'IP Address:([^,\s]+)', text)
        fingerprint = re.search(r'sha256 Fingerprint=([^\n]+)', text, re.I)
        subject = re.search(r'^subject=(.+)$', text, re.M)
        issuer = re.search(r'^issuer=(.+)$', text, re.M)
        from datetime import datetime, timezone
        expires_at = None
        expired = False
        for line in text.splitlines():
            if line.startswith('notAfter='):
                try:
                    expires_at = datetime.strptime(line.split('=', 1)[1].strip(),
                          '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    expired = expires_at < datetime.now(timezone.utc)
                except ValueError:
                    pass
        return {'details': text, 'dns_names': dns_names, 'ip_addresses': ip_addresses,
                'sha256_fingerprint': fingerprint.group(1).strip() if fingerprint else '',
                'subject': subject.group(1).strip() if subject else '',
                'issuer': issuer.group(1).strip() if issuer else '',
                'self_signed_candidate': bool(subject and issuer and subject.group(1).strip() == issuer.group(1).strip()),
                'expired': expired, 'expires_at': expires_at.isoformat() if expires_at else None}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {}


def probe_upstream(row):
    result = {'state': 'offline', 'code': 'UNKNOWN', 'http_status': None,
              'redirect': '', 'error': '', 'message': '', 'suggestions': []}
    host, port = row['upstream_host'], int(row['upstream_port'])
    scheme = row['upstream_scheme']
    public_host = row.get('upstream_host_header') or row['domain']
    name = row.get('upstream_tls_name') or host

    if port == 9987 and scheme == 'http':
        result.update(state='misconfigured', code='UDP_AS_HTTP',
                      message='TeamSpeak-UDP-Port als HTTP-Proxy eingetragen',
                      suggestions=['Statt HTTP-Domain eine UDP-Stream-Regel auf 9987 erstellen.',
                                   'Router: UDP 9987 auf ProxyCircuit weiterleiten.'])
        return result
    if port == 5060 and scheme == 'http':
        result.update(state='misconfigured', code='SIP_AS_HTTP',
                      message='SIP-Port 5060 ist kein HTTP-Webdienst',
                      suggestions=['TCP/UDP-Stream oder SIP-spezifischen Proxy verwenden.'])
        return result
    if scheme == 'https' and port == 80:
        result['suggestions'].append('HTTPS auf Port 80 ist ungewoehnlich; HTTP am Ziel pruefen.')

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=3.0)
        sock.settimeout(3.0)
        if scheme == 'https':
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=name)
        # GET, not HEAD: many Proxmox & other applications return 501 for HEAD.
        request = ('GET / HTTP/1.1\r\nHost: ' + public_host + '\r\n'
                   'X-Forwarded-Proto: https\r\nConnection: close\r\n\r\n').encode('ascii')
        sock.sendall(request)
        line = b''
        while b'\n' not in line and len(line) < 2000:
            chunk = sock.recv(1)
            if not chunk:
                break
            line += chunk
        head = line.decode('ascii', 'replace').strip()
        if not head.startswith('HTTP/'):
            result.update(state='error', code='BAD_HTTP_RESPONSE',
                          message='Ziel hat keine gueltige HTTP-Antwort gesendet', error=head[:140],
                          suggestions=['Protokoll (HTTP/HTTPS) und Port des Zieldienstes pruefen.'])
            return result
        try:
            status = int(head.split()[1])
        except (ValueError, IndexError):
            status = 0
        result['http_status'] = status
        if status >= 500:
            result.update(state='error', code='BACKEND_HTTP_ERROR',
                          message=f'Zielserver antwortet selbst mit HTTP {status}',
                          suggestions=['Backend-Logs und gegebenenfalls weitere interne Upstreams pruefen.'])
        else:
            result.update(state='online', code='HTTP_OK', message=f'Backend erreichbar: HTTP {status}')
        return result
    except ssl.SSLCertVerificationError as exc:
        desc = str(exc)
        low = desc.lower()
        if 'expired' in low:
            code, msg = 'TLS_EXPIRED', 'Das HTTPS-Zielzertifikat ist abgelaufen.'
            tips = ['Zertifikat auf dem ZIELSERVER erneuern; HTTP-Proxy-Zertifikat reicht nicht.']
        elif 'hostname' in low or 'ip address mismatch' in low or 'not valid for' in low:
            code, msg = 'TLS_NAME_MISMATCH', 'Der TLS-Servername stimmt nicht mit dem Zielzertifikat ueberein.'
            tips = ['Den Zertifikats-DNS-Namen im Host-Feld „TLS-Servername“ eintragen.']
        else:
            code, msg = 'TLS_UNTRUSTED', 'Die ausstellende CA ist am Proxy nicht vertrauenswuerdig.'
            tips = ['CA des Zielservers auf ProxyCircuit vertrauenswuerdig installieren.',
                    'Abgelaufene oder selbstsignierte Zertifikate am Zielserver ersetzen.']
        result.update(state='tls_error', code=code, error=desc[:250], message=msg, suggestions=tips)
        info = certificate_info(host, port, name)
        result['certificate'] = info
        if info.get('expired'):
            result['code'] = 'TLS_EXPIRED'
            result['message'] = 'Das HTTPS-Zielzertifikat ist abgelaufen.'
            result['suggestions'] = ['Zertifikat auf dem Zielserver erneuern; auch die Vertrauenskette pruefen.']
        dns_names = info.get('dns_names') or []
        if dns_names and name.lower() not in [v.lower() for v in dns_names]:
            result['suggestions'].append('Im Zielzertifikat stehen DNS-Namen wie ' + dns_names[0] +
                                         '; SNI/TLS-Servernamen nur nach Zertifikatspruefung anpassen.')
        return result
    except ssl.SSLError as exc:
        message = str(exc)[:250]
        suggestions = ['Schema HTTP/HTTPS und Zielport abgleichen.',
                       'Bei „wrong version number“ wahrscheinlich HTTP statt HTTPS verwenden.']
        result.update(state='tls_error', code='TLS_HANDSHAKE', error=message,
                      message='TLS-Handshake fehlgeschlagen', suggestions=suggestions)
        return result
    except (TimeoutError, socket.timeout) as exc:
        result.update(state='offline', code='TIMEOUT', error=str(exc)[:180],
                      message='Zeitueberschreitung zum Zielserver',
                      suggestions=['Dienststatus, Firewall, IP-Adresse und Netzpfad pruefen.'])
        return result
    except OSError as exc:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            code, message = 'NO_ROUTE', 'Zielserver/Route nicht erreichbar'
            advice = ['ARP, Firewall, VLAN und Erreichbarkeit des Zielhosts pruefen.']
        elif exc.errno == errno.ECONNREFUSED:
            code, message = 'PORT_CLOSED', 'Zielserver lehnt die Verbindung ab'
            advice = ['Port und gestarteten Dienst auf dem Zielserver pruefen.']
        elif isinstance(exc, socket.gaierror):
            code, message = 'DNS_ERROR', 'DNS-Aufloesung des Upstreams fehlgeschlagen'
            advice = ['Interne DNS-Aufloesung und Hostname pruefen.']
        else:
            code, message = 'CONNECTION_ERROR', 'Netzwerkverbindung fehlgeschlagen'
            advice = ['Firewall, IP, Port und Dienststatus pruefen.']
        result.update(state='offline', code=code, error=str(exc)[:250],
                      message=message, suggestions=advice)
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass




def inspect_nginx_upstream(domain: str, path=NGINX_HTTP):
    """Read only the matching generated vhost; never return key files or unrelated sites."""
    result = {'readable': False, 'https_present': False, 'http_present': False,
              'proxy_pass': '', 'tls_name': '', 'tls_verification': '',
              'trusted_ca_path': '', 'matches_database_upstream': None}
    try:
        config = Path(path).read_text(encoding='utf-8')
    except OSError as exc:
        result['error'] = str(exc)[:160]
        return result
    result['readable'] = True
    marker = re.compile(r'^# (HTTPS|HTTP) host: ' + re.escape(domain) + r'$', re.M)
    marks = list(marker.finditer(config))
    for match in marks:
        result[match.group(1).lower() + '_present'] = True
    # Prefer the HTTPS block, because this is where browser-facing 502s occur.
    chosen = next((m for m in marks if m.group(1) == 'HTTPS'), marks[0] if marks else None)
    if chosen is None:
        return result
    block_end = re.search(r'^# (?:HTTPS|HTTP) host: ', config[chosen.end():], re.M)
    block = config[chosen.end():chosen.end()+block_end.start()] if block_end else config[chosen.end():]
    for name, regexp in (
        ('proxy_pass', r'^\s*proxy_pass\s+([^;]+);'),
        ('tls_name', r'^\s*proxy_ssl_name\s+([^;]+);'),
        ('tls_verification', r'^\s*proxy_ssl_verify\s+([^;]+);'),
        ('trusted_ca_path', r'^\s*proxy_ssl_trusted_certificate\s+([^;]+);'),
    ):
        found = re.search(regexp, block, re.M)
        result[name] = found.group(1).strip()[:240] if found else ''
    return result


def inspect_backend_without_trust(row, timeout=3):
    """Diagnostic-only HTTPS GET to inspect WHICH virtual host answers.

    Security: does NOT imply a successful TLS verification; credentials and cookies
    are NEVER sent, nor is the response body returned to the caller. Production
    proxy verification is not changed.
    """
    result = {'reachable': False, 'http_status': None, 'redirect': '',
              'page_title': '', 'warning': 'Diagnose OHNE TLS-Vertrauenspruefung; nicht fuer produktive Verbindungen.'}
    if row.get('upstream_scheme') != 'https':
        return result
    host = row['upstream_host']; port = int(row['upstream_port'])
    tls_name = row.get('upstream_tls_name') or host
    public_host = row.get('upstream_host_header') or row['domain']
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(raw, server_hostname=tls_name) as tls:
                # GET /, no cookies and no follow redirects, maximum 16KB.
                request = ('GET / HTTP/1.1\r\nHost: ' + public_host +
                           '\r\nUser-Agent: ProxyCircuit-Diagnose/0.2.2\r\n'
                           'Accept: text/html\r\nConnection: close\r\n\r\n')
                tls.sendall(request.encode('ascii'))
                data = b''
                while len(data) < 16384:
                    chunk = tls.recv(min(4096, 16384-len(data)))
                    if not chunk:
                        break
                    data += chunk
                    if b'\r\n\r\n' in data and (b'</title>' in data.lower() or len(data)>8192):
                        break
        headers, _, body = data.partition(b'\r\n\r\n')
        first = headers.split(b'\r\n',1)[0].decode('latin-1','replace')
        if not first.startswith('HTTP/'):
            result['error'] = 'Keine gueltige HTTP-Antwort'
            return result
        result['reachable'] = True
        try:
            result['http_status'] = int(first.split()[1])
        except (IndexError, ValueError):
            pass
        for line in headers.decode('latin-1','replace').split('\r\n')[1:]:
            if line.lower().startswith('location:'):
                result['redirect'] = line.split(':',1)[1].strip()[:200]
                break
        title = re.search(rb'<title[^>]*>(.*?)</title>', body, re.I|re.S)
        if title:
            result['page_title'] = html.unescape(re.sub(r'\s+', ' ', title.group(1).decode('utf-8','replace')).strip())[:120]
        return result
    except (OSError, ssl.SSLError) as exc:
        result['error'] = str(exc)[:200]
        return result


def probe_https_local(domain):
    result = {'state': 'error', 'http_status': None, 'error': ''}
    try:
        context = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1', 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                tls.settimeout(3)
                req = ('GET / HTTP/1.1\r\nHost: ' + domain + '\r\nConnection: close\r\n\r\n').encode('ascii')
                tls.sendall(req)
                first = tls.recv(512).split(b'\r\n', 1)[0].decode('ascii','replace')
                if first.startswith('HTTP/'):
                    result['state'] = 'responding'
                    try:
                        result['http_status'] = int(first.split()[1])
                    except (ValueError, IndexError):
                        pass
                else:
                    result['error'] = 'Keine gueltige HTTP-Antwort erhalten'
    except (OSError, ssl.SSLError) as exc:
        result['error'] = str(exc)[:260]
    return result


def diagnose_route(row):
    host = HostInput(**row)
    presence = config_presence(host.domain)
    dns = resolve_ipv4(host.domain)
    is_public = any(ipaddress.ip_address(ip).is_global for ip in dns['addresses'])
    upstream = probe_upstream(dict(row))
    active_config = inspect_nginx_upstream(host.domain)
    expected_url = f'{host.upstream_scheme}://{host.upstream_host}:{host.upstream_port}'
    active_config['matches_database_upstream'] = (active_config['proxy_pass'] == expected_url) if active_config['proxy_pass'] else None
    guidance = []
    if active_config['matches_database_upstream'] is False:
        guidance.append('Aktive Nginx-Konfiguration stimmt nicht mit dem gespeicherten Ziel ueberein. Deploy pruefen.')
    if host.upstream_scheme == 'https':
        if active_config['tls_verification'] != 'on' and active_config['https_present']:
            guidance.append('VORSICHT: TLS-Verifizierung ist nicht nachweislich aktiv.')
        configured_tls_name = host.upstream_tls_name or host.upstream_host
        if active_config['tls_name'] and active_config['tls_name'] != configured_tls_name:
            guidance.append('TLS-Name in Nginx und Datenbank stimmen nicht ueberein.')
        if not host.upstream_tls_name:
            guidance.append('TLS-Servername fehlt. Bei einem IP-Ziel ist der Zertifikats-DNS-Name ggf. abweichend.')
    if upstream.get('code','').startswith('TLS_'):
        upstream['unverified_backend'] = inspect_backend_without_trust(dict(row))
        if upstream['unverified_backend'].get('page_title'):
            guidance.append('HINWEIS: Unter dem aktuellen Backend-Host-Header erscheint die Seite: ' +
                            upstream['unverified_backend']['page_title'])
    tls = probe_https_local(host.domain) if presence['https'] else {'state': 'not-configured', 'http_status': None, 'error': ''}
    return {'domain': host.domain, 'configured_enabled': host.enabled,
            'configured_ssl': bool(host.certificate_id), 'nginx': presence,
            'applied_nginx_upstream': active_config, 'upstream': upstream,
            'recommendations': guidance, 'local_https': tls, 'dns': dns,
            'dns_points_to_public_ip': is_public, 'public_ingress': 'not_verified',
            'note': 'Kein WAN-Test. Unverifizierter HTTPS-Test liest nur HTTP-Status und Seitentitel; Proxy-TLS bleibt strikt aktiviert.'}
