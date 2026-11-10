# ProxyCircuit v0.2.2 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org | Copyright (c) 2026 Mohammad Zamir Akbari.
"""Strict configuration validation: user values must not become Nginx directives."""
import ipaddress
import re
from pydantic import BaseModel, Field, field_validator, model_validator

DNS_PART = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.I)
EMAIL = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$')

def clean_domain(value: str, *, wildcard=False) -> str:
    if not isinstance(value, str):
        raise ValueError('Domain muss Text sein')
    if any(c in value for c in ('\r', '\n', '\t')):
        raise ValueError('Domain enthält unzulässige Steuerzeichen')
    value = value.strip().lower().rstrip('.')
    if value.startswith('*.'):
        if not wildcard:
            raise ValueError('Wildcard-Domains in dieser Funktion nicht erlaubt')
        suffix = value[2:]
    else:
        suffix = value
    try:
        suffix = suffix.encode('idna').decode('ascii')
    except (UnicodeError, ValueError) as exc:
        raise ValueError('Domain ist nicht gültig') from exc
    if len(suffix) > 253 or '.' not in suffix or not all(DNS_PART.fullmatch(p) for p in suffix.split('.')):
        raise ValueError('Domain ist nicht gültig (z. B. app.example.de)')
    return ('*.' if value.startswith('*.') else '') + suffix

def clean_target(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError('Ziel muss Text sein')
    if any(c in value for c in ('\r', '\n', '\t')):
        raise ValueError('Ziel enthält unzulässige Steuerzeichen')
    value = value.strip().lower()
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not value or any(not DNS_PART.fullmatch(p) for p in value.split('.')):
        raise ValueError('Ziel muss eine IP-Adresse oder ein gültiger Hostname sein')
    return value

def nginx_target(target: str) -> str:
    target = clean_target(target)
    return f'[{target}]' if ':' in target else target

def cert_matches_domain(cert_domain: str, host_domain: str) -> bool:
    if cert_domain == host_domain:
        return True
    if cert_domain.startswith('*.'):
        suffix = cert_domain[2:]
        return host_domain.endswith('.' + suffix) and host_domain.count('.') == suffix.count('.') + 1
    return False

class HostInput(BaseModel):
    domain: str
    upstream_scheme: str = 'http'
    upstream_host: str
    upstream_port: int = Field(ge=1, le=65535)
    upstream_tls_name: str | None = None
    websocket: bool = True
    force_https: bool = False
    certificate_id: str | None = None
    category: str = Field(default='', max_length=70)
    upstream_host_header: str | None = None
    enabled: bool = True

    @field_validator('domain')
    @classmethod
    def domain_valid(cls, v):
        return clean_domain(v, wildcard=True)

    @field_validator('upstream_host')
    @classmethod
    def host_valid(cls, v):
        return clean_target(v)

    @field_validator('upstream_tls_name', mode='before')
    @classmethod
    def upstream_tls_name_valid(cls, v):
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        return clean_domain(v, wildcard=False)

    @field_validator('upstream_host_header', mode='before')
    @classmethod
    def upstream_host_header_valid(cls, v):
        if not v or (isinstance(v, str) and not v.strip()):
            return None
        return clean_target(v)

    @field_validator('category')
    @classmethod
    def category_valid(cls, v):
        v = v.strip()
        if any(ord(c) < 32 for c in v) or any(c in '<>\\/' for c in v):
            raise ValueError('Kategoriename enthaelt unzulaessige Zeichen')
        return v

    @field_validator('upstream_scheme')
    @classmethod
    def scheme_valid(cls, v):
        if v not in ('http', 'https'):
            raise ValueError('Nur http oder https erlaubt')
        return v

    @model_validator(mode='after')
    def forced_ssl_requires_cert(self):
        if self.upstream_tls_name and self.upstream_scheme != 'https':
            raise ValueError('TLS-Servername ist nur fuer HTTPS-Zielserver erlaubt')
        if self.force_https and not self.certificate_id:
            raise ValueError('HTTPS-Weiterleitung benötigt ein zugewiesenes Zertifikat')
        return self

class StreamInput(BaseModel):
    label: str = Field(min_length=1, max_length=70)
    protocol: str
    listen_port: int = Field(ge=1, le=65535)
    target_host: str
    target_port: int = Field(ge=1, le=65535)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    enabled: bool = True

    @field_validator('protocol')
    @classmethod
    def protocol_valid(cls, v):
        if v not in ('tcp', 'udp'):
            raise ValueError('TCP oder UDP auswählen')
        return v

    @field_validator('target_host')
    @classmethod
    def host_valid(cls, v):
        return clean_target(v)

    @field_validator('label')
    @classmethod
    def label_valid(cls, v):
        v = v.strip()
        if not v or any(ord(c) < 32 for c in v):
            raise ValueError('Ungültiger Anzeigename')
        return v

class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)

class CertIssueInput(BaseModel):
    domain: str
    email: str

    @field_validator('domain')
    @classmethod
    def domain_valid(cls, v):
        return clean_domain(v, wildcard=False)

    @field_validator('email')
    @classmethod
    def email_valid(cls, v):
        v = v.strip()
        if not EMAIL.fullmatch(v) or len(v) > 254:
            raise ValueError('Eine gültige Kontakt-E-Mail-Adresse eingeben')
        return v

class CertImportInput(BaseModel):
    label: str = Field(min_length=1, max_length=70)
    domain: str
    fullchain_pem: str = Field(min_length=100, max_length=200000)
    private_key_pem: str = Field(min_length=100, max_length=200000)

    @field_validator('domain')
    @classmethod
    def domain_valid(cls, v):
        return clean_domain(v, wildcard=True)

    @field_validator('label')
    @classmethod
    def label_valid(cls, v):
        return v.strip()
