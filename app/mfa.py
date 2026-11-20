# ProxyCircuit v0.2.6 Beta | Author: Mohammad Zamir Akbari | https://zamir.akbari.org
"""Optional RFC 6238 TOTP for administrators. Secrets never leave admin setup.

Uses 30-second SHA1 TOTP, 6 digits with +/-1 time-step tolerance,
constant-time comparison, and replay protection through last_counter.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def totp(secret, *, counter=None, now=None, digits=6):
    if counter is None:
        counter=int((time.time() if now is None else now)//30)
    raw=base64.b32decode(secret+'='*((8-len(secret)%8)%8),casefold=True)
    digest=hmac.new(raw,struct.pack('>Q',counter),hashlib.sha1).digest()
    offset=digest[-1]&15
    value=(struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%(10**digits)
    return str(value).zfill(digits)


def valid_counter(secret, code, *, now=None, last_counter=-1):
    if not isinstance(code,str) or len(code)!=6 or not code.isdigit():
        return None
    counter=int((time.time() if now is None else now)//30)
    matches=[]
    for candidate in (counter-1,counter,counter+1):
        if candidate>last_counter and hmac.compare_digest(totp(secret,counter=candidate),code):
            matches.append(candidate)
    return max(matches) if matches else None


def uri(username,secret):
    label=quote('ProxyCircuit:'+username,safe='')
    return f'otpauth://totp/{label}?secret={secret}&issuer=ProxyCircuit&algorithm=SHA1&digits=6&period=30'
