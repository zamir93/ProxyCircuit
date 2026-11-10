# ProxyCircuit v0.2.3-beta - Docker example (Debian 13)
# Author: Mohammad Zamir Akbari | https://zamir.akbari.org
# Copyright (c) 2026 Mohammad Zamir Akbari. All rights reserved.
FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/rpmgr \
    RPMGR_RUNTIME=docker

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl openssl tini nginx libnginx-mod-stream \
      certbot python3 python3-venv python3-pip iproute2 iputils-ping util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr \
    && mkdir -p /opt/rpmgr /var/lib/rpmgr /var/www/rpmgr-acme /var/www/rpmgr-fallback /etc/rpmgr \
    && rm -f /etc/nginx/sites-enabled/default \
    && printf '\n# ProxyCircuit TCP/UDP stream rules\ninclude /etc/nginx/rpmgr-stream.conf;\n' >> /etc/nginx/nginx.conf \
    && printf 'stream { }\n' > /etc/nginx/rpmgr-stream.conf \
    && printf '# ProxyCircuit initial HTTP configuration\n' > /etc/nginx/conf.d/rpmgr-managed.conf

COPY requirements.txt /opt/rpmgr/requirements.txt
RUN python3 -m venv /opt/rpmgr/venv \
    && /opt/rpmgr/venv/bin/python -m pip install --no-cache-dir -r /opt/rpmgr/requirements.txt \
    && /opt/rpmgr/venv/bin/python -c "import fastapi, uvicorn, paramiko, zeroconf, websockets; assert getattr(websockets, '__version__', None), 'websockets missing version'; from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol; print('ProxyCircuit Docker Python runtime OK')"

COPY app /opt/rpmgr/app
COPY plugins /opt/rpmgr/plugins
COPY docker/entrypoint.sh docker/apply_loop.py docker/renew-loop.sh /opt/rpmgr/docker/
RUN chmod 0755 /opt/rpmgr/docker/entrypoint.sh /opt/rpmgr/docker/renew-loop.sh \
    && chown -R root:root /opt/rpmgr \
    && chmod -R a+rX /opt/rpmgr/venv /opt/rpmgr/app /opt/rpmgr/plugins

VOLUME ["/var/lib/rpmgr", "/etc/rpmgr", "/etc/letsencrypt", "/var/www/rpmgr-acme", "/var/www/rpmgr-fallback"]
EXPOSE 80/tcp 443/tcp 9443/tcp

HEALTHCHECK --interval=30s --timeout=8s --start-period=45s --retries=3 \
  CMD curl --fail --silent --insecure --max-time 5 https://127.0.0.1:9443/api/version > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/rpmgr/docker/entrypoint.sh"]
