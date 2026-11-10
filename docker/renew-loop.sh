#!/usr/bin/env bash
# ProxyCircuit Docker background ACME renewal - Mohammad Zamir Akbari
set -Eeuo pipefail
# certbot renew only affects certificates that were already successfully issued.
while :; do
  sleep 43200
  echo '[ProxyCircuit] Scheduled certificate renewal check ...'
  certbot renew --quiet --deploy-hook 'nginx -t && nginx -s reload' || true
done
