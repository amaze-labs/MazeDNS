#!/usr/bin/env bash
# Verify a zone replicated from primary (node1) to secondary (node2).
# Usage: ./scripts/verify.sh [zone]   (default: example.com)
set -euo pipefail
ZONE="${1:-example.com}"

command -v dig >/dev/null || { echo "dig not found. macOS: 'brew install bind'"; exit 1; }

echo "== SOA on PRIMARY (node1, port 5301) =="
dig @127.0.0.1 -p 5301 "$ZONE" SOA +short || true
echo
echo "== SOA on SECONDARY (node2, port 5302) =="
dig @127.0.0.1 -p 5302 "$ZONE" SOA +short || true
echo

s1=$(dig @127.0.0.1 -p 5301 "$ZONE" SOA +short | awk 'NR==1{print $3}')
s2=$(dig @127.0.0.1 -p 5302 "$ZONE" SOA +short | awk 'NR==1{print $3}')

if [ -n "${s1:-}" ] && [ "${s1:-}" = "${s2:-}" ]; then
  echo "✅ SOA serial matches on both nodes ($s1) — replication is working."
else
  echo "⚠️  SOA serial mismatch (primary='${s1:-<none>}' secondary='${s2:-<none>}')."
  echo "   If the secondary is empty, confirm the zone is a member of 'cluster-catalog'."
fi
echo
echo "== DNSSEC check (DNSKEY on secondary) =="
dig @127.0.0.1 -p 5302 "$ZONE" DNSKEY +dnssec +short || true
