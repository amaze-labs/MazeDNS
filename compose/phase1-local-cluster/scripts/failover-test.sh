#!/usr/bin/env bash
# Simulate primary failure: stop node1, confirm node2 still answers.
# Usage: ./scripts/failover-test.sh [zone]   (default: example.com)
set -euo pipefail
ZONE="${1:-example.com}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

echo "Stopping PRIMARY (node1)..."
docker compose stop node1
sleep 2
echo
echo "Querying SECONDARY (node2, port 5302) with the primary DOWN:"
dig @127.0.0.1 -p 5302 "$ZONE" SOA +short || true
echo
echo "If you still got an answer, HA works: the secondary serves from its own copy."
echo
echo "To make node2 the new primary (true failover):"
echo "  https://127.0.0.1:53444  ->  Administration > Cluster > Promote To Primary"
echo
echo "Bring the old primary back later with:  docker compose start node1"
