#!/usr/bin/env bash
# Bring up the Phase 1 local cluster and print next steps.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example (edit ADMIN_PASSWORD if you like)."
fi

docker compose up -d

cat <<'EOF'

Containers starting — give them ~15s on first run.

Open the consoles (accept the self-signed cert warning if using https):
  node1 (PRIMARY):    http://127.0.0.1:5380    https://127.0.0.1:53443
  node2 (SECONDARY):  http://127.0.0.1:5381    https://127.0.0.1:53444
  login: admin / <ADMIN_PASSWORD from .env>

Next: README.md  ->  "Step 3 — Form the cluster".
EOF
