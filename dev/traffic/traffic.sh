#!/bin/sh
# DNS traffic generator for the dev cluster.
#   TARGET   resolver host to query        (default: mazedns)
#   PORT     resolver port                 (default: 5300)
#   SLEEP    seconds between queries       (default: 3)
#   DOMAINS  space-separated domain list   (default: a mixed allow/block set)
set -u

TARGET="${TARGET:-mazedns}"
PORT="${PORT:-5300}"
SLEEP="${SLEEP:-3}"
# A mix of normal lookups and domains blocked by the sample blocklist
# (doubleclick.net, googleadservices.com, ads.example.com, tracking.example.org).
DOMAINS="${DOMAINS:-google.com github.com wikipedia.org cloudflare.com amazon.com \
netflix.com reddit.com apple.com microsoft.com example.com \
doubleclick.net googleadservices.com ads.example.com tracking.example.org}"

echo "traffic: querying ${TARGET}:${PORT} every ${SLEEP}s"
i=0
while true; do
  for d in $DOMAINS; do
    i=$((i + 1))
    dig +tries=1 +time=2 "@${TARGET}" -p "${PORT}" "$d" A >/dev/null 2>&1
    # Sprinkle in AAAA / HTTPS lookups for query-type variety.
    [ $((i % 3)) -eq 0 ] && dig +tries=1 +time=2 "@${TARGET}" -p "${PORT}" "$d" AAAA  >/dev/null 2>&1
    [ $((i % 5)) -eq 0 ] && dig +tries=1 +time=2 "@${TARGET}" -p "${PORT}" "$d" HTTPS >/dev/null 2>&1
    sleep "${SLEEP}"
  done
done
