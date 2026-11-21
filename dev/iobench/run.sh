#!/bin/sh
# Disk-write benchmark: how many bytes each MazeDNS process writes to disk for
# a config apply, while idle, and per DNS query under a steady load. Reads
# write_bytes from /proc/<pid>/io (the bytes the process sent to the block
# layer), the same counter used to measure a production host.
#
#   dev/iobench/run.sh                       # defaults below
#   QPS=60 LOAD_SECS=300 dev/iobench/run.sh  # override any knob
#   KEEP=1 dev/iobench/run.sh                # leave the cluster running
#
# Needs Docker and Go. Builds the images from this checkout, so run it once on
# the base commit and once on the change to compare.
set -eu

QPS=${QPS:-6}                 # steady load on resolver-a (resolver-b stays idle)
CLIENTS=${CLIENTS:-4}         # load generators (distinct client IPs), sharing QPS
LOAD_SECS=${LOAD_SECS:-180}
IDLE_SECS=${IDLE_SECS:-120}
SETTLE_SECS=${SETTLE_SECS:-155} # after the load: one query-log ship interval + a sync
RULES=${RULES:-369000}        # replicated rules
CP_URL=http://127.0.0.1:18080

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
dc() { docker compose -f "$here/compose.yml" "$@"; }
net=mazedns-iobench_default
cp=mazedns-iobench-control-plane-1
ra=mazedns-iobench-resolver-a-1
rb=mazedns-iobench-resolver-b-1

cleanup() {
	docker rm -f $(docker ps -aq --filter label=mazedns-iobench-load) >/dev/null 2>&1 || true
	[ "${KEEP:-0}" = 1 ] || dc down -v >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# wb CONTAINER: write_bytes of the container's main process.
wb() { docker run --rm --pid="container:$1" --cap-add SYS_PTRACE alpine:3.20 awk '/^write_bytes/{print $2}' /proc/1/io; }
# queries HOST: the resolver's total query counter.
queries() {
	docker run --rm --network "$net" alpine:3.20 wget -qO- "http://$1:8080/metrics" |
		awk '/^mazedns_queries_total/{s+=$2} END{printf "%d", s}'
}
# logged CONTAINER MSG: how many times the container logged msg="MSG".
logged() { docker logs "$1" 2>&1 | grep -c "msg=\"$2\"" || true; }
wait_logged() { # CONTAINER MSG COUNT
	i=0
	while [ "$(logged "$1" "$2")" -lt "$3" ]; do
		i=$((i + 1)); [ $i -gt 120 ] && { echo "timeout waiting for $1: $2" >&2; exit 1; }
		sleep 2
	done
}
synced() { logged "$1" "cluster synced"; }
wait_synced() { wait_logged "$1" "cluster synced" "$2"; }
api() { curl -sf -b "$tmp/jar" -c "$tmp/jar" -H 'Content-Type: application/json' "$@"; }
kib() { echo $(($1 / 1024)); }

echo "== building and starting the benchmark cluster"
dc down -v >/dev/null 2>&1 || true
dc up -d --build >/dev/null
until curl -sf "$CP_URL/healthz" >/dev/null; do sleep 1; done
api -X POST "$CP_URL/api/setup/complete" -d '{"username":"admin","password":"iobench-password-1"}' >/dev/null
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$(docker info --format '{{.Architecture}}' | sed 's/x86_64/amd64/;s/aarch64/arm64/')" go build -o "$tmp/load" ./dev/iobench/load)
echo "   waiting for both resolvers to enroll and sync"
wait_logged "$ra" "cluster sync started" 1
wait_logged "$rb" "cluster sync started" 1

echo "== scenario 1: replicate $RULES rules (first full apply)"
awk -v n="$RULES" 'BEGIN{printf "{\"name\":\"bench\",\"category\":\"ads\",\"text\":\""; for(i=0;i<n;i++) printf "0.0.0.0 blocked%d.bench.test\\n", i; printf "\"}"}' >"$tmp/list.json"
b0=$(wb "$rb"); s0=$(synced "$rb")
api -X POST "$CP_URL/api/lists/import" --data-binary "@$tmp/list.json" >/dev/null
wait_synced "$rb" $((s0 + 1)); sleep 5
full=$(($(wb "$rb") - b0))
wait_synced "$ra" 1

echo "== scenario 2: one rule added (incremental apply)"
b0=$(wb "$rb"); s0=$(synced "$rb")
api -X POST "$CP_URL/api/rules" -d '{"action":"deny","domain":"one-more.bench.test","category":"custom"}' >/dev/null
wait_synced "$rb" $((s0 + 1)); sleep 5
one=$(($(wb "$rb") - b0))

echo "== scenario 3: idle for ${IDLE_SECS}s"
sleep 35 # let the previous writes settle (one sync cycle)
ia0=$(wb "$ra"); ib0=$(wb "$rb"); ic0=$(wb "$cp")
sleep "$IDLE_SECS"
idle_a=$(($(wb "$ra") - ia0)); idle_b=$(($(wb "$rb") - ib0)); idle_cp=$(($(wb "$cp") - ic0))

echo "== scenario 4: $QPS queries/s on resolver-a from $CLIENTS clients for ${LOAD_SECS}s"
per=$(awk -v q="$QPS" -v c="$CLIENTS" 'BEGIN{printf "%.3f", q/c}')
la0=$(wb "$ra"); lc0=$(wb "$cp"); q0=$(queries resolver-a)
i=0
while [ $i -lt "$CLIENTS" ]; do
	docker run -d --label mazedns-iobench-load --network "$net" -v "$tmp/load:/load:ro" alpine:3.20 \
		/load -server resolver-a:53 -qps "$per" -duration "${LOAD_SECS}s" >/dev/null
	i=$((i + 1))
done
sleep "$LOAD_SECS"
# Let the last queries reach the control plane's database: resolvers ship
# every 30s sync and the control plane writes what they shipped every 2
# minutes (each 30s sync on older builds).
sleep "$SETTLE_SECS"
load_a=$(($(wb "$ra") - la0)); load_cp=$(($(wb "$cp") - lc0)); nq=$(($(queries resolver-a) - q0))
span=$((LOAD_SECS + SETTLE_SECS))
# Net of the idle baseline over the same span.
net_a=$((load_a - idle_a * span / IDLE_SECS)); net_cp=$((load_cp - idle_cp * span / IDLE_SECS))

echo
echo "== results (bytes written, from /proc/<pid>/io write_bytes)"
printf '%-44s %12s\n' "full apply of $RULES rules (resolver)" "$(kib $full) KiB"
printf '%-44s %12s\n' "apply of a one-rule change (resolver)" "$(kib $one) KiB"
printf '%-44s %12s\n' "idle resolver, per day" "$(awk -v b="$idle_b" -v s="$IDLE_SECS" 'BEGIN{printf "%.1f MiB", b*86400/s/1048576}')"
printf '%-44s %12s\n' "idle control plane, per day" "$(awk -v b="$idle_cp" -v s="$IDLE_SECS" 'BEGIN{printf "%.1f MiB", b*86400/s/1048576}')"
printf '%-44s %12s\n' "queries sent to resolver-a" "$nq"
[ "$nq" -gt 0 ] && {
	printf '%-44s %12s\n' "resolver, bytes per query (net of idle)" "$((net_a / nq))"
	printf '%-44s %12s\n' "control plane, bytes per query (net of idle)" "$((net_cp / nq))"
	printf '%-44s %12s\n' "resolver at this load, per day" "$(awk -v b="$load_a" -v s="$span" 'BEGIN{printf "%.1f MiB", b*86400/s/1048576}')"
	printf '%-44s %12s\n' "control plane at this load, per day" "$(awk -v b="$load_cp" -v s="$span" 'BEGIN{printf "%.1f MiB", b*86400/s/1048576}')"
}
