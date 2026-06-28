#!/usr/bin/env bash
# dns-latency-debug.sh — read-only DNS latency diagnostics for a container host.
# Pinpoints the usual "many containers, low CPU, slow DNS" causes: conntrack
# table exhaustion, the musl A+AAAA 5s conntrack race, and UDP buffer drops.
#
# Usage:  ./dns-latency-debug.sh [resolver_ip] [count] [domain]
#   resolver_ip  DNS server to test (default: first nameserver in resolv.conf)
#   count        number of probe queries (default: 30)
#   domain       name to resolve (default: example.com)
#
# Run it on the affected host. To catch the musl/Alpine 5s race, also run it
# INSIDE one of the affected containers. Makes NO changes (only suggests fixes).
# See docs/troubleshooting.md for the matching fixes.

set -u
RES="${1:-}"
COUNT="${2:-30}"
DOMAIN="${3:-example.com}"

sec() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '   %s\n' "$*"; }
warn() { printf '   \033[33m! %s\033[0m\n' "$*"; }
bad()  { printf '   \033[31mX %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok %s\033[0m\n' "$*"; }

# Resolve which server to probe.
if [ -z "$RES" ]; then
  RES=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)
fi
[ -z "$RES" ] && RES="127.0.0.1"

VERDICT=()

sec "Environment"
note "host: $(hostname 2>/dev/null)   kernel: $(uname -r 2>/dev/null)"
note "probing resolver: $RES   domain: $DOMAIN   queries: $COUNT"
note "resolv.conf options: $(awk '/^options/{$1="";print}' /etc/resolv.conf 2>/dev/null | xargs) ${NONE:-}"
if grep -q 'single-request' /etc/resolv.conf 2>/dev/null; then
  ok "single-request* is set (mitigates the musl A+AAAA race)"
else
  note "single-request-reopen NOT set (relevant only for musl/Alpine containers)"
fi

# ----------------------------------------------------------------------------
sec "conntrack (the #1 cause on container hosts)"
CT_DIR=/proc/sys/net/netfilter
if [ -r "$CT_DIR/nf_conntrack_count" ]; then
  CNT=$(cat "$CT_DIR/nf_conntrack_count" 2>/dev/null)
  MAX=$(cat "$CT_DIR/nf_conntrack_max" 2>/dev/null)
  PCT=$(( MAX > 0 ? CNT * 100 / MAX : 0 ))
  note "entries: $CNT / $MAX  (${PCT}% full)"
  note "udp timeout: $(cat $CT_DIR/nf_conntrack_udp_timeout 2>/dev/null)s   udp stream timeout: $(cat $CT_DIR/nf_conntrack_udp_timeout_stream 2>/dev/null)s"
  if [ "$PCT" -ge 80 ]; then
    bad "conntrack table is ${PCT}% full — packets (incl. DNS) get dropped here"
    VERDICT+=("conntrack table near full: raise net.netfilter.nf_conntrack_max and lower nf_conntrack_udp_timeout(_stream)")
  else
    ok "conntrack table has headroom"
  fi
else
  note "nf_conntrack sysctls not readable (run as root, or conntrack not loaded)"
fi
if have conntrack; then
  S=$(conntrack -S 2>/dev/null)
  DROPS=$(printf '%s' "$S" | grep -oE '(drop|insert_failed|early_drop)=[0-9]+' | awk -F= '{s+=$2} END{print s+0}')
  note "conntrack -S drop/insert_failed/early_drop total: $DROPS"
  [ "${DROPS:-0}" -gt 0 ] && { warn "non-zero conntrack drops — table pressure or races"; VERDICT+=("conntrack reports drops/insert_failed ($DROPS)"); }
else
  note "'conntrack' tool not installed (apt/apk add conntrack[-tools] for -S stats)"
fi
DMESG=$(dmesg 2>/dev/null | grep -i 'nf_conntrack: table full' | tail -3)
if [ -n "$DMESG" ]; then
  bad "kernel log shows conntrack table-full drops:"
  printf '     %s\n' "$DMESG"
  VERDICT+=("dmesg: 'nf_conntrack: table full, dropping packet' — definitive conntrack exhaustion")
fi

# ----------------------------------------------------------------------------
sec "UDP receive-buffer drops"
UDP_BEFORE=$(cat /proc/net/snmp 2>/dev/null | awk '/^Udp:/{getline; print}')
RBE_BEFORE=$(printf '%s' "$UDP_BEFORE" | awk '{print $NF}')  # last col ~ RcvbufErrors (kernel-dependent)
note "net.core.rmem_max: $(cat /proc/sys/net/core/rmem_max 2>/dev/null)   rmem_default: $(cat /proc/sys/net/core/rmem_default 2>/dev/null)"
if have netstat; then
  netstat -su 2>/dev/null | grep -iE 'receive buffer errors|packet receive errors|InErrors' | sed 's/^/   /'
fi

# ----------------------------------------------------------------------------
sec "Latency probe ($COUNT queries to $RES)"
# Pick a query tool.
QTOOL=""
if have dig; then QTOOL=dig
elif have drill; then QTOOL=drill
elif have nslookup; then QTOOL=nslookup
fi
if [ -z "$QTOOL" ]; then
  warn "no dig/drill/nslookup found — skipping latency probe (apt/apk add bind-tools / dnsutils)"
else
  note "using: $QTOOL  (+time=5 +tries=2 so a single dropped packet shows as a ~5s spike)"
  slow=0; race=0; fail=0; total=0; min=99999; max=0; sum=0
  for i in $(seq 1 "$COUNT"); do
    t0=$(date +%s.%N)
    case "$QTOOL" in
      dig)      out=$(dig +time=5 +tries=2 +noall +stats "@$RES" "$DOMAIN" A 2>/dev/null); rc=$? ;;
      drill)    out=$(drill -Q "@$RES" "$DOMAIN" A 2>/dev/null); rc=$? ;;
      nslookup) out=$(nslookup -timeout=5 "$DOMAIN" "$RES" 2>/dev/null); rc=$? ;;
    esac
    t1=$(date +%s.%N)
    el=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", b-a}')
    total=$((total+1))
    [ "$rc" -ne 0 ] && fail=$((fail+1))
    awk -v e="$el" 'BEGIN{exit !(e>1.0)}'  && slow=$((slow+1))
    awk -v e="$el" 'BEGIN{exit !(e>4.5 && e<6.5)}' && race=$((race+1))
    sum=$(awk -v s="$sum" -v e="$el" 'BEGIN{printf "%.3f", s+e}')
    awk -v e="$el" -v m="$min" 'BEGIN{exit !(e<m)}' && min=$el
    awk -v e="$el" -v m="$max" 'BEGIN{exit !(e>m)}' && max=$el
  done
  avg=$(awk -v s="$sum" -v n="$total" 'BEGIN{printf "%.3f", (n>0)?s/n:0}')
  note "min=${min}s  avg=${avg}s  max=${max}s   failures=${fail}/${total}"
  note "slow (>1s): $slow/${total}    ~5s spikes (4.5-6.5s): $race/${total}"
  if [ "$race" -gt 0 ]; then
    bad "~5s spikes detected — classic UDP conntrack DROP (lost packet -> client retry timeout)"
    VERDICT+=("~5s latency spikes: UDP conntrack race/drop. On musl/Alpine add 'options single-request-reopen'; fix conntrack sizing; consider 'use-vc' (TCP).")
  elif [ "$slow" -gt 0 ]; then
    warn "some queries >1s but not the 5s pattern — check upstream RTT and buffers"
  else
    ok "latency looks healthy from this vantage point"
  fi
fi

# Re-read UDP errors to compute deltas during the probe.
UDP_AFTER=$(cat /proc/net/snmp 2>/dev/null | awk '/^Udp:/{getline; print}')
RBE_AFTER=$(printf '%s' "$UDP_AFTER" | awk '{print $NF}')
if [ -n "${RBE_BEFORE:-}" ] && [ -n "${RBE_AFTER:-}" ] && [ "$RBE_AFTER" -gt "$RBE_BEFORE" ] 2>/dev/null; then
  bad "UDP error counter rose by $((RBE_AFTER-RBE_BEFORE)) during the probe (buffer drops)"
  VERDICT+=("UDP receive errors increased during probe: raise net.core.rmem_max / rmem_default")
fi

# ----------------------------------------------------------------------------
sec "Top conntrack talkers (if available, may need root)"
if have conntrack; then
  conntrack -L 2>/dev/null | grep -c udp | sed 's/^/   udp conntrack entries: /'
  conntrack -L -p udp --dport 53 2>/dev/null | wc -l | sed 's/^/   udp:53 conntrack entries: /'
else
  note "(install conntrack-tools for a breakdown)"
fi

# ----------------------------------------------------------------------------
sec "VERDICT"
if [ "${#VERDICT[@]}" -eq 0 ]; then
  ok "No smoking gun from this host. If containers still feel slow:"
  note "- run this script INSIDE an affected container (musl race only shows there)"
  note "- compare MazeDNS's own per-query 'ms' (Requests tab -> Node filter) vs the latency above:"
  note "    low ms there + high here  => path problem (conntrack/buffers/NAT), not the resolver"
else
  printf '   Likely cause(s):\n'
  for v in "${VERDICT[@]}"; do printf '   \033[31m->\033[0m %s\n' "$v"; done
  cat <<'EOF'

   Suggested sysctl (test, then persist in /etc/sysctl.d/99-dns-udp.conf):
     net.core.rmem_max=16777216
     net.core.rmem_default=4194304
     net.core.wmem_max=16777216
     net.core.netdev_max_backlog=4096
     net.netfilter.nf_conntrack_max=524288
     net.netfilter.nf_conntrack_udp_timeout=30
     net.netfilter.nf_conntrack_udp_timeout_stream=60
   Apply now (root):  sudo sysctl -w net.core.rmem_max=16777216 ; etc.
   For musl/Alpine containers also add to their /etc/resolv.conf:
     options single-request-reopen
   Full guide: docs/troubleshooting.md
EOF
fi
echo
