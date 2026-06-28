# Troubleshooting & host tuning

Operational issues that come from the **host/network around** MazeDNS rather than
MazeDNS itself, and the host settings that prevent them.

---

## High DNS latency on a busy host (many containers), even at low CPU

**Symptom:** one host — typically one running lots of containers — has slow DNS,
while CPU/RAM are low, conntrack has headroom, and a quick sequential `dig` to the
resolver looks fast. The slowness shows up under real, concurrent load.

**Cause:** the host's **UDP socket receive buffer is too small** (kernel default
is ~208 KB). Many containers querying at once burst past it and the kernel
**silently drops** the packets; clients then wait and retry, which appears as high
tail latency. A sequential probe never fills the buffer, so it looks healthy — the
tell-tale sign is a large, growing **`receive buffer errors`** counter:

```bash
netstat -su | grep -iE 'receive buffer errors|packet receive errors'
# watch it climb while the containers are busy:
watch -n1 'netstat -su | grep "receive buffer errors"'
```

### Fix — raise the host UDP buffers (suggested host config)

```bash
# apply now
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.rmem_default=4194304
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.netdev_max_backlog=4096

# persist across reboots
printf 'net.core.rmem_max=16777216\nnet.core.rmem_default=4194304\nnet.core.wmem_max=16777216\nnet.core.netdev_max_backlog=4096\n' \
  | sudo tee /etc/sysctl.d/99-dns-udp.conf
sudo sysctl --system   # reload
```

MazeDNS already **requests an 8 MiB** UDP socket buffer (`SO_RCVBUF`/`SO_SNDBUF`)
on its listener, but the kernel caps the effective size at `net.core.rmem_max` /
`wmem_max` — so the resolver only gets the big buffer **after** you raise those
limits above. If MazeDNS runs in a container, set the sysctls on the **host**
(they apply to the host network namespace the container shares, or run the
container with `--sysctl net.core.rmem_max=...` where supported).

### Verify

```bash
B=$(netstat -su | awk '/receive buffer errors/{print $1}')
for i in $(seq 1 400); do dig @<resolver-ip> h$i-$RANDOM.example.com +tries=1 +time=2 >/dev/null 2>&1 & done; wait
A=$(netstat -su | awk '/receive buffer errors/{print $1}')
echo "receive buffer errors delta during burst: $((A-B))"   # want 0
```

---

## ~5-second latency spikes from Alpine/musl containers

**Symptom:** some lookups from containers take almost exactly ~5 s; most are fast.

**Cause:** musl libc (Alpine images) sends the A and AAAA queries **in parallel on
one socket**, and a kernel UDP/conntrack DNAT race can drop one of them; the
client then waits out its 5 s timeout before retrying. It is independent of
MazeDNS.

**Fix (any one):**

- Add to the container's `/etc/resolv.conf`:
  ```
  options single-request-reopen
  ```
  (or `single-request`). In Docker this can be set per-container with
  `--dns-option single-request-reopen`, or in `docker-compose`:
  ```yaml
  dns_opt: ["single-request-reopen"]
  ```
- Or force TCP from the client: `options use-vc` (MazeDNS handles TCP cleanly).
- Or disable AAAA lookups in apps that don't need IPv6.

---

## conntrack table exhaustion

**Symptom:** intermittent DNS (and other) failures on a container host; CPU low.

**Cause:** every UDP query creates a conntrack entry; a full table drops new
packets.

**Check:**

```bash
dmesg | grep -i 'nf_conntrack: table full'
cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max
conntrack -S 2>/dev/null | grep -E 'drop|insert_failed|early_drop'
```

**Fix:**

```bash
sudo sysctl -w net.netfilter.nf_conntrack_max=524288
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=30
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=60
```

---

## DNSSEC was slow / some sites broke

Fixed in the resolver (EDNS buffer capped at the fragmentation-safe 1232 bytes,
UDP replies capped there too, DNSSEC records stripped for clients that didn't
request them). If you still see latency on cache-cold signed domains, prefer
**DoT upstreams** — they carry large/validated answers over a pooled TLS
connection, avoiding UDP fragmentation and per-query handshakes:

```
tls://1.1.1.1:853#cloudflare-dns.com
tls://9.9.9.9:853#dns.quad9.net
```

Set them in **Settings → Upstream resolvers** (quick-fill buttons provided).
Verify DNSSEC is validating: `nslookup dnssec-failed.org` must return **SERVFAIL**.

---

## Is it the resolver, or the path to it?

MazeDNS records per-query processing time. Compare it against what clients feel:

- **Requests** tab → set the **Node** filter to the affected host → sort by `ms`.
- From a client: `dig @<resolver-ip> example.com` and read `Query time`.

If MazeDNS's `ms` is **low** but the client's query time is **high**, the problem
is the **path** (UDP buffers / conntrack / NAT) covered above — not the resolver.

### Diagnostic script

`dev/dns-latency-debug.sh` runs all of the above read-only checks (conntrack, UDP
buffer drops, latency probe incl. the 5 s pattern) and prints a verdict. Run it on
the host, and inside an affected container for the musl race.
