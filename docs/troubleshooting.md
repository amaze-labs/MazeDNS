# Troubleshooting

Symptom → fix. Diagnostics use `docker`, `kubectl`, and `dig`. Replace
`mazedns-agent` / `mazedns-control-plane` with your container names (the fast-deploy
compose names them `mazedns-agent` and `mazedns-control-plane`).

- [An agent doesn't appear in the Cluster tab](#an-agent-doesnt-appear-in-the-cluster-tab)
- [The agent won't start / can't bind port 53](#the-agent-wont-start--cant-bind-port-53)
- [DNS doesn't resolve through the agent](#dns-doesnt-resolve-through-the-agent)
- [The dashboard shows only one client](#the-dashboard-shows-only-one-client)
- [High DNS latency on a busy host, even at low CPU](#high-dns-latency-on-a-busy-host-even-at-low-cpu)
- [~5-second latency spikes from Alpine/musl containers](#5-second-latency-spikes-from-alpinemusl-containers)
- [conntrack table exhaustion](#conntrack-table-exhaustion)
- [DNSSEC is slow or some sites break](#dnssec-is-slow-or-some-sites-break)
- [Is it the resolver, or the path to it?](#is-it-the-resolver-or-the-path-to-it)

---

## An agent doesn't appear in the Cluster tab

Check the agent's logs:

```bash
docker logs mazedns-agent --tail 50          # or: kubectl logs -n mazedns ds/dns-agent
```

Common causes:

- **Join token mismatch.** The agent's `MAZEDNS_JOIN_TOKEN` must equal the control
  plane's. The control plane must have `MAZEDNS_CLUSTER_ENABLED=true`.
- **Can't reach the control plane.** The logs show the CP hostname failing to
  resolve or connect. If the agent is the only DNS on its network it can't resolve
  the CP's FQDN — pin the IP with `MAZEDNS_CP_IP=<cp-ip>` (TLS still verifies the
  URL host). See [install.md](install.md#reaching-the-control-plane-from-an-agent).
- **Pending approval.** With `MAZEDNS_REQUIRE_APPROVAL=true`, the node is created
  *pending* — approve it in the Cluster tab before it serves.

## The agent won't start / can't bind port 53

The agent image binds `53` as a non-root user via a file capability, so this
normally just works. If the logs show a bind/permission error:

- **Port already in use on the host.** Another DNS service already owns `:53` — a
  host stub resolver (`resolved`), `dnsmasq`, or Pi-hole. Free it, or map a different
  host port (`-p 5353:53`) and point clients there.
- **Restrictive runtime.** If your platform strips default capabilities, either run
  with host networking (default caps include `NET_BIND_SERVICE`) or set
  `MAZEDNS_LISTEN_PORT` to an unprivileged port and remap.

Verify the container is up and what it bound:

```bash
docker ps --filter name=mazedns-agent          # is it running / restarting?
docker logs mazedns-agent --tail 20            # look for "listener up ... addr=:53"
```

## DNS doesn't resolve through the agent

Query the agent directly:

```bash
dig @<agent-host> example.com            # host-network / mapped :53
dig @<agent-host> -p 5353 example.com    # if you mapped a non-standard host port
dig @<agent-host> doubleclick.net        # should be blocked
```

- **No answer at all** → the port isn't reachable (firewall, wrong host port, or the
  agent isn't listening — see above).
- **Resolves but nothing is blocked** → the agent has no rules yet. Confirm it's
  enrolled (Cluster tab) and that blocklists/deny rules exist under the control plane.
  A brand-new deployment ships no default blocklist.
- **`SERVFAIL`** → the node may be in maintenance/drain, or all upstreams are failing.
  Check **Settings → Upstream resolvers** and the agent logs for `forward failed`.

## The dashboard shows only one client

Docker's NAT rewrites the source IP of queries that arrive through a published port
(`-p 53:53`), so every client looks like the Docker gateway. Run the agent with
**host networking** (Linux) to preserve real client IPs — see
[user-guide.md](user-guide.md#seeing-real-client-ips). Docker Desktop (macOS/Windows)
can't pass the original client IP through its VM.

## High DNS latency on a busy host, even at low CPU

**Symptom:** one host — typically one running many containers — has slow DNS while
CPU/RAM are low and a quick sequential `dig` looks fast. Slowness shows up only under
real, concurrent load.

**Cause:** the host's **UDP receive buffer is too small** (kernel default ~208 KB).
Many containers querying at once burst past it and the kernel **silently drops**
packets; clients retry, which appears as high tail latency. The tell-tale is a
growing `receive buffer errors` counter (check on the host):

```bash
watch -n1 'netstat -su | grep "receive buffer errors"'
```

**Fix — raise the host UDP buffers** (MazeDNS already requests an 8 MiB socket
buffer, but the kernel caps it at these limits):

```bash
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.rmem_default=4194304
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.netdev_max_backlog=4096

# persist across reboots:
printf 'net.core.rmem_max=16777216\nnet.core.rmem_default=4194304\nnet.core.wmem_max=16777216\nnet.core.netdev_max_backlog=4096\n' \
  | sudo tee /etc/sysctl.d/99-dns-udp.conf
sudo sysctl --system
```

The agent shares the host network namespace under `network_mode: host`, so these
host sysctls apply to it. The agent already spreads the UDP read loop across cores
by default (one `SO_REUSEPORT` socket per available CPU, capped at 8). If that
causes trouble on a given host — e.g. uneven load distribution or memory pressure
from the per-socket 8 MiB buffers — pin it with `MAZEDNS_UDP_LISTENERS` (set `1`
for a single socket, or an explicit count).

**Verify** the drops stop under a burst (run from a client host):

```bash
B=$(ssh host 'netstat -su' | awk '/receive buffer errors/{print $1}')
for i in $(seq 1 400); do dig @<agent-host> h$i-$RANDOM.example.com +tries=1 +time=2 >/dev/null 2>&1 & done; wait
A=$(ssh host 'netstat -su' | awk '/receive buffer errors/{print $1}')
echo "receive buffer errors delta: $((A-B))"   # want 0
```

## ~5-second latency spikes from Alpine/musl containers

**Symptom:** some lookups from containers take almost exactly ~5 s; most are fast.

**Cause:** musl libc (Alpine) sends the A and AAAA queries in parallel on one socket,
and a kernel UDP/conntrack DNAT race can drop one; the client then waits out its 5 s
timeout. Independent of MazeDNS.

**Fix (any one):**

- Add a resolver option to the *client* container:
  ```yaml
  dns_opt: ["single-request-reopen"]   # docker compose
  ```
  or `docker run --dns-option single-request-reopen`.
- Or force TCP from the client (`options use-vc` — MazeDNS handles TCP cleanly).
- Or disable AAAA lookups in apps that don't need IPv6.

## conntrack table exhaustion

**Symptom:** intermittent DNS (and other) failures on a container host; CPU low.

**Cause:** every UDP query creates a conntrack entry; a full table drops new packets.

```bash
# on the host:
dmesg | grep -i 'nf_conntrack: table full'
cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max
```

**Fix:**

```bash
sudo sysctl -w net.netfilter.nf_conntrack_max=524288
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=30
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=60
```

## DNSSEC is slow or some sites break

The resolver already caps the EDNS/UDP size at the fragmentation-safe 1232 bytes and
strips DNSSEC records for clients that didn't ask for them. If cache-cold signed
domains are still slow, prefer **DoT upstreams** — large/validated answers travel over
a pooled TLS connection, avoiding UDP fragmentation and per-query handshakes. Set them
in **Settings → Upstream resolvers**:

```
tls://1.1.1.1:853#cloudflare-dns.com
tls://9.9.9.9:853#dns.quad9.net
```

Verify validation from a client: `dig @<agent-host> dnssec-failed.org` must return
**SERVFAIL**.

## Is it the resolver, or the path to it?

MazeDNS records per-query processing time. Compare it against what clients feel:

- **Requests** tab → set the **Node** filter to the affected host → sort by `ms`.
- From a client: `dig @<agent-host> example.com` and read `Query time`.

If MazeDNS's `ms` is **low** but the client's query time is **high**, the problem is
the **path** (UDP buffers / conntrack / NAT) covered above — not the resolver.
