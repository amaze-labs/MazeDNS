# Phase 1 — Local 2-node Technitium cluster (proof of concept)

Goal: see the whole master/agent model work on your laptop before touching
multi-site or k3s. You will:

1. start two Technitium nodes,
2. form a cluster (node1 = primary/master, node2 = secondary/agent),
3. create and DNSSEC-sign a zone on the primary,
4. replicate it to the secondary via the cluster catalog,
5. verify with `dig`,
6. kill the primary and confirm the secondary still serves (then promote it).

Both nodes run on one Docker bridge network with **static IPs** (172.28.0.10 /
.11) because clustering requires stable addresses. HTTPS is enabled with a
self-signed cert because the cluster channel uses DANE-EE TLS.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose version`)
- `dig` (macOS: `brew install bind`)

## Port map (host → container)

| Node  | Role      | Web HTTP                | Web HTTPS                  | DNS         |
|-------|-----------|-------------------------|----------------------------|-------------|
| node1 | primary   | http://127.0.0.1:5380   | https://127.0.0.1:53443    | `-p 5301`   |
| node2 | secondary | http://127.0.0.1:5381   | https://127.0.0.1:53444    | `-p 5302`   |

Inside the Docker network the nodes reach each other at their static IPs on the
standard ports, so the cluster **join URL** is `https://172.28.0.10:53443`.

## Step 1 — Start the nodes

```bash
./scripts/up.sh
```

This copies `.env.example` → `.env` (edit `ADMIN_PASSWORD` if you like) and runs
`docker compose up -d`. Give it ~15s on first run while the image pulls.

## Step 2 — Log in

Open **node1** at http://127.0.0.1:5380 and log in as `admin` / the
`ADMIN_PASSWORD` from `.env` (default `changeme-local-only`). Do the same for
**node2** at http://127.0.0.1:5381. (The `https://…:53443/53444` URLs also work;
accept the self-signed cert warning.)

## Step 3 — Form the cluster

**On node1 (the master):**
1. `Administration` → `Cluster` → `Initialize` → **New Cluster**.
2. Cluster domain: `dns.example.com` (matches `CLUSTER_DOMAIN`; can be private).
3. Primary node IP: `172.28.0.10`.
4. Confirm. node1 is now the cluster primary.

**On node2 (the agent):**
1. `Administration` → `Cluster` → **Join Cluster**.
2. This node's IP: `172.28.0.11`.
3. Primary web service URL: `https://172.28.0.10:53443`.
4. Admin username/password of node1.
5. If prompted about the certificate, allow / disable validation (self-signed).
6. Join. Initial config sync runs (a few seconds).

node2 now appears as a secondary in node1's Cluster view, and node1's
settings/users mirror onto node2.

## Step 4 — Create and sign a zone (on the primary)

On **node1**:
1. `Zones` → `Add Zone` → **Primary Zone**, name `example.com` → Add.
2. Add a record: type `A`, name `www`, value `203.0.113.10` → Save.
3. Sign it: open the zone → **DNSSEC** → **Sign Zone** → algorithm
   `ECDSA P-256 (ECDSAP256SHA256)`, online signing → Sign. DNSKEY/RRSIG appear.

> All config happens on the primary — that's the master/agent rule.

## Step 5 — Replicate it to the agent

Add the zone to the **cluster catalog** so secondaries auto-create it:

1. On node1, open the `example.com` zone → **Options** (zone settings).
2. Find the catalog setting and make the zone a **member of `cluster-catalog`**.
3. Save.

Within a few seconds node2's `Zones` list shows `example.com` as a secondary
(catalog) zone — **including the DNSSEC keys**, so node2 can be promoted later.

## Step 6 — Verify replication

```bash
./scripts/verify.sh example.com
```

Expected: identical SOA serials on both nodes and a DNSKEY on the secondary.
Manual equivalent:

```bash
dig @127.0.0.1 -p 5301 www.example.com A +short     # primary
dig @127.0.0.1 -p 5302 www.example.com A +short     # secondary  → same answer
dig @127.0.0.1 -p 5302 example.com DNSKEY +dnssec   # secondary has the keys
```

## Step 7 — Failover test

```bash
./scripts/failover-test.sh example.com
```

It stops node1 and queries node2 — which keeps answering from its own copy.
That's the HA property. To make node2 the real primary:

- node2 console (https://127.0.0.1:53444) → `Administration` → `Cluster` →
  **Promote To Primary**.

Bring the old primary back when ready: `docker compose start node1`.

## Cleanup

```bash
docker compose down       # stop, keep data (volumes)
docker compose down -v    # wipe everything (fresh start)
```

## Troubleshooting

- **Image won't pull / tag not found:** ensure `TECHNITIUM_TAG=latest` in `.env`.
- **Join fails on the certificate:** use `https://172.28.0.10:53443` and
  allow/disable cert validation (it's self-signed by design).
- **Secondary zone empty after Step 5:** confirm the zone is a member of
  `cluster-catalog`, wait a few seconds, re-run `verify.sh`.
- **`dig` not found:** `brew install bind` (macOS).
- **Port already in use:** something else holds 5380/53/etc. — adjust the host
  ports in `docker-compose.yml`.

## What you just proved

The master/agent (primary/secondary) model, automatic config + zone + DNSSEC-key
replication, and survive-the-master-dying failover — the core of the whole
system. Next: **Phase 2** hardens the authoritative tier. See
[`../../docs/roadmap.md`](../../docs/roadmap.md).
