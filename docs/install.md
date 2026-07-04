# Install

MazeDNS ships as **two containers**:

- **control-plane** — web UI, API, auth, classifier, cluster coordination. Holds
  the config and dashboard and **does not answer DNS**. Run **one**.
- **dns-agent** — a resolver node. Serves DNS, replicates its filtering config from
  the control plane, exposes only `/healthz` + `/metrics`. Run **one or more**,
  wherever you want to serve DNS.

Clients point at the **agents**, never at the control plane. Agents keep resolving
from their local copy even if the control plane is briefly unreachable.

Images (multi-arch `linux/amd64` + `linux/arm64`):

```
ghcr.io/ipmaze/mazedns-control-plane:latest
ghcr.io/ipmaze/mazedns-dns-agent:latest
```

Pick a path:

- [1. Docker / Compose](#1-docker--compose) — the quickest way in.
- [2. Kubernetes](#2-kubernetes) — control plane as a Deployment, agents as a
  DaemonSet or Deployment.

For every setting referenced below, see **[configuration.md](configuration.md)**.

---

## First-boot setup wizard

The control plane is configured through its **web UI**, not env vars or YAML. A
fresh control plane starts in **setup mode**: the API is locked to everything
except the wizard until setup completes. There is **no setup token** — the wizard
uses *trust-on-first-use* (like Grafana): whoever reaches the fresh control plane
first completes setup. **Do not expose the control plane publicly until you have
finished the wizard.** The log prints a plain reminder that setup mode is active.

The wizard first asks **how operators sign in**:

- **Local accounts** — create an admin username + password (no
  `MAZEDNS_ADMIN_PASSWORD`, no config file, no restart).
- **Single sign-on (OIDC)** — configure an external identity provider right there.
  You paste the issuer URL, client ID/secret, and the **admin email** that is
  granted the admin role on its first (and every) SSO login. The wizard shows the
  **redirect URI** to register with your provider and verifies the issuer's
  discovery document before finishing. A local **break-glass admin** is created
  alongside SSO by default so a misconfigured or unreachable IdP can never lock you
  out (you can opt out and rely on the `reset-admin` CLI below instead).

It then walks you through basic DNS defaults and your first enrollment key. The
auth choice isn't final — switch or repair it later under **Settings → Access**.

```bash
docker logs mazedns-control-plane   # confirms setup mode is active; no token needed
# open http://<host>:8080 and complete the wizard
```

Only **bootstrap** options stay in the environment/YAML: the database
(`MAZEDNS_DB_PATH` / `MAZEDNS_DB_DRIVER` / `MAZEDNS_DB_DSN`), the API bind
(`MAZEDNS_API_ADDRESS`, `api.port`), and `MAZEDNS_LOG_LEVEL`. Everything else —
DNS defaults, SSO, metrics export, classifier, cluster policy — is edited live under
**Settings** and stored in the database (the single source of truth). An existing
deployment upgrades transparently: its current env/YAML values seed the database
once on first boot of the new version, then are ignored.

Lost the admin password? Reset it directly against the DB (break-glass, not an env
var read on every boot):

```bash
docker compose exec control-plane /control-plane reset-admin --username admin
# prints a generated password if --password is omitted
```

## Enrollment in one paragraph

You create **enrollment keys** in the UI (Cluster → Enrollment keys), each with an
optional expiry and maximum number of uses. An agent starts with the control-plane
URL + an enrollment key (passed as `MAZEDNS_JOIN_TOKEN`) + a node name,
self-registers, and receives a per-node key it stores locally and the control plane
rotates automatically — it then appears in the **Cluster** tab automatically, with
no key to copy. (A `MAZEDNS_JOIN_TOKEN` set on the control plane's own config is
deprecated but still honored: it's imported once as a never-expiring enrollment
key.) Toggle **require approval** in the setup wizard or under Settings → Access to
hold new agents until you approve them.

### Removing an agent: revoke vs. remove-only

In the **Cluster** tab, deleting an agent offers two intents:

- **Remove and revoke** (default) — tombstones the node's identity. A still-running
  agent presenting that identity is refused at re-enrollment (it keeps serving DNS
  standalone but cannot rejoin), and the attempt consumes **no** enrollment-key use.
  Use this to decommission or lock out a compromised agent. Reverse it with
  **Un-revoke** (the agent then rejoins as a *new* node on its next attempt).
- **Remove only** — deletes the row without a tombstone, so the agent may re-enroll
  as a brand-new node. Use it for intentional replacement, and it's also the path a
  control-plane database reset takes (the CP self-heals every agent back in).

**Residual limitation:** revocation is keyed on the node's stored identity (in its
`/data`). An agent whose `/data` was **wiped** enrolls with *no* identity, so it
can't be matched to a tombstone and would join as a new node. To keep such an agent
out, **revoke the enrollment key it holds** (Cluster → Enrollment keys) and/or turn
on **require approval** so new joins wait for an admin.

---

## 1. Docker / Compose

### Fast deploy (recommended)

The repo ships [`docker-compose.prod.yml`](../docker-compose.prod.yml): it pulls
the published images and runs a control plane plus one DNS agent.

```bash
curl -O https://raw.githubusercontent.com/IPMaze/MazeDNS/main/docker-compose.prod.yml
docker compose -f docker-compose.prod.yml up -d
```

That's it:

- Open `http://localhost:8080` and complete the wizard (choose local or SSO auth,
  create your admin,
  DNS defaults, and first enrollment key).
- The wizard shows an agent snippet. Paste the enrollment key it gives you into the
  agent's `MAZEDNS_JOIN_TOKEN` (or set it before `up -d` and re-run) so the bundled
  agent joins. Create more enrollment keys anytime under Cluster → Enrollment keys.
- DNS → the agent listens on the host's `:53` (UDP + TCP). Test it:

  ```bash
  dig @localhost example.com          # resolves
  dig @localhost doubleclick.net      # blocked
  ```

Both containers persist their state in named volumes mounted at `/data`. In a real
multi-site deployment each agent runs on its own host/site and reaches the control
plane over your private overlay (VPN/WireGuard) — see
[Reaching the control plane](#reaching-the-control-plane-from-an-agent) below.

> The agent image listens on port **53** by default and binds it as a non-root user
> via a `CAP_NET_BIND_SERVICE` file capability baked into the binary — no root and no
> `cap_add` needed with Docker's default capabilities.

### Real client IPs and node IPs (host networking)

The agent in `docker-compose.prod.yml` runs with **`network_mode: host`** (the
recommended production setup): it binds the host's `:53` directly, so the resolver
sees each client's real source IP (per-client dashboard stats) and the control
plane records the node's real host IP. With bridge port mapping (`53:53`) instead,
Docker's NAT rewrites every query's source to the Docker gateway, the dashboard
collapses all clients into one, and nodes show up with bridge addresses like
`172.18.0.2`.

Host networking has no Compose-provided DNS, so the control plane's IP must be
pinned with **`MAZEDNS_CP_IP`** (required by the compose file) — see below. The
agent's HTTP API is moved to `:9090` via `MAZEDNS_API_PORT` so it doesn't collide
with a control plane sharing the host on `:8080`.

### Reaching the control plane from an agent

An agent needs to reach the control plane's URL (`MAZEDNS_CP_URL`). If the agent is
the **only DNS server on its network**, or runs with `network_mode: host` and has no
upstream resolver yet, it can't resolve the control plane's hostname at boot. Pin
the IP so DNS is bypassed (TLS still verifies the URL's hostname):

```yaml
    environment:
      MAZEDNS_CP_URL: "https://cp.example.com:8080"
      MAZEDNS_CP_IP:  "10.0.0.5"        # dial this IP; skip DNS
```

Alternatives:

- Add a static host entry instead (Go honors `/etc/hosts`):

  ```yaml
      extra_hosts:
        - "cp.example.com:10.0.0.5"
  ```

- Or point `MAZEDNS_CP_URL` straight at an IP.

When `MAZEDNS_CP_IP` is left empty, the agent auto-learns and pins the address the
control plane advertises at enrollment (`MAZEDNS_ADVERTISE_ADDR` on the control
plane) and persists it across restarts.

### `docker run` equivalents

If you prefer plain `docker run`:

```bash
# 1. Control plane — dashboard/API only, never serves DNS. Configure it in the
#    browser: open the UI and complete the setup wizard (no token — trust-on-first-
#    use; don't expose it publicly until setup is done). The wizard sets up auth
#    (local or SSO), your admin, and first enrollment key.
docker run -d --name mazedns-control-plane \
  -p 8080:8080 -v cp-data:/data \
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \
  -e MAZEDNS_DB_PATH=/data/mazedns.db \
  ghcr.io/ipmaze/mazedns-control-plane:latest

# 2. DNS agent — self-enrolls with an enrollment key, then serves DNS on :53.
#    Host networking (recommended): real client IPs in the dashboard and the
#    node's real host IP at the control plane; MAZEDNS_CP_IP is required because
#    there is no Docker DNS (it pins the dial — TLS still verifies the URL host).
docker run -d --name mazedns-agent \
  --network host -v agent-data:/data \
  -e MAZEDNS_CP_URL=http://<control-plane-host>:8080 \
  -e MAZEDNS_CP_IP=<control-plane-ip> \
  -e MAZEDNS_JOIN_TOKEN=<enrollment-key> \
  -e MAZEDNS_NODE_NAME=agent-1 \
  -e MAZEDNS_DB_PATH=/data/mazedns.db \
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \
  -e MAZEDNS_API_PORT=9090 \
  ghcr.io/ipmaze/mazedns-dns-agent:latest
  # MAZEDNS_JOIN_TOKEN is an enrollment key you create in the UI (Cluster →
  # Enrollment keys), not a shared password. It only lets an agent enroll; the
  # control plane then issues a per-node key it rotates automatically.
  # MAZEDNS_NODE_NAME is only the initial display label. The control plane assigns
  # the node an immutable UUID at first enrollment (stored on the -v agent-data
  # volume); you can rename the node later in the UI without re-identifying it.
  # Keep the volume: it holds the node's identity + key, so restarts/renames map
  # back to the SAME node instead of enrolling a duplicate.
  # Prefer bridge networking? Replace --network host with
  #   -p 53:53/udp -p 53:53/tcp -p 9090:8080
  # and drop MAZEDNS_CP_IP + MAZEDNS_API_PORT — but the dashboard then shows the
  # docker bridge IP for all clients and for this node.
```

> **Keep the agent's `/data` volume across image updates.** It stores the node's
> identity (its server-assigned UUID + rotating key). Recreate the agent without it
> and the control plane sees a brand-new node — you get a duplicated, `-2`-suffixed
> entry instead of the original.

`MAZEDNS_API_ADDRESS=0.0.0.0` makes the mapped `/healthz` + `/metrics` port reachable
from outside the container (it defaults to loopback). The control plane's `/metrics`
can be locked behind a bearer token (**Settings → Integrations → Metrics scrape
token**); see [configuration.md](configuration.md#scraping-metrics-prometheus) for
the Prometheus scrape job.

---

## 2. Kubernetes

Run one control-plane Deployment and expose the agents to clients. Apply into a
dedicated namespace, and adjust the storage class, image tag, and Service type for
your cluster.

```yaml
apiVersion: v1
kind: Namespace
metadata: { name: mazedns }
---
apiVersion: v1
kind: Secret
metadata: { name: mazedns-secrets, namespace: mazedns }
type: Opaque
stringData:
  # An enrollment key created in the UI (Cluster → Enrollment keys). Agents present
  # it to self-enroll; it is never used to serve DNS. (The first admin is created in
  # the setup wizard, not via an env var — there is no admin-password secret.)
  join-token: "<enrollment-key-from-the-wizard>"
```

### Control plane

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: control-plane-data, namespace: mazedns }
spec:
  accessModes: ["ReadWriteOnce"]
  resources: { requests: { storage: 5Gi } }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: control-plane, namespace: mazedns }
spec:
  replicas: 1
  strategy: { type: Recreate }        # single writer per DB (see configuration.md)
  selector: { matchLabels: { app: mazedns-control-plane } }
  template:
    metadata: { labels: { app: mazedns-control-plane } }
    spec:
      containers:
        - name: control-plane
          image: ghcr.io/ipmaze/mazedns-control-plane:latest
          # Configured via the first-boot web wizard (no token — trust-on-first-use;
          # keep it off the public internet until setup completes). Only bootstrap
          # values live here. Recover a lost admin with
          # `kubectl exec deploy/mazedns-control-plane -- /control-plane reset-admin`.
          # The control plane always serves cluster endpoints — no enable flag.
          env:
            - { name: MAZEDNS_API_ADDRESS, value: "0.0.0.0" }
            - { name: MAZEDNS_DB_PATH, value: "/data/mazedns.db" }
          ports: [{ containerPort: 8080 }]
          livenessProbe:  { httpGet: { path: /healthz, port: 8080 }, initialDelaySeconds: 5 }
          readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
          volumeMounts: [{ name: data, mountPath: /data }]
      volumes:
        - name: data
          persistentVolumeClaim: { claimName: control-plane-data }
---
apiVersion: v1
kind: Service
metadata: { name: control-plane, namespace: mazedns }
spec:
  selector: { app: mazedns-control-plane }
  ports: [{ name: http, port: 8080, targetPort: 8080 }]
  # type: LoadBalancer   # or front the UI with an Ingress + TLS
```

### DNS agents

Agents connect back to `control-plane:8080` inside the cluster and serve DNS to
clients. A **DaemonSet** (one agent per node) is a common fit; a Deployment behind a
`LoadBalancer` Service also works. Each pod keeps a small local database holding the
node's identity + key — an agent that loses it re-enrolls with its enrollment key
and comes back as a *new* node (its old row is orphaned). `emptyDir` is fine if the
enrollment key is unlimited-use; to keep a stable identity across restarts, mount a
`PersistentVolumeClaim` for the agent's data directory instead.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata: { name: dns-agent, namespace: mazedns }
spec:
  selector: { matchLabels: { app: mazedns-dns-agent } }
  template:
    metadata: { labels: { app: mazedns-dns-agent } }
    spec:
      containers:
        - name: dns-agent
          image: ghcr.io/ipmaze/mazedns-dns-agent:latest
          env:
            - { name: MAZEDNS_API_ADDRESS, value: "0.0.0.0" }   # required for kubelet probes + scraping
            - { name: MAZEDNS_DB_PATH, value: "/data/mazedns.db" }
            - { name: MAZEDNS_CP_URL, value: "http://control-plane.mazedns.svc:8080" }
            - name: MAZEDNS_JOIN_TOKEN
              valueFrom: { secretKeyRef: { name: mazedns-secrets, key: join-token } }
            - name: MAZEDNS_NODE_NAME
              valueFrom: { fieldRef: { fieldPath: spec.nodeName } }
          ports:
            - { name: dns-udp, containerPort: 53, protocol: UDP }
            - { name: dns-tcp, containerPort: 53, protocol: TCP }
            - { name: http,    containerPort: 8080 }
          livenessProbe:  { httpGet: { path: /healthz, port: 8080 } }
          readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
          volumeMounts: [{ name: data, mountPath: /data }]
      # emptyDir loses the node's identity when the pod is recreated, so the agent
      # re-enrolls as a NEW node (a duplicate, -2-suffixed entry). Fine only with an
      # unlimited-use enrollment key. For a stable identity across restarts, back the
      # `data` volume with a PersistentVolumeClaim (or a per-node hostPath) instead.
      volumes: [{ name: data, emptyDir: {} }]
---
apiVersion: v1
kind: Service
metadata: { name: dns, namespace: mazedns }
spec:
  type: LoadBalancer            # give clients a stable DNS address
  externalTrafficPolicy: Local  # preserve real client IPs for per-client stats
  selector: { app: mazedns-dns-agent }
  ports:
    - { name: dns-udp, port: 53, targetPort: 53, protocol: UDP }
    - { name: dns-tcp, port: 53, targetPort: 53, protocol: TCP }
```

Point clients (or CoreDNS forwarding) at the `dns` Service's external address.
`MAZEDNS_API_ADDRESS=0.0.0.0` is mandatory here: kubelet runs the `/healthz` probes
against the pod IP, which a loopback bind would refuse. For real client IPs, use
`externalTrafficPolicy: Local` (above) or give the agent pod `hostNetwork: true`.

---

## Next steps

- **[configuration.md](configuration.md)** — every environment variable and YAML
  setting (including external PostgreSQL and metrics/logs export).
- **[user-guide.md](user-guide.md)** — the dashboard, blocklists, rewrites,
  clustering operations, auth/SSO, and backup/restore.
- **[troubleshooting.md](troubleshooting.md)** — symptom → fix.
