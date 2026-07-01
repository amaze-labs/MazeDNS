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

## Enrollment in one paragraph

The control plane holds a shared **join token** (`MAZEDNS_JOIN_TOKEN`). An agent
starts with the control-plane URL + the token + a node name, self-registers, and
receives a per-node key it stores locally — it then appears in the **Cluster** tab
automatically, with no key to copy. Set `MAZEDNS_REQUIRE_APPROVAL=true` on the
control plane to hold new agents until you approve them.

---

## 1. Docker / Compose

### Fast deploy (recommended)

The repo ships [`docker-compose.prod.yml`](../docker-compose.prod.yml): it pulls
the published images and runs a control plane plus one DNS agent.

```bash
curl -O https://raw.githubusercontent.com/IPMaze/MazeDNS/main/docker-compose.prod.yml

MAZEDNS_ADMIN_PASSWORD='choose-a-strong-one' \
MAZEDNS_JOIN_TOKEN="$(openssl rand -hex 16)" \
  docker compose -f docker-compose.prod.yml up -d
```

That's it:

- Dashboard → `http://localhost:8080` (log in as `admin` with the password above).
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

### Seeing real client IPs (host networking)

With the default bridge port mapping (`53:53`), Docker's NAT rewrites every query's
source to the Docker gateway, so the dashboard collapses all clients into one. To
preserve real client IPs on a Linux host, run the agent with **host networking**.
In `docker-compose.prod.yml`, replace the agent's `ports:` block with:

```yaml
    network_mode: host
```

Host networking ignores port mappings (the agent binds the host's `:53` directly),
and there is no Compose-provided DNS, so tell the agent how to reach the control
plane by IP — see below. This is the recommended production setup.

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
# 1. Control plane — dashboard/API only, never serves DNS.
docker run -d --name mazedns-control-plane \
  -p 8080:8080 -v cp-data:/data \
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \
  -e MAZEDNS_ADMIN_PASSWORD=change-me \
  -e MAZEDNS_CLUSTER_ENABLED=true \
  -e MAZEDNS_JOIN_TOKEN=a-shared-secret \
  ghcr.io/ipmaze/mazedns-control-plane:latest

# 2. DNS agent — self-enrolls with the join token, then serves DNS on :53.
docker run -d --name mazedns-agent \
  -p 53:53/udp -p 53:53/tcp -v agent-data:/data \
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \
  -e MAZEDNS_CP_URL=http://<control-plane-host>:8080 \
  -e MAZEDNS_JOIN_TOKEN=a-shared-secret \
  -e MAZEDNS_NODE_NAME=agent-1 \
  ghcr.io/ipmaze/mazedns-dns-agent:latest
  # Agent can't resolve the control plane's hostname? Pin its IP (DNS bypassed,
  # TLS still verifies the URL host):  -e MAZEDNS_CP_IP=10.0.0.5
  # Real client IPs on Linux: use --network host instead of the -p mappings.
```

`MAZEDNS_API_ADDRESS=0.0.0.0` makes the mapped `/healthz` + `/metrics` port reachable
from outside the container (it defaults to loopback).

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
  admin-password: "change-me"
  join-token: "a-shared-secret"
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
          env:
            - { name: MAZEDNS_API_ADDRESS, value: "0.0.0.0" }
            - { name: MAZEDNS_DB_PATH, value: "/data/mazedns.db" }
            - { name: MAZEDNS_CLUSTER_ENABLED, value: "true" }
            - name: MAZEDNS_ADMIN_PASSWORD
              valueFrom: { secretKeyRef: { name: mazedns-secrets, key: admin-password } }
            - name: MAZEDNS_JOIN_TOKEN
              valueFrom: { secretKeyRef: { name: mazedns-secrets, key: join-token } }
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
`LoadBalancer` Service also works. Each pod keeps a small local database — an agent
that loses it simply re-enrolls with the join token, so `emptyDir` is fine.

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
