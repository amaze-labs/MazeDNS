# Installing & running MazeDNS

MazeDNS ships as **two self-contained components** so the dashboard can never slow
down DNS:

- **control-plane** — web UI, API, auth, classifier, cluster coordination. Holds
  the config and dashboard and **does not answer DNS**. Run **one**.
- **dns-agent** — a resolver node (data plane). Serves DNS, replicates its
  filtering config from the control plane, exposes only `/healthz` + `/metrics`.
  Run **one or more**, wherever you want to serve DNS.

Both are static binaries with no runtime dependencies. Agents keep resolving from
their local copy even if the control plane is briefly down. Clients point at the
**agents'** addresses, never at the control plane.

Pick an installation method:

- [Bare host (binaries + systemd)](#1-bare-host) — no container runtime.
- [Docker / Compose](#2-docker--compose) — the quickest path.
- [Kubernetes](#3-kubernetes) — control plane as a Deployment, agents as a
  DaemonSet/Deployment.

For every setting referenced below, see **[configuration.md](configuration.md)**.

---

## Enrollment in one paragraph

The control plane holds a shared **join token** (`MAZEDNS_JOIN_TOKEN`). An agent
boots with the control-plane URL + the token + a node name, self-registers, and
receives a per-node key it persists locally — it then appears in the **Cluster**
tab automatically, no key to copy. Set `MAZEDNS_REQUIRE_APPROVAL=true` on the
control plane to hold new agents until you approve them. See
[architecture.md](architecture.md#clustering) for the protocol.

---

## 1. Bare host

### Get the binaries

Every build is published to the rolling
**[`latest` release](https://github.com/IPMaze/MazeDNS/releases/latest)**. Each
archive contains **both** binaries plus example configs. Verify against
`mazedns_checksums.txt` (SHA-256).

| OS | Arch | Asset |
|----|------|-------|
| Linux | x86-64 | `mazedns_linux_amd64.tar.gz` |
| Linux | ARM64 | `mazedns_linux_arm64.tar.gz` |
| macOS | Apple Silicon | `mazedns_darwin_arm64.tar.gz` |
| macOS | Intel | `mazedns_darwin_amd64.tar.gz` |
| Windows | x86-64 | `mazedns_windows_amd64.zip` |

```bash
curl -L -o mazedns.tar.gz \
  https://github.com/IPMaze/MazeDNS/releases/latest/download/mazedns_linux_amd64.tar.gz
tar xzf mazedns.tar.gz && cd mazedns_linux_amd64
sudo install -m 0755 control-plane dns-agent /usr/local/bin/
sudo mkdir -p /etc/mazedns /var/lib/mazedns
```

### Control-plane host

Copy [`configs/control-plane.example.yaml`](../configs/control-plane.example.yaml)
to `/etc/mazedns/control-plane.yaml` and set at least `cluster.join_token` and an
admin password. Then create a service:

```ini
# /etc/systemd/system/mazedns-control-plane.service
[Unit]
Description=MazeDNS control plane
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/control-plane --config /etc/mazedns/control-plane.yaml
Environment=MAZEDNS_DB_PATH=/var/lib/mazedns/control-plane.db
Environment=MAZEDNS_ADMIN_PASSWORD=change-me
DynamicUser=yes
StateDirectory=mazedns
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now mazedns-control-plane
# UI on http://127.0.0.1:8080 — front it with a TLS reverse proxy for remote access.
```

### DNS-agent host(s)

Copy [`configs/dns-agent.example.yaml`](../configs/dns-agent.example.yaml) to
`/etc/mazedns/dns-agent.yaml`. Set `cluster.cp_url` (or use the env below). To bind
port 53 directly, set `listen.port: 53` and grant the capability.

```ini
# /etc/systemd/system/mazedns-dns-agent.service
[Unit]
Description=MazeDNS DNS agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/dns-agent --config /etc/mazedns/dns-agent.yaml
Environment=MAZEDNS_DB_PATH=/var/lib/mazedns/dns-agent.db
Environment=MAZEDNS_CP_URL=https://control-plane.internal:8080
Environment=MAZEDNS_JOIN_TOKEN=a-shared-secret
Environment=MAZEDNS_NODE_NAME=%H
# Let Prometheus scrape /metrics: bind it to this host's overlay/VPN IP
# (the default is loopback because the endpoint is unauthenticated).
Environment=MAZEDNS_API_ADDRESS=10.0.0.11
AmbientCapabilities=CAP_NET_BIND_SERVICE
DynamicUser=yes
StateDirectory=mazedns
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now mazedns-dns-agent
dig @127.0.0.1 -p 53 example.com     # (or your listen.port)
```

---

## 2. Docker / Compose

Two images: `ghcr.io/ipmaze/mazedns-control-plane` and
`ghcr.io/ipmaze/mazedns-dns-agent`.

### docker run

```bash
# 1. Control plane — dashboard/API only, never serves DNS.
docker run -d --name mazedns-control-plane \
  -p 8080:8080 -v cp-data:/data \
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \
  -e MAZEDNS_ADMIN_PASSWORD=change-me \
  -e MAZEDNS_CLUSTER_ENABLED=true \
  -e MAZEDNS_JOIN_TOKEN=a-shared-secret \
  ghcr.io/ipmaze/mazedns-control-plane:latest

# 2. DNS agent — self-enrolls with the join token, then serves DNS.
docker run -d --name mazedns-agent \
  -p 53:5300/udp -p 53:5300/tcp -v agent-data:/data \
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \
  -e MAZEDNS_CP_URL=http://<control-plane-host>:8080 \
  -e MAZEDNS_JOIN_TOKEN=a-shared-secret \
  -e MAZEDNS_NODE_NAME=agent-1 \
  ghcr.io/ipmaze/mazedns-dns-agent:latest
```

`MAZEDNS_API_ADDRESS=0.0.0.0` is required so the mapped `/healthz` + `/metrics`
port is reachable from outside the container (the binary defaults to loopback).

### Compose

The repo ships two compose files:

- [`docker-compose.yml`](../docker-compose.yml) — dev cluster: control plane + two
  agents + traffic generators (`make compose-dev`).
- [`docker-compose.prod.yml`](../docker-compose.prod.yml) — production: control
  plane + one agent, pulling the published images:

```bash
MAZEDNS_ADMIN_PASSWORD=... MAZEDNS_JOIN_TOKEN=... \
  docker compose -f docker-compose.prod.yml up -d
```

Data persists in named volumes mounted at `/data` in each container. In a real
multi-site deployment each agent runs on its own host/site and reaches the control
plane over your private overlay.

---

## 3. Kubernetes

Run one control-plane Deployment and expose the agents to clients. Apply into a
dedicated namespace. Adjust the storage class, image tag, and Service type for your
cluster.

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
          args: ["--config", "/etc/mazedns/mazedns.yaml"]
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
`LoadBalancer` Service also works. Each pod keeps a small local database — an
agent that loses it simply re-enrolls with the join token, so `emptyDir` is fine.

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
          args: ["--config", "/etc/mazedns/mazedns.yaml"]
          env:
            - { name: MAZEDNS_API_ADDRESS, value: "0.0.0.0" }   # required for kubelet probes + scraping
            - { name: MAZEDNS_DB_PATH, value: "/data/mazedns.db" }
            - { name: MAZEDNS_CP_URL, value: "http://control-plane.mazedns.svc:8080" }
            - name: MAZEDNS_JOIN_TOKEN
              valueFrom: { secretKeyRef: { name: mazedns-secrets, key: join-token } }
            - name: MAZEDNS_NODE_NAME
              valueFrom: { fieldRef: { fieldPath: spec.nodeName } }
          ports:
            - { name: dns-udp, containerPort: 5300, protocol: UDP }
            - { name: dns-tcp, containerPort: 5300, protocol: TCP }
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
  selector: { app: mazedns-dns-agent }
  ports:
    - { name: dns-udp, port: 53, targetPort: 5300, protocol: UDP }
    - { name: dns-tcp, port: 53, targetPort: 5300, protocol: TCP }
```

Point clients (or CoreDNS forwarding) at the `dns` Service's external address.
`MAZEDNS_API_ADDRESS=0.0.0.0` is mandatory here: kubelet runs the `/healthz` probes
against the pod IP, which a loopback bind would refuse.

---

## Next steps

- **[configuration.md](configuration.md)** — every setting, split by control
  plane / agent / infrastructure (including external PostgreSQL and metrics/logs
  export).
- **[architecture.md](architecture.md)** — how the components, replication, and
  enrollment fit together.
- **[troubleshooting.md](troubleshooting.md)** — common issues.
