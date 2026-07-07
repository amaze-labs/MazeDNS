# syntax=docker/dockerfile:1
#
# Two images from one file, selected with `--target`:
#   control-plane — API + web UI + auth + classifier + cluster coordination (no DNS)
#   dns-agent     — resolver + config replication + /healthz + /metrics (no UI)
#
# Build:
#   docker build --target control-plane -t mazedns-control-plane .
#   docker build --target dns-agent     -t mazedns-dns-agent .

ARG VERSION=dev

# ---- frontend (control plane only) ----
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# ---- control-plane binary (web UI embedded) ----
FROM golang:1.26-alpine AS build-cp
ARG VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN mkdir -p /data && \
    CGO_ENABLED=0 go build -tags embed_dist -trimpath \
      -ldflags="-s -w -X github.com/IPMaze/MazeDNS/internal/version.Version=${VERSION}" -o /out/control-plane ./cmd/control-plane

# ---- dns-agent binary (lean: no web assets) ----
FROM golang:1.26-alpine AS build-agent
ARG VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /data && \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/IPMaze/MazeDNS/internal/version.Version=${VERSION}" -o /out/dns-agent ./cmd/dns-agent
# Grant the binary CAP_NET_BIND_SERVICE via a file capability so the non-root
# runtime user can bind the privileged DNS port 53 directly (e.g. under
# network_mode: host) without running as root or needing compose cap_add. The
# capability xattr is preserved by BuildKit's COPY into the distroless image.
# NET_BIND_SERVICE is in Docker's default capability bounding set, so no extra
# runtime privileges are required.
RUN apk add --no-cache libcap && setcap 'cap_net_bind_service=+ep' /out/dns-agent

# ---- control-plane runtime ----
FROM gcr.io/distroless/static-debian12:nonroot AS control-plane
COPY --from=build-cp /out/control-plane /usr/local/bin/control-plane
COPY --from=build-cp --chown=65532:65532 /data /data
COPY configs /etc/mazedns
WORKDIR /data
EXPOSE 8080/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/control-plane", "--config", "/etc/mazedns/mazedns.yaml"]

# ---- dns-agent runtime ----
FROM gcr.io/distroless/static-debian12:nonroot AS dns-agent
COPY --from=build-agent /out/dns-agent /usr/local/bin/dns-agent
COPY --from=build-agent --chown=65532:65532 /data /data
COPY configs /etc/mazedns
WORKDIR /data
EXPOSE 53/udp 53/tcp 853/tcp 8443/tcp 8080/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/dns-agent", "--config", "/etc/mazedns/mazedns.yaml"]
