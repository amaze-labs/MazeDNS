# syntax=docker/dockerfile:1
#
# Two images from one file, selected with `--target`:
#   control-plane — API + web UI + auth + classifier + cluster coordination (no DNS)
#   dns-resolver  — DNS resolver + config replication + /healthz + /metrics (no UI)
#   dns-agent     — the same image as dns-resolver under its pre-rename target
#                   name, kept until the next major release
#
# Build:
#   docker build --target control-plane -t mazedns-control-plane .
#   docker build --target dns-resolver  -t mazedns-resolver .

ARG VERSION=dev
# The release whose resolver code ships with this release (the control plane
# flags older resolvers); the release pipeline sets it, local builds leave it empty.
ARG AGENT_BUILD=

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
ARG AGENT_BUILD
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN mkdir -p /data && \
    CGO_ENABLED=0 go build -tags embed_dist -trimpath \
      -ldflags="-s -w -X github.com/IPMaze/MazeDNS/internal/version.Version=${VERSION} -X github.com/IPMaze/MazeDNS/internal/version.AgentBuild=${AGENT_BUILD}" \
      -o /out/control-plane ./cmd/control-plane

# ---- dns-resolver binary (lean: no web assets) ----
FROM golang:1.26-alpine AS build-resolver
ARG VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /data /out/bin && \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/IPMaze/MazeDNS/internal/version.Version=${VERSION}" -o /out/bin/dns-resolver ./cmd/dns-resolver && \
    ln -s dns-resolver /out/bin/dns-agent
# Grant the binary CAP_NET_BIND_SERVICE via a file capability so the non-root
# runtime user can bind the privileged DNS port 53 directly (e.g. under
# network_mode: host) without running as root or needing compose cap_add. The
# capability xattr is preserved by BuildKit's COPY into the distroless image.
# NET_BIND_SERVICE is in Docker's default capability bounding set, so no extra
# runtime privileges are required.
RUN apk add --no-cache libcap && setcap 'cap_net_bind_service=+ep' /out/bin/dns-resolver

# ---- control-plane runtime ----
FROM gcr.io/distroless/static-debian12:nonroot AS control-plane
COPY --from=build-cp /out/control-plane /usr/local/bin/control-plane
COPY --from=build-cp --chown=65532:65532 /data /data
COPY configs /etc/mazedns
WORKDIR /data
EXPOSE 8080/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/control-plane", "--config", "/etc/mazedns/mazedns.yaml"]

# ---- dns-resolver runtime ----
FROM gcr.io/distroless/static-debian12:nonroot AS dns-resolver
# Copying the directory keeps dns-agent a symlink to dns-resolver, so a probe,
# command or entrypoint override that still names /usr/local/bin/dns-agent
# keeps working (it logs a deprecation warning).
COPY --from=build-resolver /out/bin/ /usr/local/bin/
COPY --from=build-resolver --chown=65532:65532 /data /data
COPY configs /etc/mazedns
WORKDIR /data
EXPOSE 53/udp 53/tcp 853/tcp 8443/tcp 8080/tcp
USER nonroot:nonroot
# DNS readiness: the binary queries its own /readyz, which probes the DNS
# listener over UDP and TCP with a built-in local record (no shell/curl in
# distroless). Docker only marks the container unhealthy; it does not restart it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/dns-resolver", "--config", "/etc/mazedns/mazedns.yaml", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/dns-resolver", "--config", "/etc/mazedns/mazedns.yaml"]

# ---- dns-agent: pre-rename target name, same image ----
FROM dns-resolver AS dns-agent
