# syntax=docker/dockerfile:1
#
# Single image. At runtime, MAZEDNS_MODE selects:
#   master  (default) — resolver + control-plane API + web UI
#   worker            — resolver + /healthz + /metrics only (no UI/API)

# ---- frontend ----
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# ---- build ----
FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN mkdir -p /data && \
    CGO_ENABLED=0 go build -tags embed_dist -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" -o /out/mazedns ./cmd/mazedns

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mazedns /usr/local/bin/mazedns
COPY --from=build --chown=65532:65532 /data /data
COPY configs /etc/mazedns
WORKDIR /data
EXPOSE 5300/udp 5300/tcp 8080/tcp 853/tcp 8443/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mazedns", "--config", "/etc/mazedns/mazedns.yaml"]
