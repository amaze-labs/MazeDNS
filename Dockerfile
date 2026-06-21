# syntax=docker/dockerfile:1

# ---- frontend ----
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# ---- build ----
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -tags embed_dist -trimpath -ldflags="-s -w" -o /out/mazedns ./cmd/mazedns

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mazedns /usr/local/bin/mazedns
COPY configs /etc/mazedns
EXPOSE 5300/udp 5300/tcp 8080/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mazedns", "--config", "/etc/mazedns/mazedns.yaml"]
