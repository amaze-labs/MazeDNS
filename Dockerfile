# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mazedns ./cmd/mazedns

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mazedns /usr/local/bin/mazedns
COPY configs /etc/mazedns
EXPOSE 5300/udp 5300/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mazedns", "--config", "/etc/mazedns/mazedns.yaml"]
