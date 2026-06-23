# Tiny DNS traffic generator for the dev cluster: loops `dig` against a target
# resolver so the dashboard fills with realistic per-client traffic. Each client
# container has its own IP on the compose network, so the resolver sees distinct
# source IPs (unlike host-published ports, which are NAT'd to the gateway).
FROM alpine:3.20
RUN apk add --no-cache bind-tools
COPY traffic.sh /traffic.sh
RUN chmod +x /traffic.sh
ENTRYPOINT ["/traffic.sh"]
