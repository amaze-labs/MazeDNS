# Security policy

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately through GitHub:
the repository's *Security* tab → *Report a vulnerability*
([direct link](https://github.com/amaze-labs/MazeDNS/security/advisories/new)).

Include what you can of:

- the version (Settings → About, or `GET /api/version`) and which part: the
  control plane (UI/API) or a resolver;
- how to reproduce it, and what an attacker gains;
- the configuration that matters (SSO or local accounts, SQLite or PostgreSQL,
  reverse proxy, how the resolvers are exposed, …).

MazeDNS is maintained in spare time: reports are read and answered as soon as
possible, without a fixed deadline. A fix ships as a new release; the advisory
is published once the release is out, crediting you unless you prefer not.

## Supported versions

Only the **latest release**. Every change to `main` is released, so a fix is
never backported: upgrade to get it.

## Scope

The control plane (`ghcr.io/amaze-labs/mazedns-control-plane`) and the resolver
(`ghcr.io/amaze-labs/mazedns-resolver`, also published as `mazedns-agent`).

These are deliberate and documented, not vulnerabilities
(see [Security notes](README.md#security-notes)):

- The resolver has **no client ACL**: anything that can reach its `:53` gets
  answers. Resolvers belong on a private network or behind a firewall.
- Per-client rate limiting ships **disabled** (Settings → Resolver).
- The resolver's `/metrics`, `/healthz` and `/readyz` endpoints are
  unauthenticated; they listen on loopback unless you bind them elsewhere.
- Until the setup wizard is completed, the first visitor of the control plane
  owns setup: there is no setup token. Don't expose it before then.
- The control-plane UI/API is meant for a management network or VPN, behind a
  TLS reverse proxy, not the internet.
- Classification contacts external services only once you enable them;
  what each one receives is listed in the
  [user guide](docs/user-guide.md#classification-traffic-types-and-risk).
