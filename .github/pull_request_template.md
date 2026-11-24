<!--
Title as a Conventional Commit: feat: … / fix: … / docs: … (it decides the release number).
Pull requests are public: no real domains, hostnames, addresses or query logs. See CONTRIBUTING.md.
-->

## What and why

<!-- What changes for someone running MazeDNS, and why. -->

Closes #

## How it was tested

<!-- Commands run, what you checked by hand (control plane, resolver, both?). -->

## Checklist

- [ ] `make fmt`, `make vet` and `make test` pass
- [ ] Schema or SQL touched → also passes with `-tags pgtest` on PostgreSQL
- [ ] UI touched → `npm --prefix web run typecheck` and `make web` pass; looked at it in both themes and at phone width
- [ ] Docs updated (`docs/configuration.md` for new settings, `docs/user-guide.md` for UI changes)
