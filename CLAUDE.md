# CLAUDE.md

Project context for Claude Code working on **MazeDNS** — a self-hosted DNS filter and resolver cluster: a control plane (UI, API, auth, classifier, config replication) and resolvers that answer the queries.

This file holds the working rules. The rest is documented once, for everyone: the contribution rules for humans in `CONTRIBUTING.md`, the repo layout, `make` targets, tests and a local cluster in `docs/dev/development.md`, how the pieces fit together in `docs/dev/architecture.md`, every setting in `docs/configuration.md`, the UI in `docs/user-guide.md`.

## Stack

- **Go** (version in `go.mod`), pure Go with `CGO_ENABLED=0`: two binaries, `cmd/control-plane` (never serves DNS) and `cmd/dns-resolver`. SQLite by default through `modernc.org/sqlite` (its page cache and temporaries live outside the Go heap), PostgreSQL through pgx when `MAZEDNS_DB_DRIVER` is set.
- **Web UI**: React + Vite + TypeScript in `web/`, embedded into the control-plane binary (`-tags embed_dist`).
- **Release**: every push to `main` that touches code is a release (`.github/workflows/build-containers.yml`): the version comes from the commit types since the last tag (`.github/scripts/next-version.sh`), both images are published, then the tag (no `v`) is pushed. Changes only to `docs/`, `*.md` or `LICENSE` release nothing; they ship with the next release.

## Working on this repository

The same rules, for humans, are in `CONTRIBUTING.md`.

1. **Commit messages**: conventional commits, with this co-author trailer:
       Co-authored-by: Claude <noreply@anthropic.com>
   The TYPE must describe THIS change: it decides the release number (`feat:` = minor, `type!:` = major, `docs:` = no release of its own, anything else = patch). `feat:` only for something a user can now do or see that they couldn't before; a correction or a tweak is `fix:`. Decide the type from the diff before writing the subject. One concern per commit.
2. **Tracked issues close themselves**: reference the issue from every commit that implements it (`Refs #<n>`), and make the LAST one `Closes #<n>`.
3. **Issue first, and nothing personal in it**: open the issue before writing the code that answers it (with the `file:line` evidence), and reference related issues, closed ones included. The repo is public: issues, commits, PR bodies, logs, tests, fixtures and screenshots carry nothing from a real network or deployment — no real domains, hostnames, site or client names, IP or MAC addresses, query logs, cluster or host names, no names or emails. When an example helps, invent a neutral one (`nas.home.lan`, `site-a`, `10.20.0.0/24`, `example.com`). Grep the text for real values before publishing it: GitHub keeps every edit.
4. **Take what you work on**: when work on an issue or a pull request starts — investigating counts — assign it to the person you are working for (`gh issue edit <n> --add-assignee @me`, `gh pr edit <n> --add-assignee @me`), unless it is already assigned to someone else: then ask before starting, because someone may already be on it.
5. **Measure, don't guess**: a performance or memory claim (disk writes, RSS, latency) is backed by a measurement on a realistic setup — `/proc` counters, `/metrics`, the benchmarks in `docs/dev/latency-audit.md` — not by reading the code alone. The numbers go in the issue or the PR, anonymised (rule 3).
6. **New operator knobs are environment variables**: a `MAZEDNS_*` variable read in `internal/config` (follow `MAZEDNS_KEY_MAX_AGE`) and documented in `docs/configuration.md`, not a new field in the Settings UI.
7. **Pull requests are merged by a maintainer**: work on a branch and open the PR; never merge it, and never deploy, unless the person you are working for asks for that PR.

## Before opening a pull request

The checklist in `CONTRIBUTING.md` ("Making the change") applies as written: `make fmt`, `make vet`, `make test`; the PostgreSQL suite after touching the schema or SQL; the race detector and the benchmarks after touching the resolver hot path; `npm --prefix web run typecheck` and `make web`, and a look in the browser in both themes and at phone width after touching the UI; the docs updated in the same change.
