# Contributing

Thanks for wanting to help. MazeDNS is a small project maintained in spare
time; these few rules keep it that way.

## Before writing code

**Open an issue first** — a [bug report or a feature request](https://github.com/amaze-labs/MazeDNS/issues/new/choose) —
and wait for an answer before a large change. It saves you work if the idea
doesn't fit, or fits differently. A typo or an obvious one-line fix can go
straight to a pull request.

When you start on an issue, assign it to yourself (or say so in it) so nobody
does the same work twice. One already assigned to someone else is theirs: ask
in it before you start.

Security problems are not issues: see [SECURITY.md](SECURITY.md).

## Keep it anonymous

Issues and pull requests are public. Never paste anything from a real network
— domains you resolve, hostnames, client names, IP and MAC addresses, query
logs — in the text, the logs, the tests or the screenshots. Invent neutral
ones (`nas.home.lan`, `site-a`, `10.20.0.0/24`, `example.com`).

## Making the change

Prerequisites, the repo layout, `make` targets and running a local cluster are
in [docs/dev/development.md](docs/dev/development.md); how the pieces fit
together is in [docs/dev/architecture.md](docs/dev/architecture.md). Before
opening the pull request:

- the Go code is formatted and vetted, and the tests pass (`make fmt`,
  `make vet`, `make test`);
- after touching the schema or any SQL, the suite also passes on PostgreSQL
  (`go test -tags pgtest -p 1 ./...`, see
  [Tests and benchmarks](docs/dev/development.md#tests-and-benchmarks));
- after touching the resolver hot path (`internal/resolver`, `internal/cache`,
  `internal/filter`), the race detector is clean and the benchmarks didn't get
  worse ([latency-audit.md](docs/dev/latency-audit.md));
- the frontend type-checks and builds (`npm --prefix web run typecheck`,
  `make web`), and you have looked at the change in the browser, in both
  themes and at phone width;
- the docs say what changed: a new `MAZEDNS_*` variable or YAML setting goes in
  [docs/configuration.md](docs/configuration.md), a new page or control in the
  [user guide](docs/user-guide.md).

## Commits and pull requests

Commit messages and pull request titles follow
[Conventional Commits](https://www.conventionalcommits.org/): `fix: …`,
`feat: …`, `docs: …`, `refactor: …`, `test: …`, `ci: …`, `chore: …`. The type
is not decoration: every push to `main` is a release, and the type decides
its number.

- `feat:` — something a user can now do or see that they couldn't before
  (minor version);
- `type!:` — a breaking change (major version);
- `docs:` — no new version; it ships with the next release;
- anything else — a fix, a tweak, tests (patch version).

One concern per commit. Reference the issue (`Refs #12`), and close it from
the last commit (`Closes #12`).

## Licensing

The project is under the [GNU Affero General Public License v3.0 or later](LICENSE).
By opening a pull request you agree that your contribution is licensed under
those same terms — there is no CLA and no copyright assignment.

Before adding a dependency, a font or a bundled data set (blocklists,
category databases), check its licence is AGPLv3-compatible and say in the
pull request where it comes from.

## Code of conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
