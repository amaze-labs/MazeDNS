# Demo data for screenshots

`go run ./dev/demo` fills a **fresh** control plane with the demo the screenshots
in `docs/images` show: the admin `anna`, the sites `cloud`, `home` and `office`,
four resolvers (`office-dns2` one release behind), local records, a blocklist,
named clients and a day of query history.

It uses the control plane's HTTP API only, as a browser and real resolvers do. It
enrolls four simulated resolvers, polls as them and ships their query and process
logs, backdated over the last 24 hours, so every chart and table comes from the
real code. The one exception is `-db`, below.

## Run it

```sh
make web                                   # the UI the control plane embeds
go build -tags embed_dist -o /tmp/cp ./cmd/control-plane

mkdir -p /tmp/demo && cd /tmp/demo         # the log shows the DB path: keep it short
MAZEDNS_DB_PATH=data/mazedns.db \
MAZEDNS_IMAGE_VERSION=0.143.3 MAZEDNS_AGENT_BUILD=0.143.2 \
MAZEDNS_CLASSIFIER_ENABLED=true MAZEDNS_CLASSIFIER_MODE=suggest \
  /tmp/cp --config "$OLDPWD/configs/mazedns.yaml" &

cd "$OLDPWD"
go run ./dev/demo -state /tmp/demo/state.json -db /tmp/demo/data/mazedns.db \
  -version 0.143.3 -behind 0.142.1
go run ./dev/demo -state /tmp/demo/state.json -follow   # keep it running
```

Then sign in at <http://127.0.0.1:8080> as `anna` / `demo-password-1`.

- **Versions:** stamp the control plane (`MAZEDNS_IMAGE_VERSION`) with the latest
  release, so the top bar offers no update. Set `MAZEDNS_AGENT_BUILD` to the release
  its resolver code comes from (the release notes say "unchanged since …" when it's
  older). Then `-version` is that latest release and `-behind` an older one, which
  shows as needing an update.
- **`-follow`** keeps the resolvers polling (online, in sync) and adds a trickle of
  live queries. It also re-sends their process logs, which the control plane keeps
  in memory only.
- **`-state`** keeps the resolvers' identities and counters, so later runs reuse
  them instead of enrolling new ones. Delete it along with the database to start
  over.
- **`-db`** writes four classifier verdicts for the demo's phishing-style names.
  The classifier rates those names harmless, because they don't exist: it finds no
  registration, DNS or reputation evidence. The verdicts use the factors it reports
  for such names when they do exist, so Filtering → Review has something to show.

## Screenshots

Take them in a browser at 1440×900 (CSS pixels), light theme unless the name says
dark. The exceptions: `overview.png` is the full page,
`tablet-overview-dark.png` is 820×1180, and the `mobile-*` ones are 402×874.
Sign in **before** opening any page after a restart: a page that polls with an
expired session logs 401 warnings, which then show on the Logs page.
