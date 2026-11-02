// Command demo fills a fresh control plane with a realistic demo: an admin, three
// sites, four resolvers (one a release behind), local records, a blocklist, named
// clients and a day of query history. It is what the screenshots in docs/images
// are taken from.
//
// It talks to the control plane only through its HTTP API, the way a browser and
// real resolvers do: it enrolls four simulated resolvers with an enrollment key,
// polls as them and ships their query and process logs (backdated across the
// last 24 hours), so every chart and table is built by the real code.
//
//	go run ./dev/demo -url http://127.0.0.1:8080 -follow
//
// With -follow it keeps polling and sending a trickle of live queries, so the
// resolvers stay online while you take screenshots. See dev/demo/README.md.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/cluster"
	_ "modernc.org/sqlite"
)

var (
	cpURL    = flag.String("url", "http://127.0.0.1:8080", "control plane base URL")
	user     = flag.String("user", "anna", "admin username (created by setup if the control plane is fresh)")
	password = flag.String("password", "demo-password-1", "admin password")
	version  = flag.String("version", "0.142.0", "release the up-to-date resolvers report")
	behind   = flag.String("behind", "0.141.3", "release office-dns2 reports (shows as needing an update)")
	perDay   = flag.Int("queries", 27000, "queries across all resolvers over the last 24 hours")
	follow   = flag.Bool("follow", false, "keep the resolvers online and send live traffic until interrupted")
	seed     = flag.Int64("seed", 7, "random seed, for repeatable data")
	state    = flag.String("state", "demo-state.json", "where the resolvers' identities are kept between runs")
	dbPath   = flag.String("db", "", "the control plane's SQLite file, to add classifier verdicts (optional; see verdicts)")
)

type site struct{ name, desc string }

var sites = []site{
	{"cloud", "Hetzner, Falkenstein"},
	{"home", "Home network, Como"},
	{"office", "Office, Milan"},
}

// resolver is one simulated resolver and the clients that use it.
type resolver struct {
	name, site, role, addr string
	weight                 float64 // share of the traffic
	clients                []client

	id, key, cfgVersion, app string
	stats                    map[string]int64
}

type client struct{ ip, name string }

var resolvers = []*resolver{
	{name: "cloud-dns1", site: "cloud", role: "primary", addr: "10.99.0.2", weight: 0.17, clients: []client{
		{"10.99.1.10", "web-1"}, {"10.99.1.11", "web-2"}, {"10.99.1.20", "db-1"}, {"10.99.1.30", "ci-runner"},
	}},
	{name: "home-dns1", site: "home", role: "primary", addr: "192.168.1.2", weight: 0.33, clients: []client{
		{"192.168.1.10", "laptop-sara"}, {"192.168.1.11", "phone-sara"}, {"192.168.1.12", "tv-living"},
		{"192.168.1.13", "nas"}, {"192.168.1.20", "phone-marco"}, {"192.168.1.21", "tablet-kids"},
		{"192.168.1.30", "thermostat"},
	}},
	{name: "office-dns1", site: "office", role: "primary", addr: "10.20.0.2", weight: 0.32, clients: []client{
		{"10.20.1.10", "ws-giulia"}, {"10.20.1.11", "ws-luca"}, {"10.20.1.12", "ws-elena"},
		{"10.20.1.13", "meeting-room"}, {"10.20.1.50", "printer"}, {"10.20.1.60", "voip-gw"},
	}},
	{name: "office-dns2", site: "office", role: "secondary", addr: "10.20.0.3", weight: 0.18, clients: []client{
		{"10.20.1.14", "ws-paolo"}, {"10.20.1.15", "ws-marta"}, {"10.20.1.51", "scanner"},
	}},
}

// domain is a name clients look up, and what normally happens to it.
type domain struct {
	name   string
	weight float64
	kind   string // forward | blocked | local | suspicious
	reason string // block reason (the list's category) for blocked names
}

var domains = []domain{
	{"www.google.com", 9, "forward", ""}, {"apis.google.com", 3, "forward", ""}, {"www.youtube.com", 4, "forward", ""},
	{"i.ytimg.com", 3, "forward", ""}, {"github.com", 4, "forward", ""}, {"api.github.com", 3, "forward", ""},
	{"objects.githubusercontent.com", 2, "forward", ""}, {"www.apple.com", 2, "forward", ""},
	{"gateway.icloud.com", 3, "forward", ""}, {"time.apple.com", 2, "forward", ""}, {"login.microsoftonline.com", 3, "forward", ""},
	{"outlook.office365.com", 4, "forward", ""}, {"teams.microsoft.com", 3, "forward", ""}, {"slack.com", 2, "forward", ""},
	{"edge.slack.com", 2, "forward", ""}, {"zoom.us", 1, "forward", ""}, {"www.netflix.com", 2, "forward", ""},
	{"nflxvideo.net", 2, "forward", ""}, {"open.spotify.com", 2, "forward", ""}, {"web.whatsapp.com", 2, "forward", ""},
	{"mmg.whatsapp.net", 2, "forward", ""}, {"www.wikipedia.org", 1, "forward", ""}, {"registry-1.docker.io", 2, "forward", ""},
	{"production.cloudflare.docker.com", 2, "forward", ""}, {"archive.ubuntu.com", 2, "forward", ""},
	{"security.ubuntu.com", 1, "forward", ""}, {"proxy.golang.org", 2, "forward", ""}, {"registry.npmjs.org", 2, "forward", ""},
	{"s3.eu-central-1.amazonaws.com", 2, "forward", ""}, {"www.amazon.it", 1, "forward", ""}, {"www.corriere.it", 1, "forward", ""},
	{"www.repubblica.it", 1, "forward", ""}, {"pool.ntp.org", 2, "forward", ""}, {"connectivitycheck.gstatic.com", 2, "forward", ""},
	{"www.instagram.com", 2, "forward", ""}, {"graph.facebook.com", 2, "forward", ""}, {"www.tiktok.com", 1, "forward", ""},
	{"store.steampowered.com", 1, "forward", ""}, {"www.reddit.com", 1, "forward", ""}, {"news.ycombinator.com", 1, "forward", ""},

	{"doubleclick.net", 3, "blocked", "ads"}, {"googleads.g.doubleclick.net", 3, "blocked", "ads"},
	{"pagead2.googlesyndication.com", 2, "blocked", "ads"}, {"app-measurement.com", 2, "blocked", "ads"},
	{"sb.scorecardresearch.com", 1, "blocked", "ads"}, {"ads.yahoo.com", 1, "blocked", "ads"},
	{"telemetry.tv-vendor.example", 1, "blocked", "ads"}, {"browser.events.data.msn.com", 1, "blocked", "ads"},

	{"nas.home.lan", 2, "local", ""}, {"printer.office.lan", 1, "local", ""}, {"git.corp.internal", 2, "local", ""},
	{"grafana.corp.internal", 1, "local", ""},

	// Names that look like phishing or malware, for the classifier to flag.
	{"secure-paypa1-login.com", 0.15, "suspicious", ""}, {"free-gift-claim.xyz", 0.1, "suspicious", ""},
	{"cdn-update-check.top", 0.12, "suspicious", ""}, {"account-verify-icloud.info", 0.08, "suspicious", ""},
}

var blocklist = []string{
	"doubleclick.net", "googleads.g.doubleclick.net", "pagead2.googlesyndication.com", "app-measurement.com",
	"sb.scorecardresearch.com", "ads.yahoo.com", "telemetry.tv-vendor.example", "browser.events.data.msn.com",
}

type rewrite struct{ domain, rtype, value, scope, scopeValue string }

var rewrites = []rewrite{
	{"nas.home.lan", "A", "192.168.1.13", "sites", "home"},
	{"printer.office.lan", "A", "10.20.1.50", "sites", "office"},
	{"git.corp.internal", "A", "10.99.1.40", "all", ""},
	{"grafana.corp.internal", "A", "10.99.1.41", "all", ""},
	{"vpn.corp.internal", "CNAME", "office-gw.corp.internal", "all", ""},
}

var upstreams = []string{"tls://1.1.1.1:853#cloudflare-dns.com", "tls://9.9.9.9:853#dns.quad9.net"}

// api is a signed-in admin session.
type api struct{ c *http.Client }

func (a api) do(method, path string, in, out any) error {
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, strings.TrimRight(*cpURL, "/")+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s %s: %s %s", method, path, resp.Status, e.Error)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	rng := rand.New(rand.NewSource(*seed))
	jar, _ := cookiejar.New(nil)
	a := api{c: &http.Client{Jar: jar, Timeout: 2 * time.Minute}}

	must(signIn(a), "sign in")
	if loadState() {
		// A second run (e.g. with -follow): the demo is there already.
		log.Printf("reusing the resolvers in %s", *state)
	} else {
		must(configure(a), "configure")
		must(enrollAll(a), "enroll resolvers")
		for _, r := range resolvers {
			must(poll(r), "first poll of "+r.name)
		}
		must(history(rng), "query history")
		for _, r := range resolvers {
			must(procLogs(r, rng), "process logs of "+r.name)
			must(poll(r), "poll "+r.name)
		}
		must(saveState(), "save state")
	}
	if *dbPath != "" {
		must(verdicts(*dbPath), "classifier verdicts")
	}
	log.Printf("demo ready: sign in at %s as %s / %s", *cpURL, *user, *password)
	if *follow {
		live(rng)
	}
}

// savedResolver is what a resolver keeps on disk: its identity and key.
type savedResolver struct {
	ID, Key, App string
	Stats        map[string]int64 // counters since "boot", as resolvers report them
}

func saveState() error {
	out := map[string]savedResolver{}
	for _, r := range resolvers {
		out[r.name] = savedResolver{r.id, r.key, r.app, r.stats}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*state, b, 0o600)
}

// loadState restores the resolvers from an earlier run, if there was one.
func loadState() bool {
	b, err := os.ReadFile(*state)
	if err != nil {
		return false
	}
	var in map[string]savedResolver
	if json.Unmarshal(b, &in) != nil {
		return false
	}
	for _, r := range resolvers {
		sv, ok := in[r.name]
		if !ok {
			return false
		}
		r.id, r.key, r.app, r.stats = sv.ID, sv.Key, sv.App, sv.Stats
		if r.stats == nil {
			// A state file from before counters were kept: estimate a day's.
			n := int64(float64(*perDay) * r.weight)
			r.stats = map[string]int64{"total": n, "cached": n * 43 / 100, "forwarded": n * 39 / 100,
				"blocked": n * 12 / 100, "rewritten": n * 5 / 100, "errors": n / 200}
		}
	}
	return true
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}

// signIn completes first-boot setup with the demo admin, or signs in when the
// control plane is already set up.
func signIn(a api) error {
	var st struct {
		Active bool `json:"setup_required"`
	}
	if err := a.do("GET", "/api/setup/status", nil, &st); err != nil {
		return err
	}
	if st.Active {
		return a.do("POST", "/api/setup/complete", map[string]any{"method": "local", "username": *user, "password": *password}, nil)
	}
	return a.do("POST", "/api/auth/login", map[string]string{"username": *user, "password": *password}, nil)
}

// configure sets up what the screenshots show around the resolvers: upstreams,
// sites, local records, a blocklist and client names. Everything already there
// (a second run) is left alone.
func configure(a api) error {
	var settings map[string]any
	if err := a.do("GET", "/api/settings", nil, &settings); err != nil {
		return err
	}
	settings["upstreams"] = upstreams
	if err := a.do("PUT", "/api/settings", settings, nil); err != nil {
		return err
	}
	for _, s := range sites {
		if err := a.do("POST", "/api/cluster/sites", map[string]string{"name": s.name, "description": s.desc}, nil); err != nil && !exists(err) {
			return err
		}
	}
	var have []struct {
		Domain string `json:"domain"`
	}
	if err := a.do("GET", "/api/rewrites", nil, &have); err != nil {
		return err
	}
	known := map[string]bool{}
	for _, h := range have {
		known[h.Domain] = true
	}
	for _, rw := range rewrites {
		if known[rw.domain] {
			continue
		}
		scope := []string{}
		if rw.scopeValue != "" {
			scope = append(scope, rw.scopeValue)
		}
		if err := a.do("POST", "/api/rewrites", map[string]any{
			"domain": rw.domain, "rrtype": rw.rtype, "value": rw.value, "scope_type": rw.scope, "scope_values": scope,
		}, nil); err != nil {
			return err
		}
	}
	var lists []struct {
		Name string `json:"name"`
	}
	if err := a.do("GET", "/api/lists", nil, &lists); err != nil {
		return err
	}
	hasList := false
	for _, l := range lists {
		hasList = hasList || l.Name == "Ads & trackers"
	}
	if !hasList {
		if err := a.do("POST", "/api/lists/import", map[string]string{
			"name": "Ads & trackers", "category": "ads", "text": strings.Join(blocklist, "\n"), "source": "paste",
		}, nil); err != nil {
			return err
		}
	}
	for _, r := range resolvers {
		for _, c := range r.clients {
			if err := a.do("PUT", "/api/clients/name", map[string]string{"client": c.ip, "name": c.name}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func exists(err error) bool {
	return strings.Contains(err.Error(), "409") || strings.Contains(strings.ToLower(err.Error()), "exist")
}

// enrollAll enrolls the four resolvers with one enrollment key and places
// them in their sites.
func enrollAll(a api) error {
	var key struct {
		Key string `json:"key"`
	}
	if err := a.do("POST", "/api/cluster/enroll-keys", map[string]any{"name": "demo", "ttl_hours": 1, "max_uses": len(resolvers)}, &key); err != nil {
		return err
	}
	for _, r := range resolvers {
		res, err := cluster.Enroll(context.Background(), http.DefaultClient, *cpURL, r.name, key.Key, "", "", false)
		if err != nil {
			return fmt.Errorf("%s: %w", r.name, err)
		}
		r.id, r.key = res.ID, res.Key
		r.app = *version
		if r.name == "office-dns2" {
			r.app = *behind
		}
		r.stats = map[string]int64{}
		if err := a.do("PUT", "/api/cluster/nodes/"+r.id+"/site", map[string]string{"site": r.site, "role": r.role}, nil); err != nil {
			return err
		}
	}
	return nil
}

// nodeReq is a request authenticated as resolver r.
func nodeReq(r *resolver, method, path string, body any) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, strings.TrimRight(*cpURL, "/")+path, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.key)
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}

// poll pulls the config as r does, reporting its build, the config version it
// applied (so it shows in sync), its address and its counters.
func poll(r *resolver) error {
	var buf bytes.Buffer
	req, err := http.NewRequest("GET", strings.TrimRight(*cpURL, "/")+"/api/cluster/snapshot", &buf)
	if err != nil {
		return err
	}
	stats, _ := json.Marshal(r.stats)
	req.Header.Set("Authorization", "Bearer "+r.key)
	req.Header.Set(cluster.HeaderNodeVersion, r.cfgVersion)
	req.Header.Set("X-MazeDNS-App-Version", r.app)
	req.Header.Set("X-MazeDNS-Advertise-Addr", r.addr)
	req.Header.Set("X-MazeDNS-Stats", string(stats))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("snapshot: %s", resp.Status)
	}
	var snap struct {
		Version    string `json:"version"`
		NewNodeKey string `json:"new_node_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return err
	}
	if snap.NewNodeKey != "" {
		r.key = snap.NewNodeKey
	}
	if snap.Version != "" && snap.Version != r.cfgVersion {
		// Report the applied version on the next poll, as a resolver does
		// after applying a snapshot.
		r.cfgVersion = snap.Version
		return poll(r)
	}
	return nil
}

// diurnal is the relative traffic at hour h (local time of the demo): quiet at
// night, a morning ramp, a working-day plateau and an evening peak.
func diurnal(h float64) float64 {
	return 0.15 + 0.55*math.Exp(-math.Pow((h-11)/3.2, 2)) + 0.8*math.Exp(-math.Pow((h-20.5)/2.4, 2))
}

func pick[T any](rng *rand.Rand, items []T, weight func(T) float64) T {
	total := 0.0
	for _, it := range items {
		total += weight(it)
	}
	x := rng.Float64() * total
	for _, it := range items {
		if x -= weight(it); x <= 0 {
			return it
		}
	}
	return items[len(items)-1]
}

// query makes one query log entry at t on resolver r.
func query(rng *rand.Rand, r *resolver, t time.Time) map[string]any {
	c := r.clients[rng.Intn(len(r.clients))]
	d := pick(rng, domains, func(d domain) float64 {
		// Local names only resolve on their own site.
		if d.kind == "local" && !strings.Contains(d.name, r.site) && !strings.HasSuffix(d.name, ".corp.internal") {
			return 0
		}
		return d.weight
	})
	qtype := "A"
	switch x := rng.Float64(); {
	case x < 0.33:
		qtype = "AAAA"
	case x < 0.40:
		qtype = "HTTPS"
	}
	e := map[string]any{
		"ts": t.UnixMilli(), "client": c.ip, "name": d.name, "qtype": qtype, "node": r.name, "rcode": "NOERROR",
	}
	switch {
	case d.kind == "blocked":
		e["action"], e["category"], e["rcode"], e["elapsed_ms"] = "blocked", d.reason, "NXDOMAIN", 0.05+rng.Float64()*0.1
	case d.kind == "local":
		e["action"], e["elapsed_ms"] = "rewrite", 0.04+rng.Float64()*0.08
	case rng.Float64() < 0.52:
		e["action"], e["elapsed_ms"] = "cache", 0.05+rng.Float64()*0.15
	case rng.Float64() < 0.012:
		e["action"], e["rcode"], e["elapsed_ms"] = "error", "SERVFAIL", 1500+rng.Float64()*800
	default:
		up := upstreams[0]
		if rng.Float64() < 0.2 {
			up = upstreams[1]
		}
		// Round trips by where the resolver is: the cloud one sits next to
		// the upstreams, the office pair behind a slower line.
		base := map[string]float64{"cloud": 2.5, "home": 9, "office": 13}[r.site]
		e["action"], e["upstream"], e["elapsed_ms"] = "forward", up, base+rng.ExpFloat64()*base*0.8
	}
	if d.kind == "suspicious" && e["action"] == "cache" {
		e["action"], e["upstream"], e["elapsed_ms"] = "forward", upstreams[0], 20+rng.Float64()*30
	}
	switch e["action"] {
	case "blocked":
		r.stats["blocked"]++
	case "cache":
		r.stats["cached"]++
	case "forward":
		r.stats["forwarded"]++
	case "rewrite":
		r.stats["rewritten"]++
	case "error":
		r.stats["errors"]++
	}
	r.stats["total"]++
	return e
}

// history ships a day of queries, spread over the last 24 hours by the diurnal
// curve, in time order per resolver.
func history(rng *rand.Rand) error {
	now := time.Now()
	start := now.Add(-24 * time.Hour)
	// Weight each minute by the curve, then draw query times from it.
	minutes := make([]float64, 24*60)
	total := 0.0
	for i := range minutes {
		t := start.Add(time.Duration(i) * time.Minute)
		minutes[i] = diurnal(float64(t.Hour()) + float64(t.Minute())/60)
		total += minutes[i]
	}
	for _, r := range resolvers {
		n := int(float64(*perDay) * r.weight)
		times := make([]time.Time, 0, n)
		for i, w := range minutes {
			k := int(math.Round(float64(n) * w / total * (0.85 + 0.3*rng.Float64())))
			for j := 0; j < k; j++ {
				times = append(times, start.Add(time.Duration(i)*time.Minute+time.Duration(rng.Int63n(int64(time.Minute)))))
			}
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		batch := make([]map[string]any, 0, 2000)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			resp, err := nodeReq(r, "POST", "/api/cluster/log", batch)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("log: %s", resp.Status)
			}
			batch = batch[:0]
			return nil
		}
		for _, t := range times {
			batch = append(batch, query(rng, r, t))
			if len(batch) == cap(batch) {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		if err := flush(); err != nil {
			return err
		}
		log.Printf("%s: %d queries", r.name, len(times))
	}
	return nil
}

// procLogs ships the kind of process log a resolver keeps, for the Logs page.
func procLogs(r *resolver, rng *rand.Rand) error {
	now := time.Now()
	lines := []struct{ level, msg string }{
		{"info", fmt.Sprintf("MazeDNS resolver starting version=%s", r.app)},
		{"info", fmt.Sprintf("settings applied upstreams=%d forwarders=0 strategy=ordered upstream_timeout=1.5s block=nxdomain cache=true", len(upstreams))},
		{"info", "policy reloaded blocked=8 allowed=0 rewrites=5"},
		{"info", "MazeDNS DNS starting addr=0.0.0.0:53 cache=true filter=true"},
		{"info", "listener up net=udp addr=0.0.0.0:53 sockets=4"},
		{"info", "listener up net=tcp addr=0.0.0.0:53"},
		{"info", "cluster sync started interval=30s"},
		{"info", "category database loaded categories=3 domains=41872"},
	}
	if r.name == "office-dns2" {
		lines = append(lines, struct{ level, msg string }{"warn", "forward failed upstream=tls://9.9.9.9:853#dns.quad9.net err=\"i/o timeout\" retry=next"})
	}
	if r.site == "home" && r.cfgVersion != "" {
		lines = append(lines, struct{ level, msg string }{"info", "config applied version=" + r.cfgVersion[:min(12, len(r.cfgVersion))]})
	}
	entries := make([]map[string]any, len(lines))
	for i, l := range lines {
		ts := now.Add(-time.Duration(len(lines)-i) * time.Duration(30+rng.Intn(90)) * time.Second)
		entries[i] = map[string]any{"seq": i + 1, "ts": ts.UnixMilli(), "level": l.level, "msg": l.msg}
	}
	resp, err := nodeReq(r, "POST", "/api/cluster/proclog", map[string]any{"boot_id": "demo-" + r.name, "entries": entries})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("proclog: %s", resp.Status)
	}
	return nil
}

// live keeps the resolvers polling and sends a few queries every interval,
// until interrupted.
func live(rng *rand.Rand) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	log.Print("following: resolvers stay online; Ctrl-C to stop")
	// Process logs live in the control plane's memory: send them again in case
	// it restarted (it drops lines it already has).
	for _, r := range resolvers {
		_ = poll(r) // learn the config version the log mentions
		if err := procLogs(r, rng); err != nil {
			log.Printf("%s: %v", r.name, err)
		}
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		for _, r := range resolvers {
			n := 2 + int(r.weight*float64(*perDay)/24/60/4*diurnal(float64(time.Now().Hour())))
			batch := make([]map[string]any, n)
			for i := range batch {
				batch[i] = query(rng, r, time.Now().Add(-time.Duration(rng.Intn(15000))*time.Millisecond))
			}
			if resp, err := nodeReq(r, "POST", "/api/cluster/log", batch); err == nil {
				resp.Body.Close()
			}
			if err := poll(r); err != nil {
				log.Printf("%s: %v", r.name, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// verdicts writes classifier verdicts for the demo's phishing-style names. The
// classifier itself rates them harmless: they don't exist, so it finds no
// registration, DNS or reputation evidence, only the name. These rows carry the
// factors it reports for such names when they do exist, so the Review list has
// something to show. It is the one part of the demo not made by the real code.
func verdicts(path string) error {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	type f struct {
		Label  string `json:"label"`
		Detail string `json:"detail"`
		Delta  int    `json:"delta"`
	}
	for _, v := range []struct {
		domain, category, reason string
		score                    int
		factors                  []f
	}{
		{"secure-paypa1-login.com", "phishing", "Imitates PayPal with a look-alike digit in a days-old domain.", 14, []f{
			{"Lexical: look-alike", `imitates "paypal" via look-alike characters`, -28},
			{"Domain age", "registered 6 days ago — very new", -45},
			{"Lexical: hyphens", "2 hyphens — common in look-alike domains", -8},
		}},
		{"account-verify-icloud.info", "phishing", "Uses the iCloud brand in a new, unrelated domain.", 21, []f{
			{"Lexical: brand in name", `contains the brand "icloud" with extra text — possible look-alike`, -22},
			{"Domain age", "registered 19 days ago — new", -28},
			{"Lexical: hyphens", "2 hyphens — common in look-alike domains", -8},
		}},
		{"cdn-update-check.top", "malware", "A new domain posing as an update check, queried at fixed intervals.", 30, []f{
			{"Domain age", "registered 41 days ago", -15},
			{"Lexical: hyphens", "2 hyphens — common in look-alike domains", -8},
			{"Threat intel", "listed by a malware-distribution feed", -40},
		}},
		{"free-gift-claim.xyz", "phishing", "Prize-scam wording in a recently registered domain.", 33, []f{
			{"Domain age", "registered 27 days ago — new", -28},
			{"Lexical: hyphens", "2 hyphens — common in look-alike domains", -8},
		}},
	} {
		fs, _ := json.Marshal(v.factors)
		threat := 0
		for _, x := range v.factors {
			if x.Label == "Threat intel" {
				threat = 1
			}
		}
		if _, err := db.Exec(`INSERT INTO classifications(domain, category, block, status, confidence, score, factors, reason, model, threat, updated_at)
			VALUES(?,?,1,'suggested',0.9,?,?,?,'',?,?)
			ON CONFLICT(domain) DO UPDATE SET category=excluded.category, block=1, status='suggested', confidence=0.9,
			  score=excluded.score, factors=excluded.factors, reason=excluded.reason, threat=excluded.threat, updated_at=excluded.updated_at`,
			v.domain, v.category, v.score, string(fs), v.reason, threat, time.Now().Add(-time.Duration(len(v.domain))*time.Minute).UnixMilli()); err != nil {
			return err
		}
	}
	return nil
}
