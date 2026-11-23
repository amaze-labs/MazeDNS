package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/boot"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/resolver"
)

// testQueryServer is a server with a headless resolver (no upstreams: forwards
// fail fast), a node "home-1" at site "Home", and records scoped three ways.
func testQueryServer(t *testing.T) *Server {
	t.Helper()
	s, st := newSetupServer(t)
	s.testQueryLimit = userLimiter{limit: testQueryLimit, window: testQueryWindow}
	if err := st.CreateSite("Home", ""); err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateNode("home-1", "hash", "pfx")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeSite(id, "Home", "primary"); err != nil {
		t.Fatal(err)
	}
	for _, rw := range []struct{ domain, value, scope, on string }{
		{"everywhere.lan", "10.0.0.1", "all", ""},
		{"nas.home.lan", "10.0.0.5", "sites", "Home"},
		{"office.lan", "10.9.0.1", "sites", "Office"},
	} {
		var on []string
		if rw.on != "" {
			on = []string{rw.on}
		}
		if _, err := st.AddRewriteScoped(rw.domain, "A", rw.value, rw.scope, on); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.AddRule("deny", "ads.example", "ads"); err != nil {
		t.Fatal(err)
	}
	res := resolver.New(resolver.Options{Timeout: 200 * time.Millisecond})
	res.ApplySettings(resolver.Settings{Upstreams: []string{"127.0.0.1:1"}})
	p, err := boot.BuildPolicy(st, config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	res.SetPolicy(p)
	s.res = res
	return s
}

func runTestQuery(t *testing.T, s *Server, body string) (int, testQueryResponse) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.testQuery(rr, httptest.NewRequest(http.MethodPost, "/api/tools/resolve", strings.NewReader(body)))
	var out testQueryResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return rr.Code, out
}

// Issue #96: a record scoped to a site answers only when testing as that site
// or one of its resolvers; the answer says which record and its scope.
func TestTestQueryScopedRecords(t *testing.T) {
	s := testQueryServer(t)

	code, out := runTestQuery(t, s, `{"name":"nas.home.lan","node":"home-1"}`)
	if code != 200 || out.Decision != "rewrite" || out.Site != "Home" || out.RewriteScope != "sites" ||
		len(out.Answer.Answer) != 1 || !strings.Contains(out.Answer.Answer[0].Data, "10.0.0.5") {
		t.Fatalf("as home-1: %d %+v", code, out)
	}
	if _, out := runTestQuery(t, s, `{"name":"nas.home.lan","site":"Home"}`); out.Decision != "rewrite" {
		t.Fatalf("as site Home: %+v", out)
	}
	// Globally and from another site the scoped record does not apply.
	for _, body := range []string{`{"name":"nas.home.lan"}`, `{"name":"nas.home.lan","site":"Office"}`} {
		if _, out := runTestQuery(t, s, body); out.Decision == "rewrite" {
			t.Fatalf("%s: scoped record leaked: %+v", body, out)
		}
	}
	// PTR for an address a local A record points to: the reverse name is derived.
	if _, out := runTestQuery(t, s, `{"name":"10.0.0.1","type":"PTR"}`); out.Name != "1.0.0.10.in-addr.arpa" || out.Decision != "rewrite" {
		t.Fatalf("PTR by address: %+v", out)
	}
	if _, out := runTestQuery(t, s, `{"name":"everywhere.lan","site":"Office"}`); out.Decision != "rewrite" || out.RewriteScope != "all" {
		t.Fatalf("unscoped record: %+v", out)
	}
	// Blocked, with the category; forwarding failures carry the error.
	if _, out := runTestQuery(t, s, `{"name":"x.ads.example","type":"AAAA"}`); out.Decision != "blocked" || out.Category != "ads" || out.Type != "AAAA" {
		t.Fatalf("blocked: %+v", out)
	}
	if _, out := runTestQuery(t, s, `{"name":"example.com"}`); out.Decision != "error" || out.Error == "" || out.Answer.Rcode != "SERVFAIL" {
		t.Fatalf("forward error: %+v", out)
	}
}

func TestTestQueryValidation(t *testing.T) {
	s := testQueryServer(t)
	for body, want := range map[string]int{
		`{"name":""}`:                          400,
		`{"name":"bad..name"}`:                 400,
		`{"name":"example.com","type":"ANY"}`:  400,
		`{"name":"example.com","type":"NOPE"}`: 400,
		`{"name":"x.lan","node":"missing"}`:    404,
	} {
		if code, _ := runTestQuery(t, s, body); code != want {
			t.Errorf("%s: %d, want %d", body, code, want)
		}
	}
}

func TestTestQueryRateLimit(t *testing.T) {
	s := testQueryServer(t)
	s.testQueryLimit = userLimiter{limit: 2, window: time.Hour}
	for i := 0; i < 2; i++ {
		if code, _ := runTestQuery(t, s, `{"name":"x.ads.example"}`); code != 200 {
			t.Fatalf("query %d: %d", i, code)
		}
	}
	if code, _ := runTestQuery(t, s, `{"name":"x.ads.example"}`); code != http.StatusTooManyRequests {
		t.Fatalf("over limit: %d, want 429", code)
	}
}

// A domain in a blocked category only through a per-domain correction (an
// operator override) is blocked in a test as on the resolvers, which get the
// corrections with their settings: the control plane's own runtime has none.
func TestTestQueryCategoryCorrections(t *testing.T) {
	s, st := newCategoryServer(t)
	s.testQueryLimit = userLimiter{limit: testQueryLimit, window: testQueryWindow}
	if err := st.SaveSettings(`{"upstreams":["127.0.0.1:1"],"blocked_categories":["social"]}`); err != nil {
		t.Fatal(err)
	}
	set, _ := s.loadSettings()
	s.res.ApplySettings(set) // as on the control plane: no CategoryDomains
	raw, _ := s.replicatedSettings()
	var rep resolver.Settings
	_ = json.Unmarshal(raw, &rep)
	if rep.CategoryDomains["instagram.com"] != "social" {
		t.Skip("instagram.com is not a built-in social correction any more")
	}
	if _, out := runTestQuery(t, s, `{"name":"www.instagram.com"}`); out.Decision != "blocked" || out.Category != "social" || !out.CategoryBlock {
		t.Fatalf("corrected domain: %+v", out)
	}
}
