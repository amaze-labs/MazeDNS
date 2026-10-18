package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/classifier"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

func newCategoryServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var b categories.Builder
	b.Add("facebook.com", "social")
	cz := classifier.NewCategorizer(st, categories.NewLoadedHolder(b.Build()))
	_ = cz.Refresh()
	return &Server{store: st, res: resolver.New(resolver.Options{}), categorizer: cz}, st
}

func call(t *testing.T, h http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(method, target, strings.NewReader(body)))
	return rr
}

// Blocked categories are set through their own endpoint, validated, and kept
// when a settings save doesn't mention them.
func TestBlockedCategories(t *testing.T) {
	s, st := newCategoryServer(t)
	if err := st.SaveSettings(`{"upstreams":["192.0.2.1:53"]}`); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"categories":["other"]}`, `{"categories":["nope"]}`} {
		if rr := call(t, s.putBlockedCategories, http.MethodPut, "/", bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400", bad, rr.Code)
		}
	}
	rr := call(t, s.putBlockedCategories, http.MethodPut, "/", `{"categories":["social","adult","adult"]}`)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	if got := strings.Join(s.blockedCategories(), ","); got != "adult,social" { // de-duplicated, taxonomy order
		t.Fatalf("blocked = %q", got)
	}

	// A settings save from a UI that doesn't know the field keeps them…
	if rr := call(t, s.putSettings, http.MethodPut, "/", `{"upstreams":["192.0.2.9:53"]}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	if got := strings.Join(s.blockedCategories(), ","); got != "adult,social" {
		t.Errorf("after a settings save without the field: %q", got)
	}
	// …and one that sends them sets them.
	if rr := call(t, s.putSettings, http.MethodPut, "/", `{"upstreams":["192.0.2.9:53"],"blocked_categories":[]}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	if got := s.blockedCategories(); len(got) != 0 {
		t.Errorf("after clearing: %v", got)
	}

	rr = call(t, s.getCategoryList, http.MethodGet, "/", "")
	var list struct {
		Categories []categoryInfo `json:"categories"`
		Enabled    bool           `json:"enabled"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil || !list.Enabled || len(list.Categories) != len(categories.All) {
		t.Fatalf("list = %s (err %v)", rr.Body.String(), err)
	}
	for _, c := range list.Categories {
		if c.ID == "social" && c.Domains != 1 {
			t.Errorf("social domains = %d, want 1", c.Domains)
		}
	}
}

func TestCategoryOverrideAPI(t *testing.T) {
	s, _ := newCategoryServer(t)
	get := func(domain string) map[string]any {
		rr := call(t, s.getDomainCategory, http.MethodGet, "/?domain="+domain, "")
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out
	}
	if got := get("www.facebook.com"); got["category"] != "social" || got["source"] != classifier.SourceDatabase || got["domain"] != "facebook.com" {
		t.Fatalf("before override: %v", got)
	}
	if rr := call(t, s.putCategoryOverride, http.MethodPut, "/", `{"domain":"www.facebook.com","category":"nope"}`); rr.Code != http.StatusBadRequest {
		t.Errorf("unknown category: code %d", rr.Code)
	}
	if rr := call(t, s.putCategoryOverride, http.MethodPut, "/", `{"domain":"www.facebook.com","category":"chat"}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	got := get("facebook.com")
	if got["category"] != "chat" || got["source"] != classifier.SourceOverride || got["override"] == nil {
		t.Fatalf("after override: %v", got)
	}
	if rr := call(t, s.deleteCategoryOverride, http.MethodDelete, "/?domain=facebook.com", ""); rr.Code != http.StatusNoContent {
		t.Fatal(rr.Body.String())
	}
	if got := get("facebook.com"); got["category"] != "social" {
		t.Errorf("after delete: %v", got)
	}
}

// Agents get the per-domain corrections for the blocked categories with the
// replicated settings: every override, and model labels in blocked categories
// for domains the database doesn't know. They are never stored.
func TestReplicatedSettingsCarryCategoryDomains(t *testing.T) {
	s, st := newCategoryServer(t) // the database knows facebook.com (social)
	if err := st.SaveSettings(`{"upstreams":["192.0.2.1:53"],"blocked_categories":["gambling"]}`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []store.Classification{
		{Domain: "bet.example", Category: "other", Status: store.ClassClean, ContentCategory: "gambling", ContentChecked: true},
		{Domain: "news.example", Category: "other", Status: store.ClassClean, ContentCategory: "news", ContentChecked: true},
		{Domain: "facebook.com", Category: "other", Status: store.ClassClean, ContentCategory: "gambling", ContentChecked: true},
	} {
		if _, err := st.InsertClassification(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetCategoryOverride("casino-blog.example", "news", "alice"); err != nil {
		t.Fatal(err)
	}
	_ = s.categorizer.Refresh()

	raw, err := s.replicatedSettings()
	if err != nil {
		t.Fatal(err)
	}
	var set resolver.Settings
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"bet.example": "gambling", "casino-blog.example": "news"}
	if len(set.CategoryDomains) != len(want) {
		t.Fatalf("category_domains = %v, want %v", set.CategoryDomains, want)
	}
	for d, c := range want {
		if set.CategoryDomains[d] != c {
			t.Errorf("%s = %q, want %q", d, set.CategoryDomains[d], c)
		}
	}
	stored, _ := st.GetSettings()
	if strings.Contains(stored, "category_domains") {
		t.Errorf("category_domains was stored: %s", stored)
	}
}

// When the VictoriaMetrics export is on, agents learn only that (and how
// often): they relay their metrics through the control plane, so the URL and
// credentials never leave it.
func TestReplicatedSettingsCarryMetricsRelay(t *testing.T) {
	s, st := newCategoryServer(t)
	if err := st.SaveSettings(`{"upstreams":["192.0.2.1:53"]}`); err != nil {
		t.Fatal(err)
	}
	decode := func() (map[string]json.RawMessage, string) {
		raw, err := s.replicatedSettings()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m, string(raw)
	}
	if m, _ := decode(); m["metrics_export"] != nil {
		t.Error("metrics_export sent while the export is off")
	}
	if err := st.SaveVMExport(store.VMExport{Enabled: true, URL: "http://vm:8428", IntervalSec: 15, Username: "u", Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	m, raw := decode()
	if got := string(m["metrics_export"]); got != `{"enabled":true,"interval_sec":15}` {
		t.Errorf("metrics_export = %s", got)
	}
	if strings.Contains(raw, "secret") || strings.Contains(raw, "vm:8428") {
		t.Error("the VictoriaMetrics URL or password reached the replicated settings")
	}
}

// An agent's relayed metrics are forwarded with the control plane's
// credentials, labelled with the agent's authenticated name — never a name the
// agent picks. Without a valid key, or with the export off, nothing is sent.
func TestClusterMetricsRelay(t *testing.T) {
	s, st := newCategoryServer(t)
	var got struct {
		path, user, pass, body string
		calls                  int
	}
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.calls++
		got.path = r.URL.RequestURI()
		got.user, got.pass, _ = r.BasicAuth()
		b, _ := io.ReadAll(r.Body)
		got.body = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer vm.Close()

	const key = "node-key-for-test"
	if err := st.CreateNodeWithID("node-1", "oci-dns03", hashKey(key), keyPrefix(key), true); err != nil {
		t.Fatal(err)
	}
	post := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/cluster/metrics", strings.NewReader("mazedns_queries_total{action=\"forward\"} 42\n"))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rr := httptest.NewRecorder()
		s.clusterMetrics(rr, req)
		return rr
	}

	if rr := post(key); rr.Code != http.StatusConflict || got.calls != 0 {
		t.Fatalf("export off: code %d, %d forwarded", rr.Code, got.calls)
	}
	if err := st.SaveVMExport(store.VMExport{Enabled: true, URL: vm.URL, Job: "mazedns", Instance: "control", Username: "u", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "wrong-key"} {
		if rr := post(bad); rr.Code != http.StatusUnauthorized {
			t.Errorf("key %q: code %d, want 401", bad, rr.Code)
		}
	}
	if got.calls != 0 {
		t.Fatalf("forwarded without a valid key")
	}
	if rr := post(key); rr.Code != http.StatusNoContent {
		t.Fatalf("code %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(got.path, "instance%3Doci-dns03") || !strings.Contains(got.path, "job%3Dmazedns") || strings.Contains(got.path, "control") {
		t.Errorf("forwarded to %s, want instance=oci-dns03 (not the control plane's)", got.path)
	}
	if got.user != "u" || got.pass != "pw" || !strings.Contains(got.body, "mazedns_queries_total") {
		t.Errorf("forwarded auth %s:%s body %q", got.user, got.pass, got.body)
	}
}
