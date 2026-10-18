package classifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// fakeModel is an OpenAI-compatible endpoint that answers each domain with the
// category in answers (default "other") and counts calls; it also serves the
// trusted list at /trusted.txt.
func fakeModel(t *testing.T, answers map[string]string, trusted ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/trusted.txt" {
			_, _ = io.WriteString(w, strings.Join(trusted, "\n")+"\n")
			return
		}
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		cat := "other"
		for d, c := range answers {
			if strings.Contains(string(body), d) {
				cat = c
			}
		}
		verdict, _ := json.Marshal(map[string]any{"category": cat, "confidence": 0.9, "reason": "test"})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": string(verdict)}}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func contentWorker(t *testing.T, srv *httptest.Server, db *categories.Holder) (*Worker, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	set := Settings{
		Enabled: true, Mode: string(ModeSuggest), AIEnabled: true, Endpoint: srv.URL, Model: "test",
		TrustedDisableDefault: true, TrustedListURL: srv.URL + "/trusted.txt", ThreatFeeds: []string{},
	}
	w := NewWorker(st, func() Settings { return set }, nil)
	if db != nil {
		w.SetCategoryDB(db)
	}
	return w, st
}

func verdictOf(t *testing.T, st *store.Store, domain string) store.Classification {
	t.Helper()
	items, err := st.ListClassifications("", domain, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range items {
		if c.Domain == domain {
			return c
		}
	}
	t.Fatalf("no verdict for %s", domain)
	return store.Classification{}
}

func TestWorkerLabelsContent(t *testing.T) {
	var b categories.Builder
	b.Add("facebook.com", "social")
	db := categories.NewLoadedHolder(b.Build())
	srv, calls := fakeModel(t, map[string]string{"google.com": "search", "newsite.example": "news", "phish.example": "phishing"},
		"google.com", "facebook.com")
	w, st := contentWorker(t, srv, db)
	ctx := context.Background()

	// A trusted domain the database knows: no model call, nothing to ask later.
	w.process(ctx, "facebook.com")
	if n := calls.Load(); n != 0 {
		t.Fatalf("model called %d times for a domain the database knows", n)
	}
	if v := verdictOf(t, st, "facebook.com"); v.Category != "other" || !v.Trusted {
		t.Errorf("facebook.com verdict = %+v", v)
	}
	if left, _ := st.UncheckedContent(10); len(left) != 0 {
		t.Errorf("facebook.com left unasked: %v", left)
	}

	// A trusted domain the database doesn't know: the shortcut used to skip the
	// model entirely; now it asks what the domain is.
	w.process(ctx, "google.com")
	if v := verdictOf(t, st, "google.com"); v.Category != "other" || v.ContentCategory != "search" {
		t.Errorf("google.com verdict = %+v, want category other, content search", v)
	}

	// A scored domain: the model's content answer is the content category, and
	// the verdict category (which doesn't block) is "other".
	w.process(ctx, "newsite.example")
	if v := verdictOf(t, st, "newsite.example"); v.Category != "other" || v.ContentCategory != "news" || v.Block {
		t.Errorf("newsite.example verdict = %+v", v)
	}

	// A security answer: the verdict keeps it as the blocking reason (no
	// registration data here, so the model alone decides); no content label.
	w.process(ctx, "phish.example")
	if v := verdictOf(t, st, "phish.example"); v.ContentCategory != "" || (v.Block && v.Category != "phishing") {
		t.Errorf("phish.example verdict = %+v", v)
	}

	c := NewCategorizer(st, db)
	if err := c.Refresh(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"facebook.com": "social", "www.google.com": "search", "newsite.example": "news"} {
		if got, _ := c.Category(name); got != want {
			t.Errorf("Category(%s) = %q, want %q", name, got, want)
		}
	}
}

// Until the category database has loaded, "not in the database" means nothing:
// the model is not asked, and the domain stays for the backfill.
func TestWorkerWaitsForCategoryDB(t *testing.T) {
	notLoaded := categories.NewHolder(&categories.Source{AllURL: "http://127.0.0.1:1/never"}, true)
	srv, calls := fakeModel(t, nil, "google.com")
	w, st := contentWorker(t, srv, notLoaded)
	w.process(context.Background(), "google.com")
	if n := calls.Load(); n != 0 {
		t.Errorf("model called %d times before the database loaded", n)
	}
	if left, _ := st.UncheckedContent(10); len(left) != 1 {
		t.Errorf("unasked = %v, want google.com left for the backfill", left)
	}
}

// The backfill labels verdicts from before categories: database-known domains
// in bulk without the model, then one model call per tick.
func TestBackfillContent(t *testing.T) {
	var b categories.Builder
	b.Add("known1.example", "shopping")
	b.Add("known2.example", "news")
	db := categories.NewLoadedHolder(b.Build())
	srv, calls := fakeModel(t, map[string]string{"unknown1.example": "gaming", "unknown2.example": "sports"})
	w, st := contentWorker(t, srv, db)
	for _, d := range []string{"known1.example", "known2.example", "unknown1.example", "unknown2.example"} {
		if _, err := st.InsertClassification(store.Classification{Domain: d, Category: "other", Status: store.ClassClean}); err != nil {
			t.Fatal(err)
		}
	}
	w.backfillContent(context.Background())
	if n := calls.Load(); n != 1 {
		t.Errorf("first tick: %d model calls, want 1", n)
	}
	w.backfillContent(context.Background())
	w.backfillContent(context.Background()) // nothing left: no call
	if n := calls.Load(); n != 2 {
		t.Errorf("after three ticks: %d model calls, want 2", n)
	}
	if left, _ := st.UncheckedContent(10); len(left) != 0 {
		t.Errorf("still unasked: %v", left)
	}
	for d, want := range map[string]string{"unknown1.example": "gaming", "unknown2.example": "sports", "known1.example": ""} {
		if v := verdictOf(t, st, d); v.ContentCategory != want {
			t.Errorf("%s content = %q, want %q", d, v.ContentCategory, want)
		}
	}
}
