package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/classifier"
	"github.com/IPMaze/MazeDNS/internal/store"
)

type fakeCls struct {
	lookups  int
	excluded map[string]bool
}

func (f *fakeCls) TrustedCount() int                  { return 0 }
func (f *fakeCls) ThreatCount() int                   { return 0 }
func (f *fakeCls) TrustedSearch(string, int) []string { return nil }
func (f *fakeCls) ThreatSearch(string, int) []string  { return nil }
func (f *fakeCls) Excluded(name string) bool          { return f.excluded[name] }
func (f *fakeCls) Whois(context.Context, string) (classifier.WhoisInfo, error) {
	f.lookups++
	return classifier.WhoisInfo{Domain: "x"}, nil
}

// Opening a domain's details looks it up only with lookups and WHOIS on, and
// never for a domain kept private.
func TestWhoisOnDemandRespectsSettings(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fakeCls{excluded: map[string]bool{"corp.example.org": true}}
	s := &Server{store: st, cls: f}
	ask := func(domain string) map[string]any {
		rr := httptest.NewRecorder()
		s.getWhois(rr, httptest.NewRequest("GET", "/api/classifier/whois?domain="+domain, nil))
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out
	}

	for _, set := range []classifier.Settings{{Enabled: false, WhoisEnabled: true}, {Enabled: true, WhoisEnabled: false}} {
		_ = classifier.SaveSettings(st, set)
		if out := ask("example.com"); out["ok"] != false || out["off"] != true {
			t.Errorf("settings %+v: %v", set, out)
		}
	}
	_ = classifier.SaveSettings(st, classifier.Settings{Enabled: true, WhoisEnabled: true})
	if out := ask("corp.example.org"); out["off"] != true {
		t.Errorf("kept-private domain: %v", out)
	}
	if f.lookups != 0 {
		t.Fatalf("looked up %d times while it shouldn't have", f.lookups)
	}
	if out := ask("example.com"); out["ok"] != true || f.lookups != 1 {
		t.Errorf("allowed lookup: %v, %d lookups", out, f.lookups)
	}
}
