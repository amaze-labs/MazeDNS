package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestConfigBundleForwardersRoundTrip(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}

	if _, err := st.AddForwarder("corp.internal", []string{"10.0.0.2:53"}, store.ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRewriteScoped("nas.lan", "A", "10.0.0.5", store.ScopeNodes, []string{"n1"}); err != nil {
		t.Fatal(err)
	}

	// Export includes forwarders and rewrite scopes.
	rr := httptest.NewRecorder()
	s.exportConfig(rr, httptest.NewRequest(http.MethodGet, "/api/config/export", nil))
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	var b ConfigBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Forwarders) != 1 || b.Forwarders[0].Suffix != "corp.internal" || b.Forwarders[0].ScopeType != store.ScopeSites {
		t.Fatalf("forwarders not exported: %+v", b.Forwarders)
	}
	if len(b.Rewrites) != 1 || b.Rewrites[0].ScopeType != store.ScopeNodes {
		t.Fatalf("rewrite scope not exported: %+v", b.Rewrites)
	}

	// Replace-import into an empty store restores both, with scopes.
	st2, err := store.Open(filepath.Join(t.TempDir(), "test2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st2.Close() })
	s2 := &Server{store: st2}
	irr := httptest.NewRecorder()
	s2.importConfig(irr, httptest.NewRequest(http.MethodPost, "/api/config/import?mode=replace", strings.NewReader(rr.Body.String())))
	if irr.Code != http.StatusOK {
		t.Fatal(irr.Body.String())
	}
	fws, _ := st2.ListForwarders()
	if len(fws) != 1 || fws[0].Suffix != "corp.internal" || fws[0].ScopeType != store.ScopeSites || !fws[0].Enabled {
		t.Fatalf("forwarders not imported: %+v", fws)
	}
	rws, _ := st2.ListRewrites()
	if len(rws) != 1 || rws[0].ScopeType != store.ScopeNodes {
		t.Fatalf("rewrite scope not imported: %+v", rws)
	}
}
