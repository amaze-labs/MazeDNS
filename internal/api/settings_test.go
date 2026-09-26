package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// The settings API reports the effective upstream strategy for settings saved
// before the field existed, and normalizes what it persists.
func TestSettingsUpstreamStrategy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st, res: resolver.New(resolver.Options{})}

	get := func() resolver.Settings {
		t.Helper()
		rr := httptest.NewRecorder()
		s.getSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
		if rr.Code != http.StatusOK {
			t.Fatal(rr.Body.String())
		}
		var out resolver.Settings
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if err := st.SaveSettings(`{"upstreams":["192.0.2.1:53","192.0.2.2:53"]}`); err != nil {
		t.Fatal(err)
	}
	if got := get(); got.UpstreamStrategy != resolver.StrategyOrdered || got.UpstreamTimeoutMs != resolver.DefaultUpstreamTimeoutMs {
		t.Fatalf("legacy settings read as %q/%d, want ordered/%d", got.UpstreamStrategy, got.UpstreamTimeoutMs, resolver.DefaultUpstreamTimeoutMs)
	}

	body := `{"upstreams":["192.0.2.2:53","192.0.2.1:53"],"upstream_strategy":"Hedged","upstream_timeout_ms":20}`
	rr := httptest.NewRecorder()
	s.putSettings(rr, httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	got := get()
	if got.UpstreamStrategy != resolver.StrategyHedged || got.UpstreamTimeoutMs != resolver.MinUpstreamTimeoutMs {
		t.Fatalf("saved settings read as %q/%d, want hedged/%d", got.UpstreamStrategy, got.UpstreamTimeoutMs, resolver.MinUpstreamTimeoutMs)
	}
	if strings.Join(got.Upstreams, ",") != "192.0.2.2:53,192.0.2.1:53" {
		t.Fatalf("upstream order not preserved: %v", got.Upstreams)
	}
}
