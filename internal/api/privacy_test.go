package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/privacy"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// Ingest classifies the real name, then stores only what the level keeps.
func TestClusterLogAppliesPrivacy(t *testing.T) {
	s, st := newEnrollServer(t, "", false)
	if _, err := st.CreateNode("agent-a", hashKey("node-key"), "node"); err != nil {
		t.Fatal(err)
	}
	var queued []string
	s.SetClassifierEnqueue(func(name string) { queued = append(queued, name) })
	s.SetPrivacy(privacy.New(func() privacy.Policy { return privacy.Policy{Level: privacy.LevelHideClients} },
		privacy.NewKeyring(st)))
	body := `[{"ts":1,"client":"10.0.0.7","name":"www.google.com.","action":"forward"}]`
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/log", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer node-key")
	rr := httptest.NewRecorder()
	s.clusterLog(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Join(queued, ",") != "www.google.com." {
		t.Errorf("classifier got %v, want the real name", queued)
	}
	got, _, err := st.SearchQueryLog(store.QueryLogQuery{Limit: 10})
	if err != nil || len(got) != 1 {
		t.Fatalf("stored %v, %v", got, err)
	}
	if got[0].Name != privacy.Hidden || !privacy.IsPseudonym(got[0].Client) {
		t.Errorf("stored %+v, want a hidden name and a pseudonymous client", got[0])
	}
}

// A settings save that doesn't mention privacy keeps it; one that does is
// clamped into range.
func TestSettingsKeepPrivacy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st, res: resolver.New(resolver.Options{})}
	put := func(body string) resolver.Settings {
		t.Helper()
		rr := httptest.NewRecorder()
		s.putSettings(rr, httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatal(rr.Body.String())
		}
		var out resolver.Settings
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := put(`{"upstreams":["192.0.2.1:53"],"privacy_level":9,"privacy_detail_hours":1000}`); got.PrivacyLevel != 3 || got.PrivacyDetailHours != privacy.MaxDetailHours {
		t.Fatalf("not clamped: level %d, hours %d", got.PrivacyLevel, got.PrivacyDetailHours)
	}
	if got := put(`{"upstreams":["192.0.2.1:53"],"privacy_level":2,"privacy_detail_hours":6}`); got.PrivacyLevel != 2 {
		t.Fatalf("level = %d, want 2", got.PrivacyLevel)
	}
	if got := put(`{"upstreams":["192.0.2.2:53"]}`); got.PrivacyLevel != 2 || got.PrivacyDetailHours != 6 {
		t.Fatalf("save without privacy reset it: level %d, hours %d", got.PrivacyLevel, got.PrivacyDetailHours)
	}
	if level, hours, _ := s.res.Privacy(); level != 2 || hours != 6 {
		t.Fatalf("resolver applied level %d, hours %d", level, hours)
	}
}
