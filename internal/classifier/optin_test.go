package classifier

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func optinStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// Where classification was never turned on, the services older releases
// seeded as on are reset to off, once; where it is on, nothing changes.
func TestMigrateOptIn(t *testing.T) {
	seeded := Settings{Enabled: false, AIEnabled: true, Model: "llama3.2", Endpoint: "http://localhost:11434/v1",
		WhoisEnabled: true, ThreatFeeds: DefaultThreatFeeds, VTAPIKey: "keep-me"}

	st := optinStore(t)
	_ = SaveSettings(st, seeded)
	if err := MigrateOptIn(st); err != nil {
		t.Fatal(err)
	}
	got := LoadSettings(st, Settings{})
	if got.AIEnabled || got.WhoisEnabled || len(got.ThreatFeeds) != 0 || got.ThreatFeeds == nil || !got.NSCheckDisabled {
		t.Errorf("off instance after migration: %+v", got)
	}
	if got.VTAPIKey != "keep-me" || got.Model != "llama3.2" {
		t.Errorf("unrelated settings changed: %+v", got)
	}
	if len(threatSources(got)) != 0 {
		t.Errorf("threat sources after migration: %v (an empty list must not fall back to URLhaus)", threatSources(got))
	}
	// Turning things back on afterwards sticks: the migration runs once.
	got.WhoisEnabled = true
	_ = SaveSettings(st, got)
	_ = MigrateOptIn(st)
	if !LoadSettings(st, Settings{}).WhoisEnabled {
		t.Error("migration ran twice")
	}

	on := optinStore(t)
	inUse := seeded
	inUse.Enabled = true
	_ = SaveSettings(on, inUse)
	_ = MigrateOptIn(on)
	if g := LoadSettings(on, Settings{}); !g.AIEnabled || !g.WhoisEnabled || len(g.ThreatFeeds) != len(DefaultThreatFeeds) {
		t.Errorf("an instance using classification was changed: %+v", g)
	}
}

// With classification off, starting the worker downloads nothing.
func TestRunDownloadsNothingWhileOff(t *testing.T) {
	st := optinStore(t)
	s := Settings{Enabled: false, ThreatFeeds: DefaultThreatFeeds} // trusted default on, feeds listed
	w := NewWorker(st, func() Settings { return s }, func() error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if k, _ := w.trusted.src.Load().(string); k != "" {
		t.Errorf("trusted list loaded while off: %q", k)
	}
	if k, _ := w.threat.src.Load().(string); k != "" {
		t.Errorf("threat feeds loaded while off: %q", k)
	}
}
