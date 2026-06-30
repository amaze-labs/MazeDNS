package classifier

import (
	"path/filepath"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Settings saved before the ai_enabled switch existed must keep their behaviour:
// AI on whenever a model was configured, off otherwise.
func TestLoadSettingsAIEnabledMigration(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"legacy with model+endpoint -> AI on", `{"endpoint":"http://x/v1","model":"llama3.2"}`, true},
		{"legacy anthropic with model -> AI on", `{"provider":"anthropic","model":"claude-haiku-4-5"}`, true},
		{"legacy without model -> AI off", `{"endpoint":"http://x/v1"}`, false},
		{"explicit ai_enabled false is honoured", `{"ai_enabled":false,"endpoint":"http://x/v1","model":"llama3.2"}`, false},
		{"explicit ai_enabled true is honoured", `{"ai_enabled":true,"model":"llama3.2","endpoint":"http://x/v1"}`, true},
	}
	for _, c := range cases {
		st := openStore(t)
		if err := st.SetMeta(SettingsKey, c.raw); err != nil {
			t.Fatal(err)
		}
		s := LoadSettings(st, Settings{})
		if s.AIEnabled != c.want {
			t.Errorf("%s: AIEnabled = %v, want %v", c.name, s.AIEnabled, c.want)
		}
	}
}
