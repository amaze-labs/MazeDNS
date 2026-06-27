package classifier

import (
	"encoding/json"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// SettingsKey is the app_meta key under which the live classifier settings are
// persisted (as JSON), so they can be edited from the UI and applied at runtime.
const SettingsKey = "classifier_settings"

// LoadSettings reads the persisted settings, falling back to def when none are
// stored yet (or on a parse error).
func LoadSettings(st *store.Store, def Settings) Settings {
	raw, err := st.GetMeta(SettingsKey)
	if err != nil || raw == "" {
		return def
	}
	var s Settings
	if json.Unmarshal([]byte(raw), &s) != nil {
		return def
	}
	if s.Mode == "" {
		s.Mode = string(ModeOff)
	}
	return s
}

// SaveSettings persists the settings.
func SaveSettings(st *store.Store, s Settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.SetMeta(SettingsKey, string(b))
}
