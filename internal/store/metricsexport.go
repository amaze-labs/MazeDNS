package store

import "encoding/json"

// vmExportKey is the app_meta key holding the VictoriaMetrics push-export settings
// (JSON), so they can be edited live from the UI.
const vmExportKey = "metrics_victoria"

// VMExport is the persisted VictoriaMetrics metrics-export configuration.
type VMExport struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`          // base URL, e.g. http://victoriametrics:8428
	IntervalSec int    `json:"interval_sec"` // push interval in seconds (default 15)
	Job         string `json:"job"`          // job label
	Instance    string `json:"instance"`     // instance label ("" = hostname)
	Username    string `json:"username"`     // optional HTTP basic auth
	Password    string `json:"password"`
}

// LoadVMExport reads the export settings, returning def when unset/invalid.
func (s *Store) LoadVMExport(def VMExport) VMExport {
	raw, err := s.GetMeta(vmExportKey)
	if err != nil || raw == "" {
		return def
	}
	var v VMExport
	if json.Unmarshal([]byte(raw), &v) != nil {
		return def
	}
	return v
}

// SaveVMExport persists the export settings.
func (s *Store) SaveVMExport(v VMExport) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.SetMeta(vmExportKey, string(b))
}

// EnsureVMExport seeds the export settings from def only if they're not already
// set, so the config file provides first-run defaults while the UI stays the live
// source of truth thereafter.
func (s *Store) EnsureVMExport(def VMExport) error {
	if raw, _ := s.GetMeta(vmExportKey); raw != "" {
		return nil
	}
	return s.SaveVMExport(def)
}
