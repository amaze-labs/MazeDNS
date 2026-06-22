package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// configBundleVersion is the on-disk format version of an exported config.
const configBundleVersion = 1

// ConfigBundle is a portable snapshot of all mutable configuration: operational
// settings, filtering rules, and local DNS rewrites. It deliberately omits
// users/sessions (auth is bootstrap), the query log (transient), and cluster
// node keys (per-deployment secrets).
type ConfigBundle struct {
	Version    int                `json:"version"`
	ExportedAt int64              `json:"exported_at"`
	Settings   *resolver.Settings `json:"settings,omitempty"`
	Rules      []store.Rule       `json:"rules"`
	Rewrites   []store.Rewrite    `json:"rewrites"`
}

// exportConfig returns the full mutable config as one downloadable JSON bundle.
func (s *Server) exportConfig(w http.ResponseWriter, _ *http.Request) {
	bundle := ConfigBundle{Version: configBundleVersion, ExportedAt: time.Now().Unix()}

	raw, err := s.store.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if raw != "" {
		var set resolver.Settings
		if json.Unmarshal([]byte(raw), &set) == nil {
			bundle.Settings = &set
		}
	}

	rules, err := s.store.ListRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []store.Rule{}
	}
	bundle.Rules = rules

	rws, err := s.store.ListRewrites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rws == nil {
		rws = []store.Rewrite{}
	}
	bundle.Rewrites = rws

	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="mazedns-config-%s.json"`, time.Now().UTC().Format("20060102-150405")))
	writeJSON(w, http.StatusOK, bundle)
}

// importConfig restores a config bundle. mode=merge (default) upserts rules and
// rewrites on top of what's there; mode=replace clears them first. Settings, if
// present, are validated, persisted, and applied live.
func (s *Server) importConfig(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "merge"
	}
	if mode != "merge" && mode != "replace" {
		writeError(w, http.StatusBadRequest, "mode must be merge or replace")
		return
	}

	var b ConfigBundle
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if b.Version != configBundleVersion {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("unsupported bundle version %d (expected %d)", b.Version, configBundleVersion))
		return
	}
	if b.Settings != nil && len(b.Settings.Upstreams) == 0 {
		writeError(w, http.StatusBadRequest, "settings present but lists no upstreams")
		return
	}

	if mode == "replace" {
		if err := s.store.ClearRules(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.store.ClearRewrites(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	nr, err := s.store.AddRulesBulk(b.Rules)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nw, err := s.store.AddRewritesBulk(b.Rewrites)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if b.Settings != nil {
		if b.Settings.BlockResponse != "zeroip" {
			b.Settings.BlockResponse = "nxdomain"
		}
		if b.Settings.RateLimitQPM < 0 {
			b.Settings.RateLimitQPM = 0
		}
		if b.Settings.Cache.MaxEntries < 0 {
			b.Settings.Cache.MaxEntries = 0
		}
		data, err := json.Marshal(b.Settings)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.store.SaveSettings(string(data)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.res.ApplySettings(*b.Settings)
	}

	// Bump the cluster config version (workers re-sync) and reload the policy.
	s.afterChange()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":     mode,
		"rules":    nr,
		"rewrites": nw,
		"settings": b.Settings != nil,
	})
}
