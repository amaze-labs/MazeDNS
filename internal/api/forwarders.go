package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// Centrally-managed conditional forwarders: suffix -> upstreams, scoped to
// all nodes / a node list / sites. Agents receive their filtered set through
// the cluster snapshot; there is nothing to apply on the control plane itself
// (it serves no DNS), so mutations only need afterChange() to bump the
// content hash agents poll.

func (s *Server) listForwarders(w http.ResponseWriter, _ *http.Request) {
	fws, err := s.store.ListForwarders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fws)
}

// validateForwarderInput normalizes and validates the shared POST/PUT fields.
// Returns (suffix, scopeType, valuesJSON, ok); on !ok the response is written.
func (s *Server) validateForwarderInput(w http.ResponseWriter, suffix string, upstreams []string, scopeType string, scopeValues []string) (string, string, string, bool) {
	sfx := filter.Normalize(suffix)
	if sfx == "" {
		writeError(w, http.StatusBadRequest, "suffix required")
		return "", "", "", false
	}
	if strings.Contains(sfx, "*") {
		writeError(w, http.StatusBadRequest, "a forwarder suffix already matches all subdomains; wildcards are not allowed")
		return "", "", "", false
	}
	if len(upstreams) == 0 {
		writeError(w, http.StatusBadRequest, "at least one upstream is required")
		return "", "", "", false
	}
	for _, u := range upstreams {
		spec := strings.TrimSpace(u)
		if spec == "" {
			writeError(w, http.StatusBadRequest, "upstream must not be empty")
			return "", "", "", false
		}
		// Embedded whitespace is unambiguously malformed in every documented format
		// (plain host:port, udp://, tcp://, tls://host:port#name, https://url) and
		// ParseUpstream's ensurePort fallback never errors on it, so catch it here.
		if strings.ContainsAny(spec, " \t") {
			writeError(w, http.StatusBadRequest, "invalid upstream "+spec)
			return "", "", "", false
		}
		if _, err := resolver.ParseUpstream(spec, 5*time.Second); err != nil {
			writeError(w, http.StatusBadRequest, "invalid upstream "+u+": "+err.Error())
			return "", "", "", false
		}
	}
	st, valsJSON, err := store.CanonicalScope(scopeType, scopeValues)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", "", "", false
	}
	return sfx, st, valsJSON, true
}

func (s *Server) addForwarder(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Suffix      string   `json:"suffix"`
		Upstreams   []string `json:"upstreams"`
		ScopeType   string   `json:"scope_type"`
		ScopeValues []string `json:"scope_values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	suffix, scopeType, valsJSON, ok := s.validateForwarderInput(w, in.Suffix, in.Upstreams, in.ScopeType, in.ScopeValues)
	if !ok {
		return
	}
	if conflict, err := s.store.ForwarderScopeConflict(suffix, scopeType, valsJSON, 0); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if conflict {
		writeError(w, http.StatusConflict, "another forwarder for this suffix already targets overlapping "+scopeType)
		return
	}
	id, err := s.store.AddForwarder(suffix, in.Upstreams, scopeType, in.ScopeValues)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "suffix": suffix, "upstreams": in.Upstreams, "scope_type": scopeType, "scope_values": in.ScopeValues})
}

func (s *Server) updateForwarder(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Upstreams   []string `json:"upstreams"`
		Enabled     bool     `json:"enabled"`
		ScopeType   string   `json:"scope_type"`
		ScopeValues []string `json:"scope_values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	fws, err := s.store.ListForwarders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var cur *store.Forwarder
	for i := range fws {
		if fws[i].ID == id {
			cur = &fws[i]
			break
		}
	}
	if cur == nil {
		writeError(w, http.StatusNotFound, "forwarder not found")
		return
	}
	suffix, scopeType, valsJSON, ok := s.validateForwarderInput(w, cur.Suffix, in.Upstreams, in.ScopeType, in.ScopeValues)
	if !ok {
		return
	}
	// ForwarderScopeConflict deliberately skips rows whose scope is IDENTICAL to
	// the new one (that's the correct upsert behavior for POST), so re-scoping
	// this row onto another row's exact (suffix+scope) would sail past it and
	// hit the UNIQUE constraint as a raw 500. Catch that case here.
	for i := range fws {
		if fws[i].ID == id || fws[i].Suffix != suffix {
			continue
		}
		if fws[i].ScopeType == scopeType && scopeValuesJSON(fws[i].ScopeValues) == valsJSON {
			writeError(w, http.StatusConflict, "another forwarder for this suffix already has this exact scope")
			return
		}
	}
	if conflict, err := s.store.ForwarderScopeConflict(suffix, scopeType, valsJSON, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if conflict {
		writeError(w, http.StatusConflict, "another forwarder for this suffix already targets overlapping "+scopeType)
		return
	}
	if err := s.store.UpdateForwarder(id, in.Upstreams, in.Enabled, scopeType, in.ScopeValues); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "upstreams": in.Upstreams, "enabled": in.Enabled, "scope_type": scopeType, "scope_values": in.ScopeValues})
}

func (s *Server) deleteForwarder(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteForwarder(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	w.WriteHeader(http.StatusNoContent)
}
