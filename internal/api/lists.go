package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/ruleimport"
	"github.com/IPMaze/MazeDNS/internal/store"
)

func (s *Server) listLists(w http.ResponseWriter, _ *http.Request) {
	ls, err := s.store.ListLists()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ls == nil {
		ls = []store.List{}
	}
	writeJSON(w, http.StatusOK, ls)
}

func parsedToRules(parsed []ruleimport.Rule) []store.Rule {
	rules := make([]store.Rule, 0, len(parsed))
	for _, p := range parsed {
		rules = append(rules, store.Rule{Action: p.Action, Domain: p.Domain})
	}
	return rules
}

// importList creates a named list from pasted text or an uploaded file's content.
func (s *Server) importList(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		Text     string `json:"text"`
		Source   string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	source := in.Source
	if source != "file" && source != "paste" {
		source = "paste"
	}
	category := normalizeCategory(in.Category)
	parsed := ruleimport.Parse(in.Text)
	if len(parsed) == 0 {
		writeError(w, http.StatusBadRequest, "no valid rules found in input")
		return
	}
	id, err := s.store.CreateList(name, source, "", category, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	n, err := s.store.ReplaceListRules(id, category, parsedToRules(parsed))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.MarkListFetched(id, "")
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": name, "imported": n})
}

// addURLList subscribes to a remote list (e.g. a raw GitHub .list URL) and
// fetches it immediately; interval_minutes (0 = manual) drives auto-refresh.
func (s *Server) addURLList(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name            string `json:"name"`
		URL             string `json:"url"`
		Category        string `json:"category"`
		IntervalMinutes int    `json:"interval_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(in.Name)
	url := strings.TrimSpace(in.URL)
	if name == "" || url == "" {
		writeError(w, http.StatusBadRequest, "name and url required")
		return
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		writeError(w, http.StatusBadRequest, "url must start with http:// or https://")
		return
	}
	interval := in.IntervalMinutes * 60
	if interval < 0 {
		interval = 0
	}
	id, err := s.store.CreateList(name, "url", url, normalizeCategory(in.Category), interval)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.refresher != nil {
		if l, _ := s.store.GetList(id); l != nil {
			s.refresher.Refresh(r.Context(), *l) // immediate first fetch
		}
	}
	s.afterChange()
	l, _ := s.store.GetList(id)
	writeJSON(w, http.StatusCreated, l)
}

func (s *Server) listRulesForList(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rules, err := s.store.RulesByList(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []store.Rule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) refreshList(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	l, err := s.store.GetList(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if l == nil {
		writeError(w, http.StatusNotFound, "list not found")
		return
	}
	if l.Source != "url" {
		writeError(w, http.StatusBadRequest, "only URL lists can be refreshed")
		return
	}
	if s.refresher == nil {
		writeError(w, http.StatusInternalServerError, "refresher unavailable")
		return
	}
	s.refresher.Refresh(r.Context(), *l)
	s.afterChange()
	updated, _ := s.store.GetList(id)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) updateList(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Enabled         *bool `json:"enabled"`
		IntervalMinutes *int  `json:"interval_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if l, _ := s.store.GetList(id); l == nil {
		writeError(w, http.StatusNotFound, "list not found")
		return
	}
	if in.Enabled != nil {
		if err := s.store.SetListEnabled(id, *in.Enabled); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if in.IntervalMinutes != nil {
		iv := *in.IntervalMinutes * 60
		if iv < 0 {
			iv = 0
		}
		if err := s.store.UpdateListInterval(id, iv); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.afterChange()
	updated, _ := s.store.GetList(id)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteList(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteList(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	w.WriteHeader(http.StatusNoContent)
}

// protectionState is the block-pause status returned to the UI.
func (s *Server) protectionState() map[string]any {
	ts, _ := s.store.GetBlockPausedUntil()
	now := time.Now().Unix()
	left := int64(0)
	if ts > now {
		left = ts - now
	}
	return map[string]any{"paused": ts > now, "paused_until": ts, "seconds_left": left}
}

func (s *Server) getProtection(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.protectionState())
}

// disableProtection pauses block enforcement for the given number of seconds
// (<= 0 means until manually re-enabled).
func (s *Server) disableProtection(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Seconds int64 `json:"seconds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in) // empty body => indefinite
	now := time.Now().Unix()
	until := now + 100*365*24*3600 // effectively indefinite
	if in.Seconds > 0 {
		until = now + in.Seconds
	}
	if err := s.store.SetBlockPausedUntil(until); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.res.SetBlockPausedUntil(until)
	writeJSON(w, http.StatusOK, s.protectionState())
}

func (s *Server) enableProtection(w http.ResponseWriter, _ *http.Request) {
	if err := s.store.SetBlockPausedUntil(0); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.res.SetBlockPausedUntil(0)
	writeJSON(w, http.StatusOK, s.protectionState())
}
