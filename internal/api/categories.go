package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/classifier"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// SetCategorizer installs the domain categorizer: query-log entries are
// labelled with it as they arrive, and the category endpoints use it.
func (s *Server) SetCategorizer(c *classifier.Categorizer) { s.categorizer = c }

// labelEntries sets each entry's content category, when categories are on.
func (s *Server) labelEntries(entries []store.QueryLogEntry) {
	if s.categorizer != nil {
		s.categorizer.Label(entries)
	}
}

// categoryInfo is one category for the UI: the taxonomy entry, how many
// domains the category database lists for it, and whether it is blocked.
type categoryInfo struct {
	categories.Category
	Domains int  `json:"domains"`
	Blocked bool `json:"blocked"`
}

// getCategoryList returns the taxonomy with database counts and blocked flags,
// plus the category database's status.
func (s *Server) getCategoryList(w http.ResponseWriter, _ *http.Request) {
	var st categories.Status
	if s.categorizer != nil {
		st = s.categorizer.Status()
	}
	blocked := map[string]bool{}
	for _, c := range s.blockedCategories() {
		blocked[c] = true
	}
	out := make([]categoryInfo, 0, len(categories.All))
	for _, c := range categories.All {
		out = append(out, categoryInfo{Category: c, Domains: st.Counts[c.ID], Blocked: blocked[c.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"categories": out,
		"database":   st,
		"enabled":    s.categorizer != nil,
	})
}

// getDomainCategory returns a domain's category and where it came from.
func (s *Server) getDomainCategory(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("domain"))
	domain := classifier.RegisteredDomain(name)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "valid domain is required")
		return
	}
	if s.categorizer == nil {
		writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "category": categories.Other, "source": ""})
		return
	}
	cat, src := s.categorizer.Category(name)
	resp := map[string]any{"domain": domain, "category": cat, "source": src}
	if o, ok := s.categorizer.Override(name); ok {
		resp["override"] = o
	}
	writeJSON(w, http.StatusOK, resp)
}

// putCategoryOverride sets an operator's category for a registered domain.
func (s *Server) putCategoryOverride(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain   string `json:"domain"`
		Category string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	domain := classifier.RegisteredDomain(in.Domain)
	switch {
	case domain == "":
		writeError(w, http.StatusBadRequest, "valid domain is required")
		return
	case !categories.Valid(in.Category):
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown category %q", in.Category))
		return
	case s.categorizer == nil:
		writeError(w, http.StatusConflict, "domain categories are turned off")
		return
	}
	user := auditUser(s, r)
	if err := s.store.SetCategoryOverride(domain, in.Category, user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(store.AuditEntry{User: user, Action: "category.override",
		Detail: fmt.Sprintf("%s set to %s", domain, in.Category)})
	s.afterCategoryChange()
	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "category": in.Category, "source": classifier.SourceOverride})
}

// deleteCategoryOverride removes an operator's category for a domain.
func (s *Server) deleteCategoryOverride(w http.ResponseWriter, r *http.Request) {
	domain := classifier.RegisteredDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "valid domain is required")
		return
	}
	if err := s.store.DeleteCategoryOverride(domain); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user := auditUser(s, r)
	_ = s.store.AppendAudit(store.AuditEntry{User: user, Action: "category.override",
		Detail: fmt.Sprintf("%s back to automatic", domain)})
	s.afterCategoryChange()
	w.WriteHeader(http.StatusNoContent)
}

// afterCategoryChange makes an override take effect now: new log entries are
// labelled with it, and agents pick it up if its category is blocked.
func (s *Server) afterCategoryChange() {
	if s.categorizer != nil {
		_ = s.categorizer.Refresh()
	}
	if s.reload != nil {
		_ = s.reload()
	}
}

// getContentTraffic returns query volume by content category over the window.
func (s *Server) getContentTraffic(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-windowDur(hours)).UnixMilli()
	out, err := s.store.RollupByCategory(since, parseNodes(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	writeJSON(w, http.StatusOK, out)
}

// blockedCategories returns the categories blocked network-wide.
func (s *Server) blockedCategories() []string {
	set, err := s.loadSettings()
	if err != nil {
		return nil
	}
	return set.BlockedCategories
}

// loadSettings reads the stored resolver settings.
func (s *Server) loadSettings() (resolver.Settings, error) {
	var set resolver.Settings
	raw, err := s.store.GetSettings()
	if err != nil || raw == "" {
		return set, err
	}
	err = json.Unmarshal([]byte(raw), &set)
	return set, err
}

// putBlockedCategories sets the categories blocked network-wide. They travel to
// the agents with the resolver settings.
func (s *Server) putBlockedCategories(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Categories []string `json:"categories"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cats, err := cleanBlockedCategories(in.Categories)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	set, err := s.loadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	before := strings.Join(set.BlockedCategories, ", ")
	set.BlockedCategories = cats
	set.CategoryDomains = nil // computed when replicating, never stored
	b, err := json.Marshal(set)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SaveSettings(string(b)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.res != nil {
		s.res.ApplySettings(set)
	}
	_ = s.store.AppendAudit(store.AuditEntry{User: auditUser(s, r), Action: "categories.blocked",
		Detail: fmt.Sprintf("blocked categories: [%s] -> [%s]", before, strings.Join(cats, ", "))})
	if s.reload != nil {
		_ = s.reload() // overrides and model labels in the new categories become rules
	}
	writeJSON(w, http.StatusOK, map[string]any{"categories": cats})
}

// cleanBlockedCategories validates and de-duplicates a blocked-category list,
// in taxonomy order. "other" can't be blocked: it is everything unknown; nor
// "local": those names never leave the network.
func cleanBlockedCategories(in []string) ([]string, error) {
	want := map[string]bool{}
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == categories.Other || c == categories.Local || !categories.Valid(c) {
			return nil, fmt.Errorf("can't block category %q", c)
		}
		want[c] = true
	}
	out := []string{}
	for _, c := range categories.All {
		if want[c.ID] {
			out = append(out, c.ID)
		}
	}
	return out, nil
}
