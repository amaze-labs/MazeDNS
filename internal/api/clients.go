package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// getClients returns the windowed per-client list for the Clients tab.
// Params: ?hours=, ?nodes=, ?limit=.
func (s *Server) getClients(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	clients, err := s.store.ClientList(since, limit, parseNodes(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

// getClientDetail returns the per-client KPI/category/action breakdown for the
// inspect modal. Params: ?client= (required), ?hours=, ?nodes=.
func (s *Server) getClientDetail(w http.ResponseWriter, r *http.Request) {
	client := strings.TrimSpace(r.URL.Query().Get("client"))
	if client == "" {
		writeError(w, http.StatusBadRequest, "client is required")
		return
	}
	hours := clampHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	detail, err := s.store.ClientDetailStats(client, since, parseNodes(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// putClientName sets (or clears, with an empty name) the operator-assigned static
// hostname for a client IP. The name overrides NetBird/reverse-DNS everywhere.
func (s *Server) putClientName(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Client string `json:"client"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Client = strings.TrimSpace(in.Client)
	in.Name = strings.TrimSpace(in.Name)
	if in.Client == "" {
		writeError(w, http.StatusBadRequest, "client is required")
		return
	}
	if s.enricher == nil {
		writeError(w, http.StatusServiceUnavailable, "client enrichment is not available")
		return
	}
	if err := s.enricher.SetClientName(in.Client, in.Name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client": in.Client, "name": in.Name})
}
