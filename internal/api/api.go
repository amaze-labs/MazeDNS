// Package api serves the MazeDNS HTTP control plane, web UI, and Prometheus metrics.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
	"github.com/IPMaze/MazeDNS/web"
)

// Server is the HTTP API server.
type Server struct {
	store  *store.Store
	res    *resolver.Resolver
	reload func() error
	http   *http.Server
}

// New constructs the API server. reload rebuilds and installs the resolver policy
// from the store; it is called after every mutation.
func New(addr string, st *store.Store, res *resolver.Resolver, m *metrics.Metrics, reload func() error) *Server {
	s := &Server{store: st, res: res, reload: reload}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /metrics", m.Handler())
	mux.HandleFunc("GET /api/stats", s.getStats)
	mux.HandleFunc("GET /api/querylog", s.getQueryLog)
	mux.HandleFunc("GET /api/rules", s.listRules)
	mux.HandleFunc("POST /api/rules", s.addRule)
	mux.HandleFunc("DELETE /api/rules/{id}", s.deleteRule)
	mux.HandleFunc("GET /api/rewrites", s.listRewrites)
	mux.HandleFunc("POST /api/rewrites", s.addRewrite)
	mux.HandleFunc("DELETE /api/rewrites/{id}", s.deleteRewrite)
	mux.Handle("/", web.Handler()) // SPA + static assets (embedded with -tags embed_dist)
	s.http = &http.Server{
		Addr:              addr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error { return s.http.ListenAndServe() }

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) getStats(w http.ResponseWriter, _ *http.Request) {
	total, blocked, cached, forwarded, rewritten, errs := s.res.StatsSnapshot()
	logged, _ := s.store.CountQueryLog()
	writeJSON(w, http.StatusOK, map[string]any{
		"total":      total,
		"blocked":    blocked,
		"cached":     cached,
		"forwarded":  forwarded,
		"rewritten":  rewritten,
		"errors":     errs,
		"cache_size": s.res.CacheLen(),
		"log_count":  logged,
	})
}

func (s *Server) getQueryLog(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 100
	}
	entries, err := s.store.RecentQueryLog(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.QueryLogEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) listRules(w http.ResponseWriter, _ *http.Request) {
	rules, err := s.store.ListRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []store.Rule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.Action != "allow" && in.Action != "deny" {
		writeError(w, http.StatusBadRequest, "action must be allow or deny")
		return
	}
	domain := filter.Normalize(in.Domain)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}
	id, err := s.store.AddRule(in.Action, domain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "action": in.Action, "domain": domain})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteRule(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRewrites(w http.ResponseWriter, _ *http.Request) {
	rws, err := s.store.ListRewrites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rws == nil {
		rws = []store.Rewrite{}
	}
	writeJSON(w, http.StatusOK, rws)
}

func (s *Server) addRewrite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
		RRType string `json:"rrtype"`
		Value  string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	switch in.RRType {
	case "A", "AAAA", "CNAME":
	default:
		writeError(w, http.StatusBadRequest, "rrtype must be A, AAAA, or CNAME")
		return
	}
	domain := filter.Normalize(in.Domain)
	if domain == "" || in.Value == "" {
		writeError(w, http.StatusBadRequest, "domain and value required")
		return
	}
	id, err := s.store.AddRewrite(domain, in.RRType, in.Value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "domain": domain, "rrtype": in.RRType, "value": in.Value})
}

func (s *Server) deleteRewrite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteRewrite(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) afterChange() {
	if s.reload == nil {
		return
	}
	if err := s.reload(); err != nil {
		slog.Warn("policy reload failed", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		slog.Debug("http", "method", r.Method, "path", r.URL.Path)
	})
}
