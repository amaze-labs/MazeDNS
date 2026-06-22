// Package api serves the MazeDNS HTTP control plane, web UI, and Prometheus metrics.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/ruleimport"
	"github.com/IPMaze/MazeDNS/internal/store"
	"github.com/IPMaze/MazeDNS/web"
)

const (
	roleReadonly    = "readonly"
	roleAdmin       = "admin"
	oidcStateCookie = "mazedns_oidc_state"
)

// Server is the HTTP API server.
type Server struct {
	store          *store.Store
	res            *resolver.Resolver
	reload         func() error
	auth           *auth.Manager
	authEnabled    bool
	clusterEnabled bool
	http           *http.Server
}

// New constructs the HTTP server. In worker mode only /healthz and /metrics are
// served; in master mode the control-plane API and web UI are mounted, plus the
// cluster endpoints when clusterEnabled. reload rebuilds the resolver policy
// after every mutation.
func New(addr string, st *store.Store, res *resolver.Resolver, m *metrics.Metrics, reload func() error, authMgr *auth.Manager, authEnabled, worker, clusterEnabled bool) *Server {
	s := &Server{store: st, res: res, reload: reload, auth: authMgr, authEnabled: authEnabled, clusterEnabled: clusterEnabled}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /metrics", m.Handler())

	if !worker {
		// Auth endpoints (open).
		mux.HandleFunc("GET /api/auth/info", s.authInfo)
		mux.HandleFunc("POST /api/auth/login", s.login)
		mux.HandleFunc("POST /api/auth/logout", s.logout)
		mux.HandleFunc("GET /api/auth/me", s.me)
		mux.HandleFunc("GET /api/auth/oidc/login", s.oidcLogin)
		mux.HandleFunc("GET /api/auth/oidc/callback", s.oidcCallback)

		// Data endpoints (protected: readonly may GET, admin may mutate).
		mux.HandleFunc("GET /api/stats", s.requireRole(roleReadonly, s.getStats))
		mux.HandleFunc("GET /api/stats/timeseries", s.requireRole(roleReadonly, s.getTimeSeries))
		mux.HandleFunc("GET /api/stats/categories", s.requireRole(roleReadonly, s.getCategories))
		mux.HandleFunc("GET /api/querylog", s.requireRole(roleReadonly, s.getQueryLog))
		mux.HandleFunc("GET /api/rules", s.requireRole(roleReadonly, s.listRules))
		mux.HandleFunc("POST /api/rules", s.requireRole(roleAdmin, s.addRule))
		mux.HandleFunc("POST /api/rules/import", s.requireRole(roleAdmin, s.importRules))
		mux.HandleFunc("DELETE /api/rules/{id}", s.requireRole(roleAdmin, s.deleteRule))
		mux.HandleFunc("GET /api/rewrites", s.requireRole(roleReadonly, s.listRewrites))
		mux.HandleFunc("POST /api/rewrites", s.requireRole(roleAdmin, s.addRewrite))
		mux.HandleFunc("DELETE /api/rewrites/{id}", s.requireRole(roleAdmin, s.deleteRewrite))

		mux.HandleFunc("GET /api/settings", s.requireRole(roleReadonly, s.getSettings))
		mux.HandleFunc("PUT /api/settings", s.requireRole(roleAdmin, s.putSettings))

		// Cluster control plane (master only).
		if clusterEnabled {
			mux.HandleFunc("GET /api/cluster/nodes", s.requireRole(roleReadonly, s.clusterNodes))
			mux.HandleFunc("POST /api/cluster/nodes", s.requireRole(roleAdmin, s.addNode))
			mux.HandleFunc("DELETE /api/cluster/nodes/{name}", s.requireRole(roleAdmin, s.deleteNode))
			mux.HandleFunc("GET /api/cluster/snapshot", s.clusterSnapshot) // per-node key auth
		}

		mux.Handle("/", web.Handler()) // SPA + static assets (embedded with -tags embed_dist)
	}

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

// requireRole wraps a handler with authentication and a minimum-role check.
func (s *Server) requireRole(minRole string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authEnabled {
			h(w, r)
			return
		}
		u, ok := s.auth.UserFromRequest(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if minRole == roleAdmin && u.Role != roleAdmin {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		h(w, r)
	}
}

// ---- cluster control plane ----

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// clusterSnapshot serves the config snapshot to a worker authenticated by its
// per-node API key (Bearer). It also refreshes the node's last-seen state.
func (s *Server) clusterSnapshot(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		writeError(w, http.StatusUnauthorized, "missing node key")
		return
	}
	node, err := s.store.NodeByKeyHash(hashKey(strings.TrimPrefix(h, prefix)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil {
		writeError(w, http.StatusUnauthorized, "invalid node key")
		return
	}
	ver, _ := strconv.ParseInt(r.Header.Get("X-MazeDNS-Node-Version"), 10, 64)
	addr := r.RemoteAddr
	if host, _, e := net.SplitHostPort(r.RemoteAddr); e == nil {
		addr = host
	}
	var st store.NodeStats
	if raw := r.Header.Get("X-MazeDNS-Stats"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	_ = s.store.TouchNode(node.Name, addr, ver, st)

	rules, err := s.store.ListRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rewrites, err := s.store.ListRewrites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	version, _ := s.store.GetConfigVersion()
	if rules == nil {
		rules = []store.Rule{}
	}
	if rewrites == nil {
		rewrites = []store.Rewrite{}
	}
	writeJSON(w, http.StatusOK, cluster.Snapshot{Version: version, Rules: rules, Rewrites: rewrites})
}

func (s *Server) clusterNodes(w http.ResponseWriter, _ *http.Request) {
	nodes, err := s.store.ListNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if nodes == nil {
		nodes = []store.Node{}
	}
	writeJSON(w, http.StatusOK, nodes)
}

// addNode enrolls a worker, generating its API key (returned once, in clear).
func (s *Server) addNode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
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
	key, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	prefix := key
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	if err := s.store.CreateNode(name, hashKey(key), prefix); err != nil {
		writeError(w, http.StatusConflict, "could not create node (name in use?): "+err.Error())
		return
	}
	// The key is shown only here — it is stored hashed.
	writeJSON(w, http.StatusCreated, map[string]string{"name": name, "key": key})
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteNode(r.PathValue("name")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- auth handlers ----

func (s *Server) authInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_enabled":    s.authEnabled,
		"oidc_enabled":    s.authEnabled && s.auth.OIDCEnabled(),
		"cluster_enabled": s.clusterEnabled,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled {
		writeJSON(w, http.StatusOK, map[string]string{"status": "auth disabled"})
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	token, user, err := s.auth.Login(in.Username, in.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.auth.SetCookie(w, token)
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.authEnabled {
		s.auth.Logout(r)
		s.auth.ClearCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled {
		writeJSON(w, http.StatusOK, map[string]string{"username": "anonymous", "role": roleAdmin})
		return
	}
	u, ok := s.auth.UserFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled || !s.auth.OIDCEnabled() {
		writeError(w, http.StatusNotFound, "oidc not enabled")
		return
	}
	state, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: state, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 300,
	})
	http.Redirect(w, r, s.auth.OIDC().AuthCodeURL(state), http.StatusFound)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled || !s.auth.OIDCEnabled() {
		writeError(w, http.StatusNotFound, "oidc not enabled")
		return
	}
	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		writeError(w, http.StatusBadRequest, "invalid oauth state")
		return
	}
	claims, err := s.auth.OIDC().Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		slog.Warn("oidc exchange failed", "err", err)
		writeError(w, http.StatusUnauthorized, "oidc exchange failed")
		return
	}
	user, err := s.store.UpsertOIDCUser(claims.Subject, claims.Username, claims.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user provisioning failed")
		return
	}
	token, _, err := s.auth.StartSession(user.ID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	s.auth.SetCookie(w, token)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- data handlers ----

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

func (s *Server) getTimeSeries(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	step := hours * 3600 / 48
	if step < 60 {
		step = 60
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	points, err := s.store.QueryTimeSeries(since, step)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if points == nil {
		points = []store.SeriesPoint{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"step": step, "points": points})
}

func (s *Server) getCategories(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	cats, err := s.store.BlockedByCategory(since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cats == nil {
		cats = []store.CategoryCount{}
	}
	writeJSON(w, http.StatusOK, cats)
}

func clampHours(s string) int {
	h, _ := strconv.Atoi(s)
	if h <= 0 {
		h = 24
	}
	if h > 24*30 {
		h = 24 * 30
	}
	return h
}

// getSettings returns the current operational settings (readonly access).
func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	raw, err := s.store.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var settings resolver.Settings
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &settings)
	}
	writeJSON(w, http.StatusOK, settings)
}

// putSettings validates, persists, and applies new operational settings live.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in resolver.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(in.Upstreams) == 0 {
		writeError(w, http.StatusBadRequest, "at least one upstream is required")
		return
	}
	if in.BlockResponse != "zeroip" {
		in.BlockResponse = "nxdomain"
	}
	if in.RateLimitQPM < 0 {
		in.RateLimitQPM = 0
	}
	if in.Cache.MaxEntries < 0 {
		in.Cache.MaxEntries = 0
	}
	b, err := json.Marshal(in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SaveSettings(string(b)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.res.ApplySettings(in)
	writeJSON(w, http.StatusOK, in)
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
		Action   string `json:"action"`
		Domain   string `json:"domain"`
		Category string `json:"category"`
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
	category := normalizeCategory(in.Category)
	id, err := s.store.AddRule(in.Action, domain, category)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "action": in.Action, "domain": domain, "category": category})
}

func (s *Server) importRules(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text     string `json:"text"`
		Category string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	parsed := ruleimport.Parse(in.Text)
	if len(parsed) == 0 {
		writeError(w, http.StatusBadRequest, "no valid rules found in input")
		return
	}
	category := normalizeCategory(in.Category)
	rules := make([]store.Rule, 0, len(parsed))
	for _, p := range parsed {
		rules = append(rules, store.Rule{Action: p.Action, Domain: p.Domain, Category: category})
	}
	n, err := s.store.AddRulesBulk(rules)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"imported": n})
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

// afterChange bumps the config version (so workers re-sync) and reloads the policy.
func (s *Server) afterChange() {
	if err := s.store.BumpConfigVersion(); err != nil {
		slog.Warn("bump config version failed", "err", err)
	}
	if s.reload == nil {
		return
	}
	if err := s.reload(); err != nil {
		slog.Warn("policy reload failed", "err", err)
	}
}

func normalizeCategory(c string) string {
	switch c {
	case "ads", "trackers", "malware", "custom":
		return c
	default:
		return "custom"
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
