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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/classifier"
	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/lists"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/netbird"
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
	store               *store.Store
	res                 *resolver.Resolver
	reload              func() error
	refresher           *lists.Refresher
	auth                *auth.Manager
	authEnabled         bool
	clusterEnabled      bool
	http                *http.Server
	statsCache          *ttlCache
	classifierAvailable bool // master only — classifier endpoints/tab are offered
	cls                 classifierStatus
	enricher            *netbird.Enricher
}

// classifierStatus exposes the classifier worker's runtime state to the API
// (list sizes, list search, WHOIS) without coupling to the concrete worker.
type classifierStatus interface {
	TrustedCount() int
	ThreatCount() int
	TrustedSearch(q string, limit int) []string
	ThreatSearch(q string, limit int) []string
	Whois(ctx context.Context, domain string) (classifier.WhoisInfo, error)
}

// SetClassifierStatus wires the running classifier worker into the API.
func (s *Server) SetClassifierStatus(cs classifierStatus) { s.cls = cs }

// SetEnricher wires the running NetBird/reverse-DNS client enricher into the API.
func (s *Server) SetEnricher(e *netbird.Enricher) { s.enricher = e }

// New constructs the HTTP server. In worker mode only /healthz and /metrics are
// served; in master mode the control-plane API and web UI are mounted, plus the
// cluster endpoints when clusterEnabled. reload rebuilds the resolver policy
// after every mutation.
func New(addr string, st *store.Store, res *resolver.Resolver, m *metrics.Metrics, reload func() error, refresher *lists.Refresher, authMgr *auth.Manager, authEnabled, worker, clusterEnabled bool) *Server {
	s := &Server{store: st, res: res, reload: reload, refresher: refresher, auth: authMgr, authEnabled: authEnabled, clusterEnabled: clusterEnabled, statsCache: newTTLCache(statsTTL), classifierAvailable: !worker}
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
		// The windowed aggregations are cached briefly (see ttlCache) so frequent
		// polling and multiple widgets don't recompute the same query_log slice.
		mux.HandleFunc("GET /api/stats/timeseries", s.requireRole(roleReadonly, s.cached(s.getTimeSeries)))
		mux.HandleFunc("GET /api/stats/categories", s.requireRole(roleReadonly, s.cached(s.getCategories)))
		mux.HandleFunc("GET /api/stats/category-traffic", s.requireRole(roleReadonly, s.cached(s.getCategoryTraffic)))
		mux.HandleFunc("GET /api/stats/insights", s.requireRole(roleReadonly, s.cached(s.getInsights)))
		mux.HandleFunc("GET /api/stats/latency", s.requireRole(roleReadonly, s.cached(s.getLatency)))
		mux.HandleFunc("GET /api/querylog", s.requireRole(roleReadonly, s.getQueryLog))
		mux.HandleFunc("GET /api/rules", s.requireRole(roleReadonly, s.listRules))
		mux.HandleFunc("POST /api/rules", s.requireRole(roleAdmin, s.addRule))
		mux.HandleFunc("POST /api/rules/import", s.requireRole(roleAdmin, s.importRules))
		mux.HandleFunc("DELETE /api/rules/{id}", s.requireRole(roleAdmin, s.deleteRule))
		mux.HandleFunc("GET /api/rewrites", s.requireRole(roleReadonly, s.listRewrites))
		mux.HandleFunc("POST /api/rewrites", s.requireRole(roleAdmin, s.addRewrite))
		mux.HandleFunc("DELETE /api/rewrites/{id}", s.requireRole(roleAdmin, s.deleteRewrite))

		// Managed lists + global block-pause ("protection").
		mux.HandleFunc("GET /api/lists", s.requireRole(roleReadonly, s.listLists))
		mux.HandleFunc("POST /api/lists/import", s.requireRole(roleAdmin, s.importList))
		mux.HandleFunc("POST /api/lists/url", s.requireRole(roleAdmin, s.addURLList))
		mux.HandleFunc("GET /api/lists/{id}/rules", s.requireRole(roleReadonly, s.listRulesForList))
		mux.HandleFunc("POST /api/lists/{id}/refresh", s.requireRole(roleAdmin, s.refreshList))
		mux.HandleFunc("PUT /api/lists/{id}", s.requireRole(roleAdmin, s.updateList))
		mux.HandleFunc("DELETE /api/lists/{id}", s.requireRole(roleAdmin, s.deleteList))
		mux.HandleFunc("GET /api/protection", s.requireRole(roleReadonly, s.getProtection))
		mux.HandleFunc("POST /api/protection/disable", s.requireRole(roleAdmin, s.disableProtection))
		mux.HandleFunc("POST /api/protection/enable", s.requireRole(roleAdmin, s.enableProtection))

		// LLM domain classifier.
		mux.HandleFunc("GET /api/classifier", s.requireRole(roleReadonly, s.getClassifier))
		mux.HandleFunc("GET /api/classifier/list", s.requireRole(roleReadonly, s.getList))
		mux.HandleFunc("PUT /api/classifier/settings", s.requireRole(roleAdmin, s.putClassifierSettings))
		mux.HandleFunc("POST /api/classifier/test", s.requireRole(roleAdmin, s.testClassifier))
		mux.HandleFunc("PUT /api/classifier/mode", s.requireRole(roleAdmin, s.setClassifierMode))
		mux.HandleFunc("GET /api/classifications", s.requireRole(roleReadonly, s.listClassifications))
		mux.HandleFunc("DELETE /api/classifications", s.requireRole(roleAdmin, s.clearClassifications))
		mux.HandleFunc("POST /api/classifications/decision", s.requireRole(roleAdmin, s.decideClassification))
		mux.HandleFunc("GET /api/classifier/whois", s.requireRole(roleReadonly, s.getWhois))
		mux.HandleFunc("GET /api/classifier/clients", s.requireRole(roleReadonly, s.getDomainClients))
		mux.HandleFunc("GET /api/clients", s.requireRole(roleReadonly, s.cached(s.getClients)))
		mux.HandleFunc("GET /api/clients/detail", s.requireRole(roleReadonly, s.cached(s.getClientDetail)))
		mux.HandleFunc("PUT /api/clients/name", s.requireRole(roleAdmin, s.putClientName))
		mux.HandleFunc("GET /api/clients/resolve", s.requireRole(roleReadonly, s.resolveClients))
		mux.HandleFunc("GET /api/netbird", s.requireRole(roleReadonly, s.getNetbird))
		mux.HandleFunc("PUT /api/netbird", s.requireRole(roleAdmin, s.putNetbird))
		mux.HandleFunc("POST /api/netbird/test", s.requireRole(roleAdmin, s.testNetbird))
		mux.HandleFunc("GET /api/reverse-dns", s.requireRole(roleReadonly, s.getReverseDNS))
		mux.HandleFunc("PUT /api/reverse-dns", s.requireRole(roleAdmin, s.putReverseDNS))

		mux.HandleFunc("GET /api/settings", s.requireRole(roleReadonly, s.getSettings))
		mux.HandleFunc("PUT /api/settings", s.requireRole(roleAdmin, s.putSettings))

		// Config backup / restore (admin): export everything as one JSON bundle.
		mux.HandleFunc("GET /api/config/export", s.requireRole(roleAdmin, s.exportConfig))
		mux.HandleFunc("POST /api/config/import", s.requireRole(roleAdmin, s.importConfig))

		// Account (self) + user management (admin).
		mux.HandleFunc("POST /api/auth/password", s.requireRole(roleReadonly, s.changePassword))
		mux.HandleFunc("GET /api/users", s.requireRole(roleAdmin, s.listUsers))
		mux.HandleFunc("POST /api/users", s.requireRole(roleAdmin, s.createUser))
		mux.HandleFunc("PUT /api/users/{id}/role", s.requireRole(roleAdmin, s.setUserRole))
		mux.HandleFunc("PUT /api/users/{id}/password", s.requireRole(roleAdmin, s.resetUserPassword))
		mux.HandleFunc("DELETE /api/users/{id}", s.requireRole(roleAdmin, s.deleteUser))

		// Cluster control plane (master only).
		if clusterEnabled {
			mux.HandleFunc("GET /api/cluster/nodes", s.requireRole(roleReadonly, s.clusterNodes))
			mux.HandleFunc("POST /api/cluster/nodes", s.requireRole(roleAdmin, s.addNode))
			mux.HandleFunc("POST /api/cluster/nodes/{name}/key", s.requireRole(roleAdmin, s.renewNodeKey))
			mux.HandleFunc("PUT /api/cluster/nodes/{name}/maintenance", s.requireRole(roleAdmin, s.setNodeMaintenance))
			mux.HandleFunc("DELETE /api/cluster/nodes/{name}", s.requireRole(roleAdmin, s.deleteNode))
			mux.HandleFunc("GET /api/cluster/snapshot", s.clusterSnapshot) // per-node key auth
			mux.HandleFunc("POST /api/cluster/log", s.clusterLog)          // per-node key auth
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
	ver := r.Header.Get("X-MazeDNS-Node-Version")
	addr := r.RemoteAddr
	if host, _, e := net.SplitHostPort(r.RemoteAddr); e == nil {
		addr = host
	}
	var st store.NodeStats
	if raw := r.Header.Get("X-MazeDNS-Stats"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	_ = s.store.TouchNode(node.Name, addr, ver, st)

	// Workers receive the effective rule set (active rules + enforced AI verdicts
	// as deny rules) so list enable/disable, refreshes, and AI auto-blocks all
	// propagate without the worker needing the lists/classifications tables.
	rules, err := s.store.ReplicatedRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rewrites, err := s.store.ListRewrites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	version, _ := s.store.ConfigVersion()
	pausedUntil, _ := s.store.GetBlockPausedUntil()
	if rules == nil {
		rules = []store.Rule{}
	}
	if rewrites == nil {
		rewrites = []store.Rewrite{}
	}
	writeJSON(w, http.StatusOK, cluster.Snapshot{Version: version, Rules: rules, Rewrites: rewrites, PausedUntil: pausedUntil, Maintenance: node.Maintenance})
}

// nodeFromKey authenticates a worker by its Bearer node key, or returns nil.
func (s *Server) nodeFromKey(r *http.Request) *store.Node {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return nil
	}
	node, err := s.store.NodeByKeyHash(hashKey(strings.TrimPrefix(h, prefix)))
	if err != nil {
		return nil
	}
	return node
}

// clusterLog ingests a batch of query-log entries shipped by a worker and stores
// them tagged with the worker's node name (node-key auth).
func (s *Server) clusterLog(w http.ResponseWriter, r *http.Request) {
	node := s.nodeFromKey(r)
	if node == nil {
		writeError(w, http.StatusUnauthorized, "invalid node key")
		return
	}
	var entries []store.QueryLogEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&entries); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.InsertNodeQueryLog(node.Name, entries); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ingested": len(entries)})
}

func (s *Server) clusterNodes(w http.ResponseWriter, _ *http.Request) {
	workers, err := s.store.ListNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Prepend the master itself as a node so the cluster view counts it (it is a
	// resolver too). The master is always "online" — its last_seen is now.
	total, blocked, cached, forwarded, rewritten, errs := s.res.StatsSnapshot()
	ver, _ := s.store.ConfigVersion()
	master := store.Node{
		Name:        "master",
		Version:     ver,
		LastSeen:    time.Now().Unix(),
		IsMaster:    true,
		Maintenance: s.store.MasterMaintenance(),
		NodeStats: store.NodeStats{
			Total: int64(total), Blocked: int64(blocked), Cached: int64(cached),
			Forwarded: int64(forwarded), Rewritten: int64(rewritten), Errors: int64(errs),
		},
	}
	nodes := append([]store.Node{master}, workers...)
	writeJSON(w, http.StatusOK, nodes)
}

// setNodeMaintenance toggles a node's drain (maintenance) flag. The master applies
// it to its own resolver immediately; a worker picks up its flag on the next poll.
func (s *Server) setNodeMaintenance(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if name == "master" {
		if err := s.store.SetMasterMaintenance(in.On); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.res.SetMaintenance(in.On)
	} else {
		if err := s.store.SetNodeMaintenance(name, in.On); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "maintenance": in.On})
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

// renewNodeKey rotates a worker's API key, returning the new key once. The old
// key stops working immediately; update the worker's MAZEDNS_NODE_KEY.
func (s *Server) renewNodeKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" || name == "master" {
		writeError(w, http.StatusBadRequest, "the master has no key to renew")
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
	if err := s.store.UpdateNodeKey(name, hashKey(key), prefix); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "key": key})
}

// ---- auth handlers ----

func (s *Server) authInfo(w http.ResponseWriter, _ *http.Request) {
	enabled := false
	if s.classifierAvailable {
		enabled = classifier.LoadSettings(s.store, classifier.Settings{}).Enabled
	}
	oidcOn := s.authEnabled && s.auth.OIDCEnabled()
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_enabled":            s.authEnabled,
		"oidc_enabled":            oidcOn,
		"password_login_disabled": oidcOn && s.auth.OIDC().DisablePasswordLogin(),
		"oidc_auto_login":         oidcOn && s.auth.OIDC().AutoLogin(),
		"cluster_enabled":         s.clusterEnabled,
		"classifier_available":    s.classifierAvailable,
		"classifier_enabled":      enabled,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled {
		writeJSON(w, http.StatusOK, map[string]string{"status": "auth disabled"})
		return
	}
	// SSO-only: refuse local credential login when configured (and OIDC is up).
	if s.auth.OIDCEnabled() && s.auth.OIDC().DisablePasswordLogin() {
		writeError(w, http.StatusForbidden, "password login is disabled; sign in with SSO")
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
	// Enrich with source + avatar so the UI can hide password change for SSO
	// accounts and show the profile picture.
	source, avatar := "local", ""
	if full, _ := s.store.GetUserByID(u.ID); full != nil {
		source, avatar = full.Source, full.AvatarURL
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "username": u.Username, "role": u.Role,
		"source": source, "avatar_url": avatar,
	})
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
	// Log the exact redirect_uri sent — it must match the provider's registration
	// character-for-character (quoting it in the env is a common cause of mismatch).
	slog.Info("oidc login", "redirect_uri", s.auth.OIDC().RedirectURL())
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
	user, err := s.store.UpsertOIDCUser(claims.Subject, claims.Username, claims.Role, claims.Picture)
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
	points, err := s.store.QueryTimeSeries(since, step, parseNodes(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if points == nil {
		points = []store.SeriesPoint{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"step": step, "points": points})
}

// getLatency returns mean latency over time, overall and per node, for the
// latency chart (honours the node focus filter).
func (s *Server) getLatency(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	step := hours * 3600 / 48
	if step < 60 {
		step = 60
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	points, names, err := s.store.LatencyTimeSeries(since, step, parseNodes(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if points == nil {
		points = []store.LatencyPoint{}
	}
	if names == nil {
		names = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"step": step, "nodes": names, "points": points})
}

// getCategoryTraffic returns query volume folded into the AI content/security
// categories (social, streaming, ads, …) for the dashboard donut. Names are
// mapped to their registered domain and matched against the classifications;
// unmatched volume is reported as "uncategorized".
func (s *Server) getCategoryTraffic(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	names, err := s.store.TopQueryNames(since, parseNodes(r), 10000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	catMap, err := s.store.ClassificationCategoryMap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	totals := map[string]int64{}
	for _, n := range names {
		cat := catMap[classifier.RegisteredDomain(n.Name)]
		if cat == "" {
			cat = "uncategorized"
		}
		totals[cat] += n.Count
	}
	out := make([]store.CategoryCount, 0, len(totals))
	for cat, c := range totals {
		out = append(out, store.CategoryCount{Category: cat, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getCategories(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	cats, err := s.store.BlockedByCategory(since, parseNodes(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cats == nil {
		cats = []store.CategoryCount{}
	}
	writeJSON(w, http.StatusOK, cats)
}

// getInsights returns windowed KPIs for the dashboard in one round trip,
// merged cluster-wide: this node's breakdowns plus each worker's latest reported
// insights, plus a per-node query distribution (the master is a resolver too).
func (s *Server) getInsights(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	nodes := parseNodes(r)

	// Everything is computed from the unified query log (this node + entries
	// shipped by workers), so it is cluster-wide and exactly windowed.
	in, err := s.store.ComputeInsights(since, 12, nodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	byNode, err := s.store.QueriesByNode(since, nodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if byNode == nil {
		byNode = []store.NodeQueryCount{}
	}
	totals, err := s.store.WindowedTotals(since, nodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"unique_clients": in.UniqueClients,
		"avg_latency_ms": in.AvgLatencyMS,
		"clients":        in.Clients,
		"top_queried":    in.TopQueried,
		"top_blocked":    in.TopBlocked,
		"qtypes":         in.QTypes,
		"by_node":        byNode,
		"totals":         totals,
	})
}

// parseNodes reads a ?nodes=master,worker-a filter into store node values
// ("master" maps to "", the master's own entries). Empty = all nodes.
func parseNodes(r *http.Request) []string {
	raw := strings.TrimSpace(r.URL.Query().Get("nodes"))
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "master" {
			p = ""
		}
		out = append(out, p)
	}
	return out
}

func clampHours(s string) int {
	h, _ := strconv.Atoi(s)
	if h <= 0 {
		h = 24
	}
	if h > 24*90 {
		h = 24 * 90
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

// getQueryLog returns a filtered, sorted page of the query log. Query params:
// ?search= (name/client substring), ?action=, ?qtype=, ?category=, ?sort= (time|
// name|client|qtype|action|category|rcode|ms|node), ?desc=true, ?nodes=, ?limit/?offset.
func (s *Server) getQueryLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	var sinceMs int64
	if h, _ := strconv.Atoi(q.Get("hours")); h > 0 {
		sinceMs = time.Now().Add(-time.Duration(h) * time.Hour).UnixMilli()
	}
	entries, total, err := s.store.SearchQueryLog(store.QueryLogQuery{
		Search:   strings.TrimSpace(q.Get("search")),
		Action:   strings.TrimSpace(q.Get("action")),
		QType:    strings.TrimSpace(q.Get("qtype")),
		Category: strings.TrimSpace(q.Get("category")),
		Nodes:    parseNodes(r),
		SinceMs:  sinceMs,
		Sort:     strings.TrimSpace(q.Get("sort")),
		Desc:     q.Get("desc") == "true" || q.Get("desc") == "1",
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.QueryLogEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "total": total})
}

// listRules returns manual (non-list) rules; list-owned rules are viewed per
// list via GET /api/lists/{id}/rules.
func (s *Server) listRules(w http.ResponseWriter, _ *http.Request) {
	rules, err := s.store.ManualRules()
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
	// Wildcards are allowed only as a single leading "*." label.
	if strings.Contains(domain, "*") && (!strings.HasPrefix(domain, "*.") || strings.Contains(domain[2:], "*")) {
		writeError(w, http.StatusBadRequest, "wildcards must be a single leading label, e.g. *.example.com")
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

// afterChange reloads the local policy after a config mutation. The cluster
// version is a content hash (store.ConfigVersion), so workers detect the change
// on their next poll without an explicit bump.
func (s *Server) afterChange() {
	if s.reload == nil {
		return
	}
	if err := s.reload(); err != nil {
		slog.Warn("policy reload failed", "err", err)
	}
}

func normalizeCategory(c string) string {
	switch c {
	case "ads", "trackers", "malware", "phishing", "not-found", "custom":
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
