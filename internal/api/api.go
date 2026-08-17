// Package api serves the MazeDNS HTTP control plane, web UI, and Prometheus metrics.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

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
	"github.com/IPMaze/MazeDNS/internal/version"
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
	enqueue             func(string) // feed classifier from ingested agent logs (may be nil)
	enricher            *netbird.Enricher
	requireApproval     bool          // hold self-enrolled agents until an admin approves
	keyMaxAge           time.Duration // rotate a node's key once it exceeds this age (0 = disabled)
	keyGrace            time.Duration // overlap window a rotated-out node key stays valid
	// Login rate limiting (finding #2). loginRate keys fixed windows by IP and by
	// username; the limits are live-applied from CPSettings via applyCPSettings.
	loginRate     *keyedLimiter
	loginLimitMu  sync.RWMutex
	loginAttempts int
	loginWindow   time.Duration
	// First-boot setup mode (see setup.go). setupDone defaults true (no gating); main
	// calls EnableSetupMode to open the wizard on a fresh, admin-less control plane.
	setupDone atomic.Bool
	setupRate setupLimiter
	// rebuildOIDC swaps the running OIDC provider when SSO settings change (nil =
	// unsupported). Set by main, which owns the config→provider construction.
	rebuildOIDC func(store.OIDCSettings) error
	// procLogs holds recent process-log lines: the control plane's own slog ring
	// plus one shipped ring per agent (see logs.go).
	procLogs *procLogStore
}

// SetClusterEnrollment configures agent self-enrollment and per-node key rotation.
// requireApproval holds newly-joined agents until an admin approves them; keyMaxAge
// is the age after which the control plane rotates a node's key on its next poll
// (0 disables periodic rotation); keyGrace is how long the previous key stays valid
// after a rotation (the zero-downtime overlap). Enrollment secrets are UI-managed
// keys in the enroll_keys table, not a static config token.
func (s *Server) SetClusterEnrollment(requireApproval bool, keyMaxAge, keyGrace time.Duration) {
	s.requireApproval = requireApproval
	s.keyMaxAge = keyMaxAge
	if keyGrace <= 0 {
		keyGrace = 15 * time.Minute
	}
	s.keyGrace = keyGrace
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

// SetClassifierEnqueue wires the classifier's enqueue hook so domains arriving in
// agents' shipped query logs are fed to the classifier. On the control plane no
// DNS is served locally, so this ingest path is the classifier's source of newly
// seen domains.
func (s *Server) SetClassifierEnqueue(fn func(name string)) { s.enqueue = fn }

// SetEnricher wires the running NetBird/reverse-DNS client enricher into the API.
func (s *Server) SetEnricher(e *netbird.Enricher) { s.enricher = e }

// New constructs the HTTP server. In worker mode only /healthz and /metrics are
// served; in master mode the control-plane API and web UI are mounted, plus the
// cluster endpoints when clusterEnabled. reload rebuilds the resolver policy
// after every mutation.
func New(addr string, st *store.Store, res *resolver.Resolver, m *metrics.Metrics, reload func() error, refresher *lists.Refresher, authMgr *auth.Manager, authEnabled, worker, clusterEnabled bool) *Server {
	s := &Server{store: st, res: res, reload: reload, refresher: refresher, auth: authMgr, authEnabled: authEnabled, clusterEnabled: clusterEnabled, statsCache: newTTLCache(statsTTL), classifierAvailable: !worker, procLogs: newProcLogStore()}
	s.setupDone.Store(true) // no gating unless main calls EnableSetupMode
	// Login rate limiting seeded to the default; live-updated via applyCPSettings.
	s.loginRate = newKeyedLimiter()
	s.loginAttempts = defaultLoginRateAttempts
	s.loginWindow = defaultLoginRateWindow
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /metrics", s.metricsAuth(m.Handler()))

	if !worker {
		// First-boot setup wizard (guarded; see setup.go).
		mux.HandleFunc("GET /api/setup/status", s.setupStatus)
		mux.HandleFunc("POST /api/setup/complete", s.setupComplete)

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
		mux.HandleFunc("GET /api/stats/top-domains", s.requireRole(roleReadonly, s.cached(s.getTopDomains)))
		mux.HandleFunc("GET /api/querylog", s.requireRole(roleReadonly, s.getQueryLog))
		mux.HandleFunc("GET /api/rules", s.requireRole(roleReadonly, s.listRules))
		mux.HandleFunc("POST /api/rules", s.requireRole(roleAdmin, s.addRule))
		mux.HandleFunc("POST /api/rules/import", s.requireRole(roleAdmin, s.importRules))
		mux.HandleFunc("DELETE /api/rules/{id}", s.requireRole(roleAdmin, s.deleteRule))
		mux.HandleFunc("GET /api/rewrites", s.requireRole(roleReadonly, s.listRewrites))
		mux.HandleFunc("POST /api/rewrites", s.requireRole(roleAdmin, s.addRewrite))
		mux.HandleFunc("PUT /api/rewrites/{id}", s.requireRole(roleAdmin, s.updateRewrite))
		mux.HandleFunc("DELETE /api/rewrites/{id}", s.requireRole(roleAdmin, s.deleteRewrite))
		mux.HandleFunc("GET /api/forwarders", s.requireRole(roleReadonly, s.listForwarders))
		mux.HandleFunc("POST /api/forwarders", s.requireRole(roleAdmin, s.addForwarder))
		mux.HandleFunc("PUT /api/forwarders/{id}", s.requireRole(roleAdmin, s.updateForwarder))
		mux.HandleFunc("DELETE /api/forwarders/{id}", s.requireRole(roleAdmin, s.deleteForwarder))

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
		// Control-plane runtime settings (SSO, session TTL, cluster policy, general).
		mux.HandleFunc("GET /api/settings/cp", s.requireRole(roleAdmin, s.getCPSettings))
		mux.HandleFunc("PUT /api/settings/cp", s.requireRole(roleAdmin, s.putCPSettings))
		mux.HandleFunc("GET /api/settings/audit", s.requireRole(roleAdmin, s.getSettingsAudit))
		mux.HandleFunc("POST /api/settings/metrics-token", s.requireRole(roleAdmin, s.generateMetricsToken))
		mux.HandleFunc("DELETE /api/settings/metrics-token", s.requireRole(roleAdmin, s.clearMetricsToken))
		mux.HandleFunc("GET /api/metrics/export", s.requireRole(roleReadonly, s.getMetricsExport))
		mux.HandleFunc("PUT /api/metrics/export", s.requireRole(roleAdmin, s.putMetricsExport))
		mux.HandleFunc("GET /api/logs/export", s.requireRole(roleReadonly, s.getLogsExport))
		mux.HandleFunc("PUT /api/logs/export", s.requireRole(roleAdmin, s.putLogsExport))
		// Process logs (control plane + shipped agent rings). Admin: the lines can
		// contain client IPs and login usernames.
		mux.HandleFunc("GET /api/logs", s.requireRole(roleAdmin, s.getLogs))

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
			mux.HandleFunc("GET /api/version", s.requireRole(roleReadonly, s.serverVersion))
			mux.HandleFunc("GET /api/cluster/nodes", s.requireRole(roleReadonly, s.clusterNodes))
			mux.HandleFunc("POST /api/cluster/nodes", s.requireRole(roleAdmin, s.addNode))
			mux.HandleFunc("POST /api/cluster/nodes/{id}/key", s.requireRole(roleAdmin, s.renewNodeKey))
			mux.HandleFunc("PUT /api/cluster/nodes/{id}/maintenance", s.requireRole(roleAdmin, s.setNodeMaintenance))
			mux.HandleFunc("PUT /api/cluster/nodes/{id}/approve", s.requireRole(roleAdmin, s.approveNode))
			mux.HandleFunc("PUT /api/cluster/nodes/{id}/site", s.requireRole(roleAdmin, s.setNodeSite))
			mux.HandleFunc("PUT /api/cluster/nodes/{id}/name", s.requireRole(roleAdmin, s.renameNode))
			mux.HandleFunc("GET /api/cluster/sites", s.requireRole(roleReadonly, s.listSites))
			mux.HandleFunc("POST /api/cluster/sites", s.requireRole(roleAdmin, s.createSite))
			mux.HandleFunc("DELETE /api/cluster/sites/{name}", s.requireRole(roleAdmin, s.deleteSite))
			mux.HandleFunc("DELETE /api/cluster/nodes/{id}", s.requireRole(roleAdmin, s.deleteNode))
			mux.HandleFunc("GET /api/cluster/revoked", s.requireRole(roleAdmin, s.listRevoked))
			mux.HandleFunc("DELETE /api/cluster/revoked/{id}", s.requireRole(roleAdmin, s.unrevokeNode))
			mux.HandleFunc("GET /api/cluster/enroll-keys", s.requireRole(roleAdmin, s.listEnrollKeys))
			mux.HandleFunc("POST /api/cluster/enroll-keys", s.requireRole(roleAdmin, s.createEnrollKey))
			mux.HandleFunc("DELETE /api/cluster/enroll-keys/{id}", s.requireRole(roleAdmin, s.revokeEnrollKey))
			mux.HandleFunc("POST /api/cluster/enroll", s.clusterEnroll)      // enrollment-key auth
			mux.HandleFunc("GET /api/cluster/snapshot", s.clusterSnapshot)   // per-node key auth
			mux.HandleFunc("POST /api/cluster/log", s.clusterLog)            // per-node key auth
			mux.HandleFunc("POST /api/cluster/proclog", s.clusterProcLog)    // per-node key auth
		}

		mux.Handle("/", web.Handler()) // SPA + static assets (embedded with -tags embed_dist)
	}

	s.http = &http.Server{
		Addr:              addr,
		Handler:           logRequests(s.setupGate(mux)),
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

// validAdvertiseAddr reports whether s is a bare IP or a host:port whose host is an
// IP. The advertised address is displayed and written into generated client config,
// so a node may only report an IP-literal address — never an arbitrary hostname or
// injected string.
func validAdvertiseAddr(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	if _, perr := strconv.Atoi(port); perr != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

// nodeReclaimAfter is how long a node must have been silent before an agent
// presenting the same NAME (with a valid enrollment key but no id — its /data was
// lost) may reclaim that node's identity instead of enrolling as a "<name>-2"
// duplicate. Serving agents poll every few seconds, so two minutes of silence
// means the old container is really gone. Var (not const) so tests can shrink it.
var nodeReclaimAfter = 2 * time.Minute

// clusterEnroll lets an agent self-register using a UI-managed enrollment key. On
// success it issues a fresh per-node API key (returned once, in clear) which the
// agent persists locally alongside the node's immutable id.
//
// Security model: a node's identity is its server-generated UUID, not its name or
// the enrollment key. An enrollment key alone can only CREATE a new node — or
// RECLAIM an OFFLINE node with the exact same name (see the reclaim block below;
// this is what keeps an image update from minting "<name>-2" duplicates). It can
// never displace a live node. To rotate the key of an existing node (recovery
// after a hostname change or a rejected key) the agent must present BOTH that
// node's id AND its current node key as proof of possession.
//
//   - no id, name free           -> new node; CONSUMES one use of a valid enrollment key
//   - no id, name of an OFFLINE node -> reclaim that node (rotate key in place;
//     valid enrollment key required but not consumed)
//   - no id, name of a LIVE node -> 409 name_in_use (agent retries), unless
//     suffix_ok, which creates "<name>-2" (consumes a use)
//   - id + matching current key  -> rotate key in place; enrollment key must be VALID
//     but is not consumed (recovery of an authorized node)
//   - id + missing/wrong key     -> 403 (ownership not proven)
//   - id not found (CP reset)    -> new node (consumes a use)
//
// An expired, revoked, or exhausted enrollment key never creates or rotates any
// node. Enrollment keys authenticate ONLY here — never snapshot/log — because they
// live in their own table and node auth only ever checks node keys.
func (s *Server) clusterEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Token   string `json:"token"`    // the enrollment-key secret
		NodeID  string `json:"node_id"`  // '' on first enrollment; the agent's persisted id thereafter
		NodeKey string `json:"node_key"` // the agent's current key — ownership proof for a re-enroll
		// SuffixOK opts in to the "<name>-2" de-duplication when the name is held
		// by a live node. Agents set it only after their name-reclaim retries are
		// exhausted, so an image update no longer mints duplicate nodes.
		SuffixOK bool `json:"suffix_ok"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if name == "master" || name == "control-plane" {
		writeError(w, http.StatusBadRequest, "reserved node name")
		return
	}
	tokenHash := hashKey(strings.TrimSpace(in.Token))
	now := time.Now().Unix()
	key, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	prefix := keyPrefix(key)

	// Re-enroll path: the agent claims an existing identity. The enrollment key must
	// be valid (but is NOT consumed — this is recovery of an already-authorized node,
	// not a new join), and the agent must prove it owns the id with its current key.
	if id := strings.TrimSpace(in.NodeID); id != "" {
		// Revocation gate: a node removed with "revoke" leaves a tombstone. Refuse it
		// BEFORE any enrollment-key use is consumed, so a decommissioned/compromised
		// agent can't rejoin (as a new node) by burning key uses each poll. Checked for
		// the presented id only; an unknown, non-tombstoned id still self-heals below.
		if rn, rerr := s.store.RevokedNodeByID(id); rerr != nil {
			writeError(w, http.StatusInternalServerError, rerr.Error())
			return
		} else if rn != nil {
			slog.Warn("cluster enroll rejected: node revoked", "id", id, "name", rn.Name, "remote", clientIP(r))
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "node revoked", "revoked": true})
			return
		}
		existing, err := s.store.NodeByID(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if existing != nil {
			valid, ekPrefix, err := s.store.EnrollKeyValid(tokenHash, now)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !valid {
				slog.Warn("cluster re-enroll rejected: invalid enrollment key", "id", id, "name", existing.Name)
				writeError(w, http.StatusUnauthorized, "invalid, expired, revoked, or exhausted enrollment key")
				return
			}
			if in.NodeKey == "" || subtle.ConstantTimeCompare([]byte(hashKey(in.NodeKey)), []byte(existing.KeyHash)) != 1 {
				// The enrollment key alone must not rotate an existing node's key.
				slog.Warn("cluster re-enroll rejected: ownership not proven", "id", id, "name", existing.Name)
				writeError(w, http.StatusForbidden, "node id in use; the current node key is required to re-enroll")
				return
			}
			if err := s.store.RotateNodeKeyByID(existing.ID, hashKey(key), prefix); err != nil {
				writeError(w, http.StatusInternalServerError, "key rotation failed: "+err.Error())
				return
			}
			slog.Info("cluster node re-enrolled (key rotated)", "id", existing.ID, "name", existing.Name, "enroll_key", ekPrefix)
			writeJSON(w, http.StatusOK, map[string]any{
				"id": existing.ID, "name": existing.Name, "key": key,
				"approved": existing.Approved, "cp_address": s.store.MasterAdvertiseAddr(),
			})
			return
		}
		// id not found (control plane DB was reset, or a stale id): fall through and
		// enroll as a brand-new node (which consumes a use).
	}

	// Name-based identity reclaim: the agent presented no usable id (its /data was
	// lost — image updated without the volume, host rebuilt) but a node with this
	// exact name already exists. Creating a fresh node would leave the operator
	// with a duplicated "<name>-2" entry, so instead:
	//
	//   - existing node OFFLINE      -> reclaim: rotate its key in place and hand
	//     its identity (id, site/role, approval, stats) to the new agent. The
	//     enrollment key must be VALID but is NOT consumed (recovery, not a join).
	//   - existing node looks ALIVE  -> 409 {"name_in_use":true}; the agent waits
	//     and retries — during an image update the old container stops polling
	//     within the reclaim window. Only when the caller opts in via suffix_ok
	//     (its retries exhausted: two live hosts genuinely share the name) does
	//     the old "<name>-2" de-duplication below apply.
	//
	// Deliberate trade-off: a valid enrollment key + a known node name can take
	// over an OFFLINE node's identity. It can never displace a serving node (the
	// freshness check), every reclaim is audited, and a displaced agent that comes
	// back fails auth loudly (its key was rotated away) instead of silently
	// splitting the identity.
	if existing, nerr := s.store.NodeByName(name); nerr != nil {
		writeError(w, http.StatusInternalServerError, nerr.Error())
		return
	} else if existing != nil {
		valid, ekPrefix, verr := s.store.EnrollKeyValid(tokenHash, now)
		if verr != nil {
			writeError(w, http.StatusInternalServerError, verr.Error())
			return
		}
		if !valid {
			writeError(w, http.StatusUnauthorized, "invalid, expired, revoked, or exhausted enrollment key")
			return
		}
		if now-existing.LastSeen >= int64(nodeReclaimAfter/time.Second) {
			if err := s.store.RotateNodeKeyByID(existing.ID, hashKey(key), prefix); err != nil {
				writeError(w, http.StatusInternalServerError, "key rotation failed: "+err.Error())
				return
			}
			slog.Info("cluster node reclaimed by name (agent lost its identity — e.g. image update without /data)",
				"id", existing.ID, "name", existing.Name, "enroll_key", ekPrefix, "remote", clientIP(r))
			_ = s.store.AppendAudit(store.AuditEntry{User: "node:" + existing.Name, Action: "cluster.node.reclaim",
				Detail: fmt.Sprintf("node %s (%s) identity reclaimed via enrollment key %s from %s", existing.Name, existing.ID, ekPrefix, clientIP(r))})
			writeJSON(w, http.StatusOK, map[string]any{
				"id": existing.ID, "name": existing.Name, "key": key,
				"approved": existing.Approved, "cp_address": s.store.MasterAdvertiseAddr(),
			})
			return
		}
		if !in.SuffixOK {
			slog.Warn("cluster enroll: name held by a live node — told agent to retry", "name", name, "remote", clientIP(r))
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "node name in use by a live node", "name_in_use": true,
			})
			return
		}
	}

	// New enrollment: atomically consume one use of a valid enrollment key. This
	// rejects expired/revoked/exhausted keys and makes max_uses race-proof.
	consumed, err := s.store.ConsumeEnrollKey(tokenHash, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !consumed {
		writeError(w, http.StatusUnauthorized, "invalid, expired, revoked, or exhausted enrollment key")
		return
	}
	// Allocate a server-side id and de-duplicate the display name so a new host that
	// happens to share a hostname never collides with — or hijacks — an existing node.
	// Retry on the name-uniqueness race (two concurrent enrolls picking the same
	// candidate) so a consumed enrollment-key use isn't wasted on a lost insert.
	id := uuid.NewString()
	var createErr error
	for attempt := 0; attempt < 5; attempt++ {
		var unique string
		unique, err = s.uniqueNodeName(name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if createErr = s.store.CreateNodeWithID(id, unique, hashKey(key), prefix, !s.requireApproval); createErr == nil {
			name = unique
			break
		}
	}
	if createErr != nil {
		writeError(w, http.StatusInternalServerError, "enroll failed: "+createErr.Error())
		return
	}
	slog.Info("cluster node self-enrolled", "id", id, "name", name, "approved", !s.requireApproval)
	// cp_address (if the control plane has a configured advertise address) lets the
	// agent pin the CP's fixed IP for all later polls — see cmd/dns-agent.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "name": name, "key": key, "approved": !s.requireApproval, "cp_address": s.store.MasterAdvertiseAddr(),
	})
}

// sanitizeVersion bounds a self-reported version string for display: printable
// ASCII only, max 64 chars, anything else dropped.
func sanitizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 64 {
		v = v[:64]
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return ""
		}
	}
	return v
}

// keyPrefix returns the short display prefix (first 8 chars) of a generated key.
func keyPrefix(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}

// listEnrollKeys returns all enrollment keys (secrets never included).
func (s *Server) listEnrollKeys(w http.ResponseWriter, _ *http.Request) {
	keys, err := s.store.ListEnrollKeys()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

// createEnrollKey mints a new enrollment key, returning its secret exactly once.
// ttl_hours (0 = never) sets the expiry; max_uses (0 = unlimited) caps how many
// nodes may join with it.
func (s *Server) createEnrollKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		TTLHours int64  `json:"ttl_hours"`
		MaxUses  int64  `json:"max_uses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	var expiresAt int64
	if in.TTLHours > 0 {
		expiresAt = time.Now().Add(time.Duration(in.TTLHours) * time.Hour).Unix()
	}
	maxUses := in.MaxUses
	if maxUses < 0 {
		maxUses = 0
	}
	id := uuid.NewString()
	createdBy := ""
	if u, ok := s.currentUser(r); ok {
		createdBy = u
	}
	if err := s.store.CreateEnrollKey(id, strings.TrimSpace(in.Name), hashKey(secret), keyPrefix(secret), createdBy, expiresAt, maxUses); err != nil {
		writeError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	slog.Info("cluster enrollment key created", "id", id, "prefix", keyPrefix(secret), "by", createdBy, "expires_at", expiresAt, "max_uses", maxUses)
	// The secret is shown only here — it is stored hashed.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "name": strings.TrimSpace(in.Name), "key": secret, "key_prefix": keyPrefix(secret),
		"expires_at": expiresAt, "max_uses": maxUses,
	})
}

// revokeEnrollKey disables an enrollment key immediately.
func (s *Server) revokeEnrollKey(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeEnrollKey(r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// currentUser returns the authenticated username, if auth is enabled.
func (s *Server) currentUser(r *http.Request) (string, bool) {
	if !s.authEnabled || s.auth == nil {
		return "", false
	}
	u, ok := s.auth.UserFromRequest(r)
	if !ok {
		return "", false
	}
	return u.Username, true
}

// uniqueNodeName returns name, or name with a numeric suffix if a different node
// already uses it — so a self-enrolling host can always join without touching the
// existing node that holds the name.
func (s *Server) uniqueNodeName(name string) (string, error) {
	candidate := name
	for i := 2; ; i++ {
		existing, err := s.store.NodeByName(candidate)
		if err != nil {
			return "", err
		}
		if existing == nil {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s-%d", name, i)
	}
}

// approveNode admits a pending self-enrolled node (or re-holds it).
func (s *Server) approveNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Approved bool `json:"approved"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.SetNodeApproved(id, in.Approved); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "approved": in.Approved})
}

// renameNode changes a node's display label. Identity (the id) is unchanged and
// the node's history (tagged by name) follows the rename — see store.RenameNode.
func (s *Server) renameNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "master" || name == "control-plane" {
		writeError(w, http.StatusBadRequest, "reserved node name")
		return
	}
	if err := s.store.RenameNode(id, name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": name})
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
	node, viaCurrent, err := s.store.NodeByAnyKeyHash(hashKey(strings.TrimPrefix(h, prefix)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil {
		writeError(w, http.StatusUnauthorized, "invalid node key")
		return
	}
	if !node.Approved {
		writeError(w, http.StatusForbidden, "node pending approval")
		return
	}
	// Server-driven key rotation runs on the authenticated poll (see maybeRotate).
	newNodeKey := s.maybeRotateNodeKey(node, viaCurrent)
	ver := r.Header.Get("X-MazeDNS-Node-Version")
	// clientIP honors X-Forwarded-For / X-Real-IP: behind a reverse proxy the TCP
	// RemoteAddr is the proxy's container IP for EVERY agent (all nodes showing
	// the same 172.18.x.x), while the forwarding header carries each agent's
	// real source address.
	addr := clientIP(r)
	// Prefer the node's self-reported site-reachable address (MAZEDNS_ADVERTISE_ADDR):
	// the TCP RemoteAddr is often a docker-internal IP that doesn't exist on the LAN.
	// It is attacker-controllable (a node key holder sets it) and is displayed and
	// fed into generated client config, so validate it as an IP (or host:port with an
	// IP) and ignore anything malformed rather than trusting it verbatim.
	if adv := strings.TrimSpace(r.Header.Get("X-MazeDNS-Advertise-Addr")); adv != "" {
		if validAdvertiseAddr(adv) {
			addr = adv
		} else {
			slog.Warn("ignoring invalid advertised address", "node", node.ID, "name", node.Name, "value", adv)
		}
	}
	// Audit when a node's advertised (displayed) address changes value — it feeds the
	// generated client config, so a change is security-relevant.
	if node.Address != "" && addr != node.Address {
		_ = s.store.AppendAudit(store.AuditEntry{
			User: "node:" + node.Name, Action: "cluster.node.address",
			Detail: fmt.Sprintf("node %s advertised address changed %s -> %s", node.Name, node.Address, addr),
		})
	}
	var st store.NodeStats
	if raw := r.Header.Get("X-MazeDNS-Stats"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	// The running binary's build version, self-reported and display-only; bound
	// and sanitized so a rogue node can't inject junk into the UI.
	appVer := sanitizeVersion(r.Header.Get("X-MazeDNS-App-Version"))
	_ = s.store.TouchNode(node.ID, addr, ver, appVer, st)

	// Workers receive the effective rule set (active rules + enforced AI verdicts
	// as deny rules) so list enable/disable, refreshes, and AI auto-blocks all
	// propagate without the worker needing the lists/classifications tables.
	rules, err := s.store.ReplicatedRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rewrites, err := s.store.ListRewritesForNode(node.Name, node.Site)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	forwarders, err := s.store.ListForwardersForNode(node.Name, node.Site)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	version, _ := s.store.ConfigVersionForNode(node.Name, node.Site)
	pausedUntil, _ := s.store.GetBlockPausedUntil()
	if rules == nil {
		rules = []store.Rule{}
	}
	if rewrites == nil {
		rewrites = []store.Rewrite{}
	}
	// NodeID lets an already-deployed agent that has a key but no stored id (upgraded
	// from a pre-UUID build) learn its id transparently and persist it, without
	// re-enrolling — so it can prove ownership on a future re-enroll. NewNodeKey is
	// set only when the control plane rotated the key on this poll; the agent
	// persists it and authenticates with it from the next request.
	writeJSON(w, http.StatusOK, cluster.Snapshot{NodeID: node.ID, NewNodeKey: newNodeKey, Version: version, Rules: rules, Rewrites: rewrites, Forwarders: forwarders, PausedUntil: pausedUntil, Maintenance: node.Maintenance})
}

// maybeRotateNodeKey implements server-driven per-node key rotation on an
// authenticated snapshot poll. It returns a fresh key (to hand back to the agent
// once) when a rotation happens, or "" otherwise. The state machine:
//
//   - authed via the CURRENT key, and a grace (previous) key is still lingering ->
//     the agent has adopted the new key, so retire the previous one immediately
//     ("valid until first use of the new key").
//   - authed via the CURRENT key and it has exceeded keyMaxAge -> issue a new key,
//     keep the just-replaced key valid for keyGrace (zero-downtime overlap).
//   - authed via the GRACE key -> the agent never persisted the last issued key
//     (crash/lost response). Re-issue a fresh key while keeping the same overlap
//     window, so the old key keeps working and the agent recovers on any poll.
//
// The node's row already carries the state; we mutate it in place so callers that
// read `node` afterward (TouchNode) see the new id/hash consistently.
func (s *Server) maybeRotateNodeKey(node *store.Node, viaCurrent bool) string {
	now := time.Now()
	if viaCurrent {
		if node.PrevKeyHash != "" {
			// New key confirmed in use — drop the old one now.
			_ = s.store.ConfirmKeyRotation(node.ID)
			node.PrevKeyHash, node.PrevKeyExpiresAt = "", 0
		}
		if s.keyMaxAge <= 0 || now.Unix()-node.KeyIssuedAt < int64(s.keyMaxAge.Seconds()) {
			return "" // rotation disabled or key still fresh
		}
		newKey, err := auth.NewToken()
		if err != nil {
			slog.Warn("cluster key rotation: key generation failed", "id", node.ID, "err", err)
			return ""
		}
		grace := now.Add(s.keyGrace).Unix()
		if err := s.store.RotateNodeKey(node.ID, hashKey(newKey), keyPrefix(newKey), node.KeyHash, grace, now.Unix()); err != nil {
			slog.Warn("cluster key rotation failed", "id", node.ID, "err", err)
			return ""
		}
		slog.Info("cluster node key rotated (age policy)", "id", node.ID, "name", node.Name,
			"old_prefix", node.KeyPrefix, "new_prefix", keyPrefix(newKey), "grace", s.keyGrace)
		return newKey
	}
	// Authed via the grace key: the agent hasn't adopted the issued key yet. Re-issue
	// a fresh one, keeping the original overlap window (do not extend it), so a crash
	// between issue and persist recovers without ever locking the node out.
	newKey, err := auth.NewToken()
	if err != nil {
		slog.Warn("cluster key re-issue: key generation failed", "id", node.ID, "err", err)
		return ""
	}
	if err := s.store.RotateNodeKey(node.ID, hashKey(newKey), keyPrefix(newKey), node.PrevKeyHash, node.PrevKeyExpiresAt, now.Unix()); err != nil {
		slog.Warn("cluster key re-issue failed", "id", node.ID, "err", err)
		return ""
	}
	slog.Info("cluster node key re-issued (agent had not adopted the rotated key)", "id", node.ID, "name", node.Name,
		"new_prefix", keyPrefix(newKey))
	return newKey
}

// nodeFromKey authenticates a worker by its Bearer node key (current or a
// still-valid grace key during rotation), or returns nil.
func (s *Server) nodeFromKey(r *http.Request) *store.Node {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return nil
	}
	node, _, err := s.store.NodeByAnyKeyHash(hashKey(strings.TrimPrefix(h, prefix)))
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
	if !node.Approved {
		writeError(w, http.StatusForbidden, "node pending approval")
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
	if s.enqueue != nil {
		for _, e := range entries {
			s.enqueue(e.Name)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ingested": len(entries)})
}

// serverVersion reports the control plane's own build version (the reference the
// UI compares each agent's app_version against to flag out-of-date nodes) and the
// current replicated-config version (the rules hash agents should have applied).
func (s *Server) serverVersion(w http.ResponseWriter, _ *http.Request) {
	cfgVer, _ := s.store.ConfigVersion()
	writeJSON(w, http.StatusOK, map[string]string{
		"version":        version.Short(),
		"config_version": cfgVer,
	})
}

// clusterNodes lists the enrolled DNS agents. The control plane itself is not a
// resolver, so it does not appear here — the cluster view is the data plane only.
// Each node carries its expected (per-node) config version: scoped rewrites and
// forwarders mean there is no single cluster-wide version to compare against.
func (s *Server) clusterNodes(w http.ResponseWriter, _ *http.Request) {
	nodes, err := s.store.ListNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type nodeStatus struct {
		store.Node
		ExpectedVersion string `json:"expected_version"`
	}
	versions, err := s.store.ConfigVersionsForNodes(nodes)
	if err != nil {
		versions = nil // fall back to empty per-node versions, same as today's swallowed error
	}
	out := make([]nodeStatus, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, nodeStatus{Node: n, ExpectedVersion: versions[n.Name]})
	}
	writeJSON(w, http.StatusOK, out)
}

// setNodeMaintenance toggles an agent's drain (maintenance) flag. The agent picks
// it up on its next config poll and starts/stops answering SERVFAIL.
func (s *Server) setNodeMaintenance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.SetNodeMaintenance(id, in.On); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "maintenance": in.On})
}

// listSites returns the configured sites (named node groups).
func (s *Server) listSites(w http.ResponseWriter, _ *http.Request) {
	sites, err := s.store.ListSites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sites)
}

// createSite adds (or re-describes) a site.
func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.CreateSite(in.Name, in.Description); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": strings.TrimSpace(in.Name)})
}

// deleteSite removes a site and unassigns its nodes.
func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSite(r.PathValue("name")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": r.PathValue("name")})
}

// setNodeSite assigns a node (by id) to a site with a role (primary/secondary/backup).
// Roles are advisory labels — every agent still serves DNS.
func (s *Server) setNodeSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Site string `json:"site"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	err := s.store.SetNodeSite(id, in.Site, in.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "site": strings.TrimSpace(in.Site), "role": in.Role})
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
	id, err := s.store.CreateNode(name, hashKey(key), keyPrefix(key))
	if err != nil {
		writeError(w, http.StatusConflict, "could not create node (name in use?): "+err.Error())
		return
	}
	// The key is shown only here — it is stored hashed.
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "name": name, "key": key})
}

// deleteNode removes an agent. ?revoke=true (the default) additionally tombstones
// the node id so a still-running agent can't rejoin under its current identity;
// ?revoke=false is a plain removal for intentional agent replacement (the agent may
// re-enroll as a brand-new node). Admin only, audit-logged.
func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	revoke := r.URL.Query().Get("revoke") != "false" // default: revoke
	node, _ := s.store.NodeByID(id)
	name := id
	if node != nil {
		name = node.Name
	}
	if err := s.store.DeleteNode(id, revoke, auditUser(s, r)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.procLogs.forget(id)
	action := "removed"
	if revoke {
		action = "removed and revoked"
	}
	_ = s.store.AppendAudit(store.AuditEntry{
		User: auditUser(s, r), Action: "cluster.node.delete",
		Detail: fmt.Sprintf("%s node %s (%s)", action, name, id),
	})
	slog.Info("cluster node "+action, "id", id, "name", name)
	w.WriteHeader(http.StatusNoContent)
}

// listRevoked returns the revocation tombstones (admin only).
func (s *Server) listRevoked(w http.ResponseWriter, _ *http.Request) {
	revoked, err := s.store.ListRevokedNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, revoked)
}

// unrevokeNode deletes a node's revocation tombstone. Two intents share the
// route: the default un-revoke (the agent may rejoin as a new node on its next
// enrollment attempt), and ?forever=true, which permanently deletes the revoked
// agent's record — same tombstone removal, but audited as a purge and meant as
// "forget this agent", not "let it back in". Either way, re-joining requires a
// valid enrollment key. Admin only, audit-logged.
func (s *Server) unrevokeNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	forever := r.URL.Query().Get("forever") == "true"
	rn, _ := s.store.RevokedNodeByID(id)
	removed, err := s.store.UnrevokeNode(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "no revocation for that node")
		return
	}
	s.procLogs.forget(id)
	name := id
	if rn != nil {
		name = rn.Name
	}
	if forever {
		_ = s.store.AppendAudit(store.AuditEntry{
			User: auditUser(s, r), Action: "cluster.node.purge",
			Detail: fmt.Sprintf("permanently deleted revoked node %s (%s)", name, id),
		})
		slog.Info("cluster revoked node permanently deleted", "id", id, "name", name)
	} else {
		_ = s.store.AppendAudit(store.AuditEntry{
			User: auditUser(s, r), Action: "cluster.node.unrevoke",
			Detail: fmt.Sprintf("un-revoked node %s (%s)", name, id),
		})
		slog.Info("cluster node un-revoked", "id", id, "name", name)
	}
	w.WriteHeader(http.StatusNoContent)
}

// renewNodeKey manually rotates a worker's API key (by node id), returning the new
// key once. The previous key stays valid for the rotation grace window so a running
// agent isn't locked out: on its next poll it authenticates via the old key and the
// control plane hands it a fresh key automatically (no downtime, no re-enroll). The
// returned key is for the manual MAZEDNS_NODE_KEY path (e.g. a node not yet running).
func (s *Server) renewNodeKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "node id required")
		return
	}
	node, err := s.store.NodeByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	key, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	now := time.Now()
	grace := now.Add(s.keyGrace).Unix()
	if err := s.store.RotateNodeKey(id, hashKey(key), keyPrefix(key), node.KeyHash, grace, now.Unix()); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	slog.Info("cluster node key rotated (manual)", "id", id, "name", node.Name, "old_prefix", node.KeyPrefix, "new_prefix", keyPrefix(key))
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "key": key})
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
		"setup_required":          s.setupActive(),
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
	// Rate limit per source IP and per username (fixed window; limits from the GUI).
	if attempts, window := s.loginLimits(); attempts > 0 {
		ip := clientIP(r)
		uname := strings.ToLower(strings.TrimSpace(in.Username))
		if !s.loginRate.allow("ip:"+ip, attempts, window) || !s.loginRate.allow("user:"+uname, attempts, window) {
			slog.Warn("login rate limited", "remote", ip, "user", in.Username)
			w.Header().Set("Retry-After", strconv.Itoa(int(window.Seconds())))
			writeError(w, http.StatusTooManyRequests, "too many login attempts; try again shortly")
			return
		}
	}
	token, user, err := s.auth.Login(in.Username, in.Password)
	if err != nil {
		slog.Warn("login failed", "remote", clientIP(r), "user", in.Username)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.auth.SetCookie(w, r, token)
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.authEnabled {
		s.auth.Logout(r)
		s.auth.ClearCookie(w, r)
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
		Secure: auth.RequestIsHTTPS(r), SameSite: http.SameSiteLaxMode, MaxAge: 300,
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
	s.auth.SetCookie(w, r, token)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- data handlers ----

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// getStats returns cluster-wide lifetime counters, summed across every agent from
// the materialized rollups. The control plane doesn't resolve, so these come from
// the ingested query log rather than a local resolver (which would read zero).
func (s *Server) getStats(w http.ResponseWriter, _ *http.Request) {
	summary, err := s.store.RollupSummary(0, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	logged, _ := s.store.CountQueryLog()
	t := summary.Totals
	writeJSON(w, http.StatusOK, map[string]any{
		"total":     t.Total,
		"blocked":   t.Blocked,
		"cached":    t.Cached,
		"forwarded": t.Forwarded,
		"rewritten": t.Rewritten,
		"errors":    t.Errors,
		"log_count": logged,
	})
}

func (s *Server) getTimeSeries(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	step := stepFor(hours)
	if step < 60 {
		step = 60
	}
	since := time.Now().Add(-windowDur(hours)).UnixMilli()
	points, err := s.store.RollupTimeSeries(since, step, parseNodes(r))
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
	step := stepFor(hours)
	if step < 60 {
		step = 60
	}
	since := time.Now().Add(-windowDur(hours)).UnixMilli()
	points, names, err := s.store.RollupLatency(since, step, parseNodes(r))
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
	since := time.Now().Add(-windowDur(hours)).UnixMilli()
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
	since := time.Now().Add(-windowDur(hours)).UnixMilli()
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
	since := time.Now().Add(-windowDur(hours)).UnixMilli()
	nodes := parseNodes(r)

	// Served from the materialized rollups so any window reads small pre-aggregated
	// tables instead of scanning the raw query_log. Top domains are loaded lazily
	// (see getTopDomains) since they need the raw log.
	summary, err := s.store.RollupSummary(since, nodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	byNode, err := s.store.RollupByNode(since, nodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if byNode == nil {
		byNode = []store.NodeQueryCount{}
	}
	clients, err := s.store.RollupTopClients(since, 12, nodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if clients == nil {
		clients = []store.ClientStat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"unique_clients": summary.UniqueClients,
		"avg_latency_ms": summary.AvgLatencyMS,
		"clients":        clients,
		"top_queried":    []store.DomainStat{},
		"top_blocked":    []store.DomainStat{},
		"qtypes":         []store.TypeStat{},
		"by_node":        byNode,
		"totals":         summary.Totals,
	})
}

// getTopDomains returns the top queried + top blocked domains for the window.
// Loaded lazily (the dashboard's Top-domains section is collapsed by default) and
// read from the raw query_log, since domains are too high-cardinality to roll up.
func (s *Server) getTopDomains(w http.ResponseWriter, r *http.Request) {
	hours := clampHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-windowDur(hours)).UnixMilli()
	nodes := parseNodes(r)
	queried, err := s.store.TopDomains(since, 12, false, nodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	blocked, err := s.store.TopDomains(since, 12, true, nodes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if queried == nil {
		queried = []store.DomainStat{}
	}
	if blocked == nil {
		blocked = []store.DomainStat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"top_queried": queried, "top_blocked": blocked})
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

// clampHours parses the dashboard window in hours. Fractional values are allowed
// (e.g. 0.5 = 30 minutes) and the window is capped at 15 days (the longest range
// the UI offers; older data lives in VictoriaLogs).
func clampHours(s string) float64 {
	h, _ := strconv.ParseFloat(s, 64)
	if h <= 0 {
		h = 24
	}
	if h > 24*15 {
		h = 24 * 15
	}
	return h
}

// windowDur converts clamped hours to a Duration.
func windowDur(hours float64) time.Duration { return time.Duration(hours * float64(time.Hour)) }

// stepFor picks a time-series bucket size (seconds) so a window has ~48 buckets,
// never below 1s (matters for the 30-minute window).
func stepFor(hours float64) int {
	s := int(hours * 3600 / 48)
	if s < 1 {
		s = 1
	}
	return s
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
	if h, _ := strconv.ParseFloat(q.Get("hours"), 64); h > 0 {
		sinceMs = time.Now().Add(-windowDur(h)).UnixMilli()
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
		Domain      string   `json:"domain"`
		RRType      string   `json:"rrtype"`
		Value       string   `json:"value"`
		ScopeType   string   `json:"scope_type"`
		ScopeValues []string `json:"scope_values"`
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
	scopeType, valsJSON, err := store.CanonicalScope(in.ScopeType, in.ScopeValues)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if conflict, err := s.store.RewriteScopeConflict(domain, in.RRType, scopeType, valsJSON, 0); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if conflict {
		writeError(w, http.StatusConflict, "another rewrite for this domain already targets overlapping "+scopeType)
		return
	}
	id, err := s.store.AddRewriteScoped(domain, in.RRType, in.Value, scopeType, in.ScopeValues)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "domain": domain, "rrtype": in.RRType, "value": in.Value, "scope_type": scopeType, "scope_values": in.ScopeValues})
}

// updateRewrite edits a rewrite's value, enabled flag, and scope in place, so
// re-scoping doesn't require delete-and-recreate.
func (s *Server) updateRewrite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Value       string   `json:"value"`
		Enabled     bool     `json:"enabled"`
		ScopeType   string   `json:"scope_type"`
		ScopeValues []string `json:"scope_values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.Value == "" {
		writeError(w, http.StatusBadRequest, "value required")
		return
	}
	scopeType, valsJSON, err := store.CanonicalScope(in.ScopeType, in.ScopeValues)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The domain+rrtype being edited are needed for the overlap check.
	rws, err := s.store.ListRewrites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var cur *store.Rewrite
	for i := range rws {
		if rws[i].ID == id {
			cur = &rws[i]
			break
		}
	}
	if cur == nil {
		writeError(w, http.StatusNotFound, "rewrite not found")
		return
	}
	// RewriteScopeConflict deliberately skips rows whose scope is IDENTICAL to
	// the new one (that's the correct upsert behavior for POST), so re-scoping
	// this row onto another row's exact (domain+rrtype+scope) would sail past it
	// and hit the UNIQUE constraint as a raw 500. Catch that case here.
	for i := range rws {
		if rws[i].ID == id || rws[i].Domain != cur.Domain || rws[i].RRType != cur.RRType {
			continue
		}
		if rws[i].ScopeType == scopeType && scopeValuesJSON(rws[i].ScopeValues) == valsJSON {
			writeError(w, http.StatusConflict, "another rewrite for this domain already has this exact scope")
			return
		}
	}
	if conflict, err := s.store.RewriteScopeConflict(cur.Domain, cur.RRType, scopeType, valsJSON, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if conflict {
		writeError(w, http.StatusConflict, "another rewrite for this domain already targets overlapping "+scopeType)
		return
	}
	if err := s.store.UpdateRewrite(id, in.Value, in.Enabled, scopeType, in.ScopeValues); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "value": in.Value, "enabled": in.Enabled, "scope_type": scopeType, "scope_values": in.ScopeValues})
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

// scopeValuesJSON reproduces the canonical JSON encoding of an already-stored
// (and thus already-canonical) scope values slice, so it can be compared
// byte-for-byte against a freshly canonicalized scope's JSON encoding.
func scopeValuesJSON(vals []string) string {
	if len(vals) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(vals)
	return string(b)
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
