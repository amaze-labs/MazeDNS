package api

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/metrics"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// metricsAuth wraps the /metrics handler. When a scrape token is configured
// (Settings → metrics), it requires "Authorization: Bearer <token>" and compares
// the token's hash in constant time; when unset, /metrics stays open (its current
// behavior). The scrape token is a control-plane setting, so on a worker (which has
// no such setting) this is always open.
func (s *Server) metricsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := s.store.LoadCPSettings(cpSettingsDefaults())
		if c.MetricsScrapeTokenHash != "" {
			const p = "Bearer "
			h := r.Header.Get("Authorization")
			presented := ""
			if strings.HasPrefix(h, p) {
				presented = hashKey(strings.TrimPrefix(h, p))
			}
			if subtle.ConstantTimeCompare([]byte(presented), []byte(c.MetricsScrapeTokenHash)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				writeError(w, http.StatusUnauthorized, "metrics scrape token required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// generateMetricsToken mints a new /metrics scrape token, stores its hash + display
// prefix, and returns the raw token ONCE (admin only). Any previous token is
// replaced. The raw value is never retrievable afterwards.
func (s *Server) generateMetricsToken(w http.ResponseWriter, r *http.Request) {
	tok, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	cur := s.store.LoadCPSettings(cpSettingsDefaults())
	cur.MetricsScrapeTokenHash = hashKey(tok)
	cur.MetricsScrapeTokenPrefix = tok[:8]
	if err := s.store.SaveCPSettings(cur); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(store.AuditEntry{User: auditUser(s, r), Action: "settings.cp", Detail: "metrics_scrape_token generated (prefix " + tok[:8] + ")"})
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "prefix": tok[:8]})
}

// clearMetricsToken removes the /metrics scrape token, reopening /metrics (admin only).
func (s *Server) clearMetricsToken(w http.ResponseWriter, r *http.Request) {
	cur := s.store.LoadCPSettings(cpSettingsDefaults())
	if cur.MetricsScrapeTokenHash == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	cur.MetricsScrapeTokenHash = ""
	cur.MetricsScrapeTokenPrefix = ""
	if err := s.store.SaveCPSettings(cur); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(store.AuditEntry{User: auditUser(s, r), Action: "settings.cp", Detail: "metrics_scrape_token cleared"})
	w.WriteHeader(http.StatusNoContent)
}

// getMetricsExport returns the VictoriaMetrics export settings (password masked).
func (s *Server) getMetricsExport(w http.ResponseWriter, _ *http.Request) {
	v := s.store.LoadVMExport(store.VMExport{})
	hasPassword := v.Password != ""
	v.Password = "" // never leak the password to the UI
	writeJSON(w, http.StatusOK, map[string]any{"settings": v, "has_password": hasPassword})
}

// putMetricsExport saves the VictoriaMetrics export settings. An empty password
// means "leave unchanged" so the masked field round-trips. The running pusher
// picks the new settings up on its next cycle.
func (s *Server) putMetricsExport(w http.ResponseWriter, r *http.Request) {
	var in store.VMExport
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.URL = strings.TrimSpace(in.URL)
	in.Job = strings.TrimSpace(in.Job)
	in.Instance = strings.TrimSpace(in.Instance)
	if in.IntervalSec <= 0 {
		in.IntervalSec = 15
	}
	if in.Password == "" {
		in.Password = s.store.LoadVMExport(store.VMExport{}).Password
	}
	if err := s.store.SaveVMExport(in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	in.Password = ""
	writeJSON(w, http.StatusOK, in)
}

// getLogsExport returns the VictoriaLogs export settings (password masked).
func (s *Server) getLogsExport(w http.ResponseWriter, _ *http.Request) {
	v := s.store.LoadVLExport(store.VLExport{})
	hasPassword := v.Password != ""
	v.Password = ""
	writeJSON(w, http.StatusOK, map[string]any{"settings": v, "has_password": hasPassword})
}

// putLogsExport saves the VictoriaLogs export settings (empty password = unchanged).
func (s *Server) putLogsExport(w http.ResponseWriter, r *http.Request) {
	var in store.VLExport
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.URL = strings.TrimSpace(in.URL)
	if in.IntervalSec <= 0 {
		in.IntervalSec = 15
	}
	if in.Password == "" {
		in.Password = s.store.LoadVLExport(store.VLExport{}).Password
	}
	if err := s.store.SaveVLExport(in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	in.Password = ""
	writeJSON(w, http.StatusOK, in)
}

// vmRelayClient forwards agents' relayed metrics to VictoriaMetrics.
var vmRelayClient = &http.Client{Timeout: 10 * time.Second}

// maxRelayedMetrics bounds one relayed push (an agent's whole registry is tens of KB).
const maxRelayedMetrics = 8 << 20

// clusterMetrics forwards an agent's Prometheus metrics to VictoriaMetrics with
// the control plane's export settings, labelled instance=<the node's name>.
// The name comes from the authenticated node key, so an agent can't push
// under another's name; and the VictoriaMetrics URL and credentials never
// leave the control plane.
func (s *Server) clusterMetrics(w http.ResponseWriter, r *http.Request) {
	node := s.nodeFromKey(r)
	if node == nil {
		writeError(w, http.StatusUnauthorized, "invalid node key")
		return
	}
	if !node.Approved {
		writeError(w, http.StatusForbidden, "node pending approval")
		return
	}
	vm := s.store.LoadVMExport(store.VMExport{})
	if !vm.Enabled || strings.TrimSpace(vm.URL) == "" {
		writeError(w, http.StatusConflict, "metrics export is off")
		return
	}
	// Read it whole (bounded) so it is forwarded with a length, not chunked.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRelayedMetrics))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "metrics too large")
		return
	}
	cfg := metrics.VMConfig{URL: vm.URL, Job: vm.Job, Username: vm.Username, Password: vm.Password}
	if err := metrics.Import(r.Context(), vmRelayClient, cfg, node.Name, bytes.NewReader(body)); err != nil {
		writeError(w, http.StatusBadGateway, "victoriametrics: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
