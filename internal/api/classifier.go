package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/IPMaze/MazeDNS/internal/classifier"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// getClassifier returns the live classifier settings and per-status verdict counts.
func (s *Server) getClassifier(w http.ResponseWriter, _ *http.Request) {
	cfg := classifier.LoadSettings(s.store, classifier.Settings{Mode: string(classifier.ModeOff)})
	counts, err := s.store.ClassificationCounts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	categoryCounts, err := s.store.ClassificationCategoryCounts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Never leak the API key to the UI.
	cfg.APIKey = ""
	trustedCount, threatCount := 0, 0
	if s.clsTrusted != nil {
		trustedCount = s.clsTrusted()
	}
	if s.clsThreat != nil {
		threatCount = s.clsThreat()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":        cfg,
		"counts":          counts,
		"category_counts": categoryCounts,
		"trusted_count":   trustedCount,
		"threat_count":    threatCount,
	})
}

// getTrustedList returns a (searchable) preview of the loaded trusted domains.
func (s *Server) getTrustedList(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	count, domains := 0, []string{}
	if s.clsTrusted != nil {
		count = s.clsTrusted()
	}
	if s.clsTrustedSearch != nil {
		if d := s.clsTrustedSearch(search, limit); d != nil {
			domains = d
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": count, "domains": domains})
}

// putClassifierSettings replaces the classifier settings (from the Settings UI).
// An empty api_key is treated as "leave unchanged" so the masked field round-trips.
func (s *Server) putClassifierSettings(w http.ResponseWriter, r *http.Request) {
	var in classifier.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Mode = string(classifier.ParseMode(in.Mode))
	in.Endpoint = strings.TrimSpace(in.Endpoint)
	in.Model = strings.TrimSpace(in.Model)
	if in.APIKey == "" {
		prev := classifier.LoadSettings(s.store, classifier.Settings{})
		in.APIKey = prev.APIKey
	}
	if err := classifier.SaveSettings(s.store, in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	in.APIKey = ""
	writeJSON(w, http.StatusOK, in)
}

// testClassifier classifies a sample domain against the supplied settings (an
// empty api_key falls back to the stored one), so the user can verify the model
// endpoint works before saving. Always returns 200 with an {ok, ...} body.
func (s *Server) testClassifier(w http.ResponseWriter, r *http.Request) {
	var in classifier.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.APIKey == "" {
		in.APIKey = classifier.LoadSettings(s.store, classifier.Settings{}).APIKey
	}
	if strings.TrimSpace(in.Endpoint) == "" || strings.TrimSpace(in.Model) == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "endpoint and model are required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), in.Timeout())
	defer cancel()
	const sample = "doubleclick.net"
	v, err := classifier.NewClient(in.Endpoint, in.Model, in.APIKey, in.Timeout()).Classify(ctx, sample, classifier.Hints{})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "domain": sample, "category": v.Category, "confidence": v.Confidence, "reason": v.Reason,
	})
}

// setClassifierMode is a quick toggle of just the enforcement mode (used by the
// AI console). off|suggest|auto.
func (s *Server) setClassifierMode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cfg := classifier.LoadSettings(s.store, classifier.Settings{})
	cfg.Mode = string(classifier.ParseMode(in.Mode))
	if err := classifier.SaveSettings(s.store, cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": cfg.Mode})
}

// listClassifications returns verdicts, optionally filtered by ?status= and
// limited by ?limit=.
func (s *Server) listClassifications(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, err := s.store.ListClassifications(status, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []store.Classification{}
	}
	writeJSON(w, http.StatusOK, items)
}

// decideClassification approves or rejects a verdict. Approving makes it block;
// rejecting means it never blocks. Either way the policy is rebuilt (and the
// config hash changes, so workers re-sync).
func (s *Server) decideClassification(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain   string `json:"domain"`
		Decision string `json:"decision"` // "approve" | "reject" | "dismiss"
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if in.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	// "dismiss" hides the suggestion once: drop the verdict so the domain can be
	// re-evaluated (and possibly re-suggested) the next time it's queried.
	if in.Decision == "dismiss" {
		if err := s.store.DeleteClassification(in.Domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"domain": in.Domain, "status": "dismissed"})
		return
	}
	var status string
	switch in.Decision {
	case "approve":
		status = store.ClassApproved
	case "reject":
		status = store.ClassRejected
	default:
		writeError(w, http.StatusBadRequest, "decision must be approve, reject, or dismiss")
		return
	}
	if err := s.store.SetClassificationStatus(in.Domain, status); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.reload != nil {
		_ = s.reload() // approved -> now blocks; rejected -> stops blocking
	}
	writeJSON(w, http.StatusOK, map[string]string{"domain": in.Domain, "status": status})
}
