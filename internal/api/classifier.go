package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	// Never leak API keys to the UI — but tell it which ones are set so it can show
	// a "key present" indicator.
	hasAPIKey, hasVTKey, hasAbuseKey, hasOpenTIPKey := cfg.APIKey != "", cfg.VTAPIKey != "", cfg.AbuseIPDBAPIKey != "", cfg.OpenTIPAPIKey != ""
	cfg.APIKey, cfg.VTAPIKey, cfg.AbuseIPDBAPIKey, cfg.OpenTIPAPIKey = "", "", "", ""
	trustedCount, threatCount := 0, 0
	if s.cls != nil {
		trustedCount = s.cls.TrustedCount()
		threatCount = s.cls.ThreatCount()
	}
	usage, _ := s.store.LLMUsage(14)
	if usage == nil {
		usage = []store.LLMUsageDay{}
	}
	usageTotals, _ := s.store.LLMUsageTotals()
	repUsage, _ := s.store.ReputationUsage(14)
	if repUsage == nil {
		repUsage = []store.ReputationUsageDay{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":            cfg,
		"counts":              counts,
		"category_counts":     categoryCounts,
		"trusted_count":       trustedCount,
		"threat_count":        threatCount,
		"threat_feed_catalog": classifier.ThreatFeedCatalog(),
		"llm_usage":           usage,
		"llm_usage_totals":    usageTotals,
		"reputation_usage":    repUsage,
		"has_api_key":         hasAPIKey,
		"has_vt_key":          hasVTKey,
		"has_abuseipdb_key":   hasAbuseKey,
		"has_opentip_key":     hasOpenTIPKey,
	})
}

// getList returns a searchable preview of a loaded list (?list=trusted|threat).
func (s *Server) getList(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	count, domains := 0, []string{}
	if s.cls != nil {
		var d []string
		if r.URL.Query().Get("list") == "threat" {
			count, d = s.cls.ThreatCount(), s.cls.ThreatSearch(search, limit)
		} else {
			count, d = s.cls.TrustedCount(), s.cls.TrustedSearch(search, limit)
		}
		if d != nil {
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
	// An empty key field means "leave unchanged" so masked fields round-trip.
	prev := classifier.LoadSettings(s.store, classifier.Settings{})
	if in.APIKey == "" {
		in.APIKey = prev.APIKey
	}
	if in.VTAPIKey == "" {
		in.VTAPIKey = prev.VTAPIKey
	}
	if in.AbuseIPDBAPIKey == "" {
		in.AbuseIPDBAPIKey = prev.AbuseIPDBAPIKey
	}
	if in.OpenTIPAPIKey == "" {
		in.OpenTIPAPIKey = prev.OpenTIPAPIKey
	}
	if err := classifier.SaveSettings(s.store, in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	in.APIKey, in.VTAPIKey, in.AbuseIPDBAPIKey, in.OpenTIPAPIKey = "", "", "", ""
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
	// Anthropic uses a default base URL, so only a model is required there; the
	// OpenAI-compatible provider needs an explicit endpoint.
	if strings.TrimSpace(in.Model) == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "model is required"})
		return
	}
	if in.Provider != classifier.ProviderAnthropic && strings.TrimSpace(in.Endpoint) == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "endpoint is required for OpenAI-compatible providers"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), in.Timeout())
	defer cancel()
	const sample = "doubleclick.net"
	v, _, err := classifier.NewClient(in.Provider, in.Endpoint, in.Model, in.APIKey, in.Timeout()).Classify(ctx, sample, classifier.Hints{})
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

// listClassifications returns verdicts, optionally filtered by ?status=, a
// ?search= domain substring, and limited by ?limit=.
func (s *Server) listClassifications(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, err := s.store.ListClassifications(status, search, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []store.Classification{}
	}
	writeJSON(w, http.StatusOK, items)
}

// clearClassifications wipes all AI verdicts (a clean-slate reset) and rebuilds
// the policy (so any AI-enforced blocks are dropped until re-classified).
func (s *Server) clearClassifications(w http.ResponseWriter, _ *http.Request) {
	n, err := s.store.DeleteAllClassifications()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.reload != nil {
		_ = s.reload()
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

// getWhois returns RDAP/WHOIS registration data for a domain (for the detail view).
func (s *Server) getWhois(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if s.cls == nil {
		writeError(w, http.StatusServiceUnavailable, "classifier not available")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	info, err := s.cls.Whois(ctx, domain)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "domain": domain})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "whois": info})
}

// getDomainClients lists the clients that queried a domain (and its subdomains),
// enriched with a NetBird peer name / reverse-DNS hostname when available — so an
// operator can see who is reaching a flagged domain.
func (s *Server) getDomainClients(w http.ResponseWriter, r *http.Request) {
	domain := classifier.RegisteredDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "valid domain is required")
		return
	}
	clients, err := s.store.ClientsForDomain(domain, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.enricher != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		for i := range clients {
			id := s.enricher.Lookup(ctx, clients[i].Client)
			clients[i].Name, clients[i].Source = id.Name, id.Source
		}
	}
	if clients == nil {
		clients = []store.DomainClient{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "clients": clients})
}

// validDecisionCategory checks the corrected category matches the decision:
// blocking ("approve") wants a security category; allowing ("reject") wants a
// non-blocking content/other category.
func validDecisionCategory(decision, category string) bool {
	switch decision {
	case "approve":
		return classifier.IsBlockCategory(category)
	case "reject":
		return classifier.IsContentCategory(category)
	}
	return false
}

// decideClassification approves or rejects a verdict. Approving makes it block;
// rejecting means it never blocks. Either way the policy is rebuilt (and the
// config hash changes, so workers re-sync).
func (s *Server) decideClassification(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain   string `json:"domain"`
		Decision string `json:"decision"` // "approve" | "reject" | "dismiss"
		Category string `json:"category"` // corrected category (optional)
		Note     string `json:"note"`     // operator review note (optional)
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	in.Category = strings.ToLower(strings.TrimSpace(in.Category))
	in.Note = strings.TrimSpace(in.Note)
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
	// Guard the corrected category against the decision: blocking takes a security
	// category, allowing takes a non-blocking (content/other) category.
	if in.Category != "" && !validDecisionCategory(in.Decision, in.Category) {
		writeError(w, http.StatusBadRequest, "category is not valid for this decision")
		return
	}
	if err := s.store.SetClassificationDecision(in.Domain, status, in.Category, in.Note); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.reload != nil {
		_ = s.reload() // approved -> now blocks; rejected -> stops blocking
	}
	writeJSON(w, http.StatusOK, map[string]string{"domain": in.Domain, "status": status})
}
