package api

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/boot"
	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// SetCategoryDB attaches the category database the "Test a query" tool checks
// network-wide category blocks against (nil = category blocks only from the
// per-domain corrections in the settings).
func (s *Server) SetCategoryDB(h *categories.Holder) { s.catDB = h }

// Test-query rate limit, per signed-in user (or API token): the tool forwards
// from the control plane, so it must not become an open lookup service.
const (
	testQueryLimit  = 30
	testQueryWindow = time.Minute
)

// userLimiter is a fixed-window counter per key.
type userLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	start   time.Time
	counted map[string]int
}

func (l *userLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counted == nil || now.Sub(l.start) >= l.window {
		l.start, l.counted = now, map[string]int{}
	}
	if l.counted[key] >= l.limit {
		return false
	}
	l.counted[key]++
	return true
}

type testQueryRequest struct {
	Name string `json:"name"`
	Type string `json:"type"` // A, AAAA, … (default A)
	// Node or Site evaluate the query as that resolver (or a resolver at that
	// site) sees it: its scoped local records and conditional forwarders.
	// Neither = the records and forwarders that apply everywhere.
	Node           string `json:"node,omitempty"`
	Site           string `json:"site,omitempty"`
	DNSSEC         bool   `json:"dnssec,omitempty"`
	ForwardBlocked bool   `json:"forward_blocked,omitempty"`
}

type testQueryRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

type testQueryAnswer struct {
	Rcode     string            `json:"rcode"`
	Answer    []testQueryRecord `json:"answer"`
	Authority []testQueryRecord `json:"authority,omitempty"`
	AD        bool              `json:"ad,omitempty"` // DNSSEC-validated by the upstream
}

type testQueryResponse struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Node     string `json:"node,omitempty"`
	Site     string `json:"site,omitempty"`
	RanOn    string `json:"ran_on"` // "control-plane"
	Decision string `json:"decision"`
	// Why: the record, zone, category, forwarder and upstream involved.
	Zone           string   `json:"zone,omitempty"`
	Rewrite        string   `json:"rewrite,omitempty"`
	RewriteScope   string   `json:"rewrite_scope,omitempty"` // all | nodes | sites
	RewriteScopeOn []string `json:"rewrite_scope_values,omitempty"`
	RewriteYielded string   `json:"rewrite_yielded,omitempty"`
	Category       string   `json:"category,omitempty"`
	CategoryBlock  bool     `json:"category_block,omitempty"`
	Allowed        bool     `json:"allowed,omitempty"`
	BlockPaused    bool     `json:"block_paused,omitempty"`
	Forwarder      string   `json:"forwarder,omitempty"`
	Upstream       string   `json:"upstream,omitempty"`
	RTTMs          float64  `json:"rtt_ms,omitempty"`
	Error          string   `json:"error,omitempty"`
	// Answer is what a client would get; Upstream is what the upstream says
	// for a blocked name (forward_blocked).
	Answer         testQueryAnswer  `json:"answer"`
	UpstreamAnswer *testQueryAnswer `json:"upstream_answer,omitempty"`
}

// testQuery answers "what does this name resolve to, and why": it runs the
// resolution pipeline on the control plane, bypassing the cache, as the chosen
// resolver or site would see it (POST /api/tools/resolve).
func (s *Server) testQuery(w http.ResponseWriter, r *http.Request) {
	var in testQueryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSuffix(strings.TrimSpace(in.Name), ".")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if _, ok := dns.IsDomainName(name); !ok || len(name) > 253 {
		writeError(w, http.StatusBadRequest, "not a valid DNS name")
		return
	}
	qtype := dns.TypeA
	if t := strings.ToUpper(strings.TrimSpace(in.Type)); t != "" {
		v, ok := dns.StringToType[t]
		if !ok || v == dns.TypeANY || v == dns.TypeAXFR || v == dns.TypeIXFR {
			writeError(w, http.StatusBadRequest, "unsupported record type")
			return
		}
		qtype = v
	}
	// For PTR, accept an address and look up its reverse name.
	if qtype == dns.TypePTR {
		if ip := net.ParseIP(name); ip != nil {
			if rev, err := dns.ReverseAddr(ip.String()); err == nil {
				name = strings.TrimSuffix(rev, ".")
			}
		}
	}
	if s.res == nil {
		writeError(w, http.StatusServiceUnavailable, "no resolver on this control plane")
		return
	}

	who, _ := s.currentUser(r)
	if !s.testQueryLimit.allow(who, time.Now()) {
		writeError(w, http.StatusTooManyRequests, "too many test queries: try again in a minute")
		return
	}

	nodeName, site := strings.TrimSpace(in.Node), strings.TrimSpace(in.Site)
	if nodeName != "" {
		n, ok, err := s.findNodeByName(nodeName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "no resolver named "+nodeName)
			return
		}
		site = n.Site
	}
	rws, err := s.store.ListRewritesForNode(nodeName, site)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	fws, err := s.store.ListForwardersForNode(nodeName, site)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rewrites, wildcards := boot.RewriteMaps(rws)
	view := &resolver.TraceView{Scoped: true, Rewrites: rewrites, Wildcards: wildcards, ForwardersSet: true,
		CategoryDomains: s.traceCategoryDomains()}
	for _, f := range fws {
		view.Forwarders = append(view.Forwarders, resolver.ForwardGroup{Suffix: f.Suffix, Upstreams: f.Upstreams})
	}

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	req.RecursionDesired = true
	tr := s.res.Trace(req, view, resolver.TraceOptions{
		CategoryDB: s.catDB, ForwardBlocked: in.ForwardBlocked, DNSSEC: in.DNSSEC,
	})
	slog.Info("test query", "user", who, "name", name, "type", dns.TypeToString[qtype],
		"node", nodeName, "site", site, "decision", tr.Decision)

	out := testQueryResponse{
		Name: name, Type: dns.TypeToString[qtype], Node: nodeName, Site: site, RanOn: "control-plane",
		Decision: tr.Decision, Zone: tr.Zone, Rewrite: tr.Rewrite, RewriteYielded: tr.RewriteYielded,
		Category: tr.Category, CategoryBlock: tr.CategoryBlock, Allowed: tr.Allowed, BlockPaused: tr.BlockPaused,
		Forwarder: tr.Forwarder, Upstream: tr.Upstream, Error: tr.Error,
		Answer: answerOf(tr.Response),
	}
	if tr.RTT > 0 {
		out.RTTMs = float64(tr.RTT.Microseconds()) / 1000
	}
	if tr.UpstreamResponse != nil {
		a := answerOf(tr.UpstreamResponse)
		out.UpstreamAnswer = &a
	}
	if tr.Rewrite != "" {
		// The per-node list is scope-free (as agents get it): look the scope up
		// among all records, matching one that applies here.
		if all, err := s.store.ListRewrites(); err == nil {
			out.RewriteScope, out.RewriteScopeOn = rewriteScope(store.FilterRewritesForNode(all, nodeName, site), all, tr.Rewrite)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// traceCategoryDomains are the per-domain category corrections resolvers get
// with their settings (see replicatedSettings), so category blocks in a test
// match theirs. Empty (not nil) when there are none.
func (s *Server) traceCategoryDomains() map[string]string {
	out := map[string]string{}
	if s.categorizer == nil {
		return out
	}
	set, err := s.loadSettings()
	if err != nil {
		return out
	}
	for d, c := range s.categorizer.DomainsFor(set.BlockedCategories) {
		out[d] = c
	}
	return out
}

// findNodeByName returns the enrolled resolver with that name.
func (s *Server) findNodeByName(name string) (store.Node, bool, error) {
	nodes, err := s.store.ListNodes()
	if err != nil {
		return store.Node{}, false, err
	}
	for _, n := range nodes {
		if n.Name == name {
			return n, true, nil
		}
	}
	return store.Node{}, false, nil
}

// rewriteScope is the scope of the enabled local record for key ("name" or
// "*.suffix") among those that apply here (applying, scope-free) — looked up in
// all (which carries the scope fields). A reverse (PTR) answer has none.
func rewriteScope(applying, all []store.Rewrite, key string) (string, []string) {
	ids := map[int64]bool{}
	for _, rw := range applying {
		ids[rw.ID] = true
	}
	for _, rw := range all {
		if ids[rw.ID] && rw.Enabled && filter.Normalize(rw.Domain) == key {
			t := rw.ScopeType
			if t == "" {
				t = "all"
			}
			return t, rw.ScopeValues
		}
	}
	return "", nil
}

func answerOf(m *dns.Msg) testQueryAnswer {
	a := testQueryAnswer{Answer: []testQueryRecord{}}
	if m == nil {
		return a
	}
	a.Rcode = dns.RcodeToString[m.Rcode]
	a.AD = m.AuthenticatedData
	a.Answer = recordsOf(m.Answer)
	a.Authority = recordsOf(m.Ns)
	return a
}

func recordsOf(rrs []dns.RR) []testQueryRecord {
	out := make([]testQueryRecord, 0, len(rrs))
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, testQueryRecord{
			Name: strings.TrimSuffix(h.Name, "."),
			Type: dns.TypeToString[h.Rrtype],
			TTL:  h.Ttl,
			Data: strings.TrimPrefix(rr.String(), h.String()),
		})
	}
	return out
}
