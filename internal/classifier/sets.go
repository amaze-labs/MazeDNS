package classifier

import (
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
)

// domainSource is one list to load (a URL or file path), optionally capped.
type domainSource struct {
	url  string
	topN int
}

// setHolder owns a domain set that is (re)loaded in the background when its
// configured sources change. All access is lock-free via the atomic pointer.
type setHolder struct {
	name string
	set  atomic.Pointer[TrustedSet]
	src  atomic.Value // string key of the sources the current set was built from
	busy atomic.Bool
	// onChange, if set, fires after the set is successfully (re)loaded — used to
	// re-check existing verdicts against a refreshed threat feed.
	onChange func()
}

func newSetHolder(name string) *setHolder { return &setHolder{name: name} }

func (h *setHolder) has(domain string) bool          { return h.set.Load().Has(domain) }
func (h *setHolder) count() int                      { return h.set.Load().Count() }
func (h *setHolder) search(q string, n int) []string { return h.set.Load().Search(q, n) }

// ensureSync (re)loads the set synchronously if the sources changed. The worker
// uses this on its own goroutine so a domain is never classified against a stale
// or not-yet-loaded list — which, with classify-once, would bake in a false
// positive (e.g. a domain seen before its trusted list finished loading).
func (h *setHolder) ensureSync(sources []domainSource) {
	key := sourcesKey(sources)
	if cur, _ := h.src.Load().(string); cur == key {
		return
	}
	if len(sources) == 0 {
		h.set.Store(nil)
		h.src.Store(key)
		return
	}
	if !h.busy.CompareAndSwap(false, true) {
		return // a background load is already in flight
	}
	defer h.busy.Store(false)
	set, err := loadSources(sources)
	if err != nil {
		slog.Warn(h.name+" list load failed", "err", err)
		return
	}
	h.set.Store(set)
	h.src.Store(key)
	slog.Info(h.name+" list loaded", "domains", set.Count())
	if h.onChange != nil {
		h.onChange()
	}
}

// refresh re-fetches the set from its current sources even when the source key is
// unchanged — threat feeds (URLhaus, etc.) update continuously, so a long-running
// node must periodically re-pull them rather than trusting the startup snapshot.
func (h *setHolder) refresh(sources []domainSource) {
	if len(sources) == 0 {
		return
	}
	if !h.busy.CompareAndSwap(false, true) {
		return // a load is already in flight
	}
	defer h.busy.Store(false)
	set, err := loadSources(sources)
	if err != nil {
		slog.Warn(h.name+" list refresh failed", "err", err)
		return
	}
	h.set.Store(set)
	h.src.Store(sourcesKey(sources))
	slog.Info(h.name+" list refreshed", "domains", set.Count())
	if h.onChange != nil {
		h.onChange()
	}
}

func sourcesKey(sources []domainSource) string {
	parts := make([]string, len(sources))
	for i, s := range sources {
		parts[i] = s.url + "#" + strconv.Itoa(s.topN)
	}
	return strings.Join(parts, "|")
}

// loadSources loads and unions every source. A failed source is logged and
// skipped; only an all-empty result with an error is treated as a failure.
func loadSources(sources []domainSource) (*TrustedSet, error) {
	set := &TrustedSet{domains: make(map[string]struct{})}
	var firstErr error
	for _, s := range sources {
		one, err := LoadTrusted(s.url, s.topN)
		if err != nil {
			slog.Warn("domain list source failed", "source", s.url, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for d := range one.domains {
			set.domains[d] = struct{}{}
		}
	}
	if len(set.domains) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return set, nil
}

// customSource normalizes a user-supplied list value: blank and "off" mean none.
func customSource(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "off") {
		return ""
	}
	return v
}

// trustedSources builds the trusted-list sources: the built-in public default
// (unless disabled) plus an optional custom source.
func trustedSources(s Settings) []domainSource {
	var out []domainSource
	if !s.TrustedDisableDefault {
		topN := s.TrustedTopN
		if topN <= 0 {
			topN = DefaultTrustedTopN
		}
		out = append(out, domainSource{DefaultTrustedURL, topN})
	}
	if c := customSource(s.TrustedListURL); c != "" {
		out = append(out, domainSource{c, s.TrustedTopN})
	}
	return out
}

// threatSources builds the threat-list sources: every enabled built-in feed plus
// any custom sources, de-duplicated.
func threatSources(s Settings) []domainSource {
	feeds := s.ThreatFeeds
	if feeds == nil {
		// Pre-ThreatFeeds settings: derive from the old single-default toggle.
		if !s.ThreatDisableDefault {
			feeds = []string{"urlhaus"}
		}
	}
	seen := map[string]bool{}
	var out []domainSource
	add := func(url string) {
		if url != "" && !seen[url] {
			seen[url] = true
			out = append(out, domainSource{url, 0})
		}
	}
	for _, key := range feeds {
		if url, ok := threatFeedURL(key); ok {
			add(url)
		}
	}
	for _, c := range splitSources(s.ThreatListURL) {
		add(customSource(c))
	}
	return out
}

// splitSources splits a multi-source field on newlines, commas, and spaces.
func splitSources(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == '\t' })
}
