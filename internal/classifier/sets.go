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
}

func newSetHolder(name string) *setHolder { return &setHolder{name: name} }

func (h *setHolder) has(domain string) bool          { return h.set.Load().Has(domain) }
func (h *setHolder) count() int                      { return h.set.Load().Count() }
func (h *setHolder) search(q string, n int) []string { return h.set.Load().Search(q, n) }

// ensure reloads the set in the background if the sources changed since last load.
func (h *setHolder) ensure(sources []domainSource) {
	key := sourcesKey(sources)
	if len(sources) == 0 {
		if cur, _ := h.src.Load().(string); cur != key {
			h.set.Store(nil)
			h.src.Store(key)
		}
		return
	}
	if cur, _ := h.src.Load().(string); cur == key {
		return
	}
	if !h.busy.CompareAndSwap(false, true) {
		return // a load is already in flight
	}
	go func() {
		defer h.busy.Store(false)
		set, err := loadSources(sources)
		if err != nil {
			slog.Warn(h.name+" list load failed", "err", err)
			return
		}
		h.set.Store(set)
		h.src.Store(key)
		slog.Info(h.name+" list loaded", "domains", set.Count())
	}()
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

// threatSources builds the threat-list sources: the built-in public default
// (unless disabled) plus an optional custom source.
func threatSources(s Settings) []domainSource {
	var out []domainSource
	if !s.ThreatDisableDefault {
		out = append(out, domainSource{DefaultThreatURL, 0})
	}
	if c := customSource(s.ThreatListURL); c != "" {
		out = append(out, domainSource{c, 0})
	}
	return out
}
