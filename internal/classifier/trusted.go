package classifier

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// DefaultTrustedURL is the public top-domains list used out of the box (no manual
// configuration) to reduce false positives. Majestic Million is a free, no-auth,
// plain-CSV list of the most-referenced domains, updated daily.
const DefaultTrustedURL = "https://downloads.majestic.com/majestic_million.csv"

// DefaultTrustedTopN caps how many of the default list's (ranked, most-popular-
// first) entries are loaded, so we don't pull the full ~1M list.
const DefaultTrustedTopN = 100000

// DefaultThreatURL is the public threat-intelligence list used by default to
// corroborate malicious verdicts. abuse.ch URLhaus publishes a free, no-auth
// hosts file of domains hosting active malware.
const DefaultThreatURL = "https://urlhaus.abuse.ch/downloads/hostfile/"

// TrustedSet is an immutable set of registered domains considered well-known and
// legitimate (e.g. a popularity list like Tranco/Umbrella, or a curated
// allowlist). It is used to catch AI false positives: when the model flags a
// trusted domain, MazeDNS does not auto-block it — it asks for review instead.
type TrustedSet struct {
	domains map[string]struct{}
	// counts, when non-nil (threat sets only), records how many distinct sources
	// list each domain — so a single-feed hit (a possible misreport) can be weighed
	// less than corroboration across several feeds.
	counts map[string]int
}

// Has reports whether name's registered domain is in the trusted set.
func (t *TrustedSet) Has(name string) bool {
	if t == nil || len(t.domains) == 0 {
		return false
	}
	d := RegisteredDomain(name)
	if d == "" {
		return false
	}
	_, ok := t.domains[d]
	return ok
}

// Hits reports how many sources list name's registered domain (0 = absent). For a
// set built without counting it returns 1 when present, 0 otherwise.
func (t *TrustedSet) Hits(name string) int {
	if t == nil || len(t.domains) == 0 {
		return 0
	}
	d := RegisteredDomain(name)
	if d == "" {
		return 0
	}
	if t.counts != nil {
		return t.counts[d]
	}
	if _, ok := t.domains[d]; ok {
		return 1
	}
	return 0
}

// Count returns the number of registered domains in the set.
func (t *TrustedSet) Count() int {
	if t == nil {
		return 0
	}
	return len(t.domains)
}

// Search returns up to limit domains containing q (case-insensitive), sorted.
// An empty q returns the first `limit` domains — a preview of the set.
func (t *TrustedSet) Search(q string, limit int) []string {
	if t == nil {
		return nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q = strings.ToLower(strings.TrimSpace(q))
	out := make([]string, 0, limit)
	for d := range t.domains {
		if q == "" || strings.Contains(d, q) {
			out = append(out, d)
			if len(out) >= limit {
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// LoadTrusted builds a TrustedSet from a file path or http(s) URL. It accepts
// plain domain lists, hosts files, and ranked CSV (e.g. Tranco "rank,domain");
// each entry is reduced to its registered domain. topN > 0 caps how many entries
// are read (useful for large ranked lists).
func LoadTrusted(source string, topN int) (*TrustedSet, error) {
	var r io.ReadCloser
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("trusted list: status %d", resp.StatusCode)
		}
		r = resp.Body
	} else {
		f, err := os.Open(source)
		if err != nil {
			return nil, err
		}
		r = f
	}
	defer r.Close()
	return parseTrusted(r, topN)
}

func parseTrusted(r io.Reader, topN int) (*TrustedSet, error) {
	set := &TrustedSet{domains: make(map[string]struct{})}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Tokenize on commas and whitespace and take the first token that is a
		// real registered domain. This handles every common layout regardless of
		// which column the domain is in:
		//   "example.com"                       plain
		//   "1,example.com"                     ranked CSV (Tranco: rank,domain)
		//   "1,1,example.com,com,123,…"         ranked CSV (Majestic: domain in col 3)
		//   "0.0.0.0 example.com"               hosts
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if tok == "" || net.ParseIP(tok) != nil {
				continue // skip rank numbers, IPs, etc.
			}
			// URL feeds (e.g. OpenPhish) list full URLs — extract the host.
			if strings.Contains(tok, "://") {
				if u, err := url.Parse(tok); err == nil && u.Hostname() != "" {
					tok = u.Hostname()
				}
			}
			if d := RegisteredDomain(tok); d != "" && strings.ContainsRune(d, '.') {
				set.domains[d] = struct{}{}
				break
			}
		}
		if topN > 0 && len(set.domains) >= topN {
			break
		}
	}
	return set, sc.Err()
}
