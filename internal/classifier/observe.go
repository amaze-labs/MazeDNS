package classifier

import (
	"strings"
	"sync"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// Behaviour is what this network has seen of a registered domain in its query
// stream — passive-DNS signals no outside service can give: how widely it is
// used, and the shapes malware leaves (DNS tunneling, generated names).
type Behaviour struct {
	FirstSeen  time.Time
	Queries    int
	Clients    int // distinct clients (capped)
	Subdomains int // distinct names under the domain (capped)
	// RandomSubs counts distinct subdomain labels that look generated or
	// encoded (long and unnatural): the shape of data smuggled out over DNS.
	RandomSubs int
	LongestSub int // longest subdomain label seen
	NXDomain   int // answers saying the name doesn't exist
	TXTLike    int // TXT / NULL / ANY queries, the usual tunneling carriers
	Names      []string
}

// Thresholds of the behaviour signals.
const (
	tunnelMinSubs   = 50  // distinct subdomains before a tunneling pattern counts
	tunnelRandShare = 0.6 // share of them that look generated/encoded
	tunnelLongLabel = 40  // a subdomain label this long is data, not a hostname
	nxMinQueries    = 5
	nxShare         = 0.8
)

// Tunneling reports the DNS-tunneling / exfiltration shape: many distinct
// subdomains, mostly long and random, or very long labels carried in TXT.
func (b Behaviour) Tunneling() bool {
	if b.Subdomains >= tunnelMinSubs && float64(b.RandomSubs) >= tunnelRandShare*float64(b.Subdomains) {
		return true
	}
	return b.LongestSub >= tunnelLongLabel && b.Subdomains >= 10 && b.TXTLike*2 >= b.Queries
}

// MostlyNX reports a domain whose names mostly don't exist: typical of
// generated (DGA) names a malware client tries until one is registered.
func (b Behaviour) MostlyNX() bool {
	return b.Queries >= nxMinQueries && float64(b.NXDomain) >= nxShare*float64(b.Queries)
}

// observation is the running tally behind a Behaviour.
type observation struct {
	first, last time.Time
	queries     int
	clients     map[string]struct{}
	subs        map[string]struct{}
	randomSubs  int
	longestSub  int
	nx, txt     int
	names       []string
	requeued    time.Time // last time a behaviour change sent it back to scoring
}

// Caps that keep the tracker small on a busy network.
const (
	obsMaxDomains = 50000
	obsMaxClients = 64
	obsMaxSubs    = 1000
	obsMaxNames   = 8
	obsTTL        = 7 * 24 * time.Hour
)

// observer tallies the query stream per registered domain.
type observer struct {
	mu  sync.Mutex
	m   map[string]*observation
	lex func() *Lexicon
}

func newObserver(lex func() *Lexicon) *observer {
	return &observer{m: map[string]*observation{}, lex: lex}
}

// add records one query. It reports whether the domain just turned into a
// tunneling pattern (at most once a day), so its verdict gets scored again.
func (o *observer) add(domain string, e store.QueryLogEntry, now time.Time) bool {
	name := strings.ToLower(strings.TrimSuffix(e.Name, "."))
	o.mu.Lock()
	defer o.mu.Unlock()
	ob := o.m[domain]
	if ob == nil {
		if len(o.m) >= obsMaxDomains {
			o.pruneLocked(now)
		}
		ob = &observation{first: now, clients: map[string]struct{}{}, subs: map[string]struct{}{}}
		o.m[domain] = ob
	}
	ob.last = now
	ob.queries++
	if e.Client != "" && len(ob.clients) < obsMaxClients {
		ob.clients[e.Client] = struct{}{}
	}
	if e.Rcode == "NXDOMAIN" {
		ob.nx++
	}
	switch e.QType {
	case "TXT", "NULL", "ANY":
		ob.txt++
	}
	if sub := strings.TrimSuffix(name, "."+domain); sub != name && sub != "" {
		if _, seen := ob.subs[sub]; !seen && len(ob.subs) < obsMaxSubs {
			ob.subs[sub] = struct{}{}
			if len(ob.names) < obsMaxNames {
				ob.names = append(ob.names, name)
			}
			first := sub
			if i := strings.IndexByte(sub, '.'); i >= 0 {
				first = sub[:i]
			}
			if len(first) > ob.longestSub {
				ob.longestSub = len(first)
			}
			if randomSub(first, o.lex()) {
				ob.randomSubs++
			}
		}
	}
	if ob.behaviour().Tunneling() && now.Sub(ob.requeued) > 24*time.Hour {
		ob.requeued = now
		return true
	}
	return false
}

func (ob *observation) behaviour() Behaviour {
	return Behaviour{
		FirstSeen: ob.first, Queries: ob.queries, Clients: len(ob.clients), Subdomains: len(ob.subs),
		RandomSubs: ob.randomSubs, LongestSub: ob.longestSub, NXDomain: ob.nx, TXTLike: ob.txt,
		Names: append([]string(nil), ob.names...),
	}
}

// get returns what is known of a domain (zero when nothing).
func (o *observer) get(domain string) Behaviour {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ob := o.m[domain]; ob != nil {
		return ob.behaviour()
	}
	return Behaviour{}
}

// pruneLocked drops domains not seen for obsTTL, then the least recently seen
// tenth if that wasn't enough.
func (o *observer) pruneLocked(now time.Time) {
	for d, ob := range o.m {
		if now.Sub(ob.last) > obsTTL {
			delete(o.m, d)
		}
	}
	if len(o.m) < obsMaxDomains {
		return
	}
	var oldest time.Time
	for _, ob := range o.m {
		if oldest.IsZero() || ob.last.Before(oldest) {
			oldest = ob.last
		}
	}
	cut := oldest.Add(now.Sub(oldest) / 10)
	for d, ob := range o.m {
		if ob.last.Before(cut) {
			delete(o.m, d)
		}
	}
}

// randomSub reports a subdomain label that looks generated or encoded: long
// hex/base32/base64-like runs, or unnatural to the lexicon.
func randomSub(label string, lex *Lexicon) bool {
	if len(label) < 16 {
		return false
	}
	// Hex or very long labels are encoded data whatever the letters: a real
	// hostname label is short and made of words.
	if len(label) >= 32 || isHex(label) {
		return true
	}
	if lex != nil {
		if n, ok := lex.naturalness(label); ok {
			return n < lex.randomCut
		}
	}
	return entropy(label) > 3.8
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
