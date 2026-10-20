package privacy

import (
	"log/slog"
	"strings"
	"sync"

	"github.com/IPMaze/MazeDNS/internal/classifier"
)

// MaxDomainK bounds the domain threshold.
const MaxDomainK = 100

// maxTrackedNames bounds the names counted per day; a name beyond it is
// treated as rare (hidden), never as common.
const maxTrackedNames = 1_000_000

// DaySeeder lists the distinct (name, client) pairs stored for one UTC day,
// so counts survive a restart and cover history scrubbed after a level change.
type DaySeeder func(dayStartMs int64, each func(name, client string)) error

// domainTracker is k-anonymity for domains: it counts, per UTC day, how many
// distinct devices queried each name and each registered domain, so only
// names at least k devices share are kept. A device is counted by its day
// pseudonym, never its address, and only up to k of them are remembered per
// name: past k the name is just marked common.
type domainTracker struct {
	mu     sync.Mutex
	keys   *Keyring
	seed   DaySeeder
	k      int // the threshold the counts were kept for
	days   map[int64]*dayCounts
	warned bool
}

type dayCounts struct {
	names map[string]*seenBy // full name ("a.example.com.")
	regs  map[string]*seenBy // registered domain ("example.com.")
}

type seenBy struct {
	common bool
	devs   []string // distinct pseudonyms, until common
}

func newDomainTracker(keys *Keyring, seed DaySeeder) *domainTracker {
	return &domainTracker{keys: keys, seed: seed, days: map[int64]*dayCounts{}}
}

// observe counts client's query for name at tsMs.
func (t *domainTracker) observe(name, client string, tsMs int64, k int) {
	if name == "" || name == Hidden || client == "" {
		return
	}
	dev := client
	if !IsPseudonym(dev) {
		dev = t.keys.Pseudonym(client, tsMs)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setK(k)
	t.count(t.day(tsMs/dayMs), name, dev)
}

// keep returns what to store for name, queried at tsMs: the name itself when at
// least k devices queried it that day or the day before; else its registered
// domain when that is shared by k devices; else Hidden.
func (t *domainTracker) keep(name string, tsMs int64, k int) string {
	if name == "" || name == Hidden {
		return name
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setK(k)
	day := tsMs / dayMs
	today, before := t.day(day), t.day(day-1)
	n := canonical(name)
	if common(today.names, n) || common(before.names, n) {
		return name
	}
	if reg := registered(name); reg != "" && (common(today.regs, reg) || common(before.regs, reg)) {
		return reg
	}
	return Hidden
}

// prune forgets the days before beforeDay.
func (t *domainTracker) prune(beforeDay int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for day := range t.days {
		if day < beforeDay {
			delete(t.days, day)
		}
	}
}

// day returns a day's counts, seeding them from the store on first use in
// this process; t.mu must be held.
func (t *domainTracker) day(day int64) *dayCounts {
	if d, ok := t.days[day]; ok {
		return d
	}
	d := &dayCounts{names: map[string]*seenBy{}, regs: map[string]*seenBy{}}
	t.days[day] = d
	if t.seed != nil {
		err := t.seed(day*dayMs, func(name, client string) {
			if name == "" || name == Hidden || client == "" {
				return
			}
			dev := client
			if !IsPseudonym(dev) {
				dev = t.keys.Pseudonym(client, day*dayMs)
			}
			t.count(d, name, dev)
		})
		if err != nil {
			slog.Warn("privacy: seeding domain counts failed; rare-domain checks start empty", "err", err)
		}
	}
	return d
}

// setK starts the counts over when the threshold changed (they only remember
// up to k devices per name); t.mu must be held.
func (t *domainTracker) setK(k int) {
	if k != t.k {
		t.k = k
		t.days = map[int64]*dayCounts{}
	}
}

// count records dev for name and its registered domain; t.mu must be held.
func (t *domainTracker) count(d *dayCounts, name, dev string) {
	t.add(d.names, canonical(name), dev)
	if reg := registered(name); reg != "" {
		t.add(d.regs, reg, dev)
	}
}

// add records dev for key; t.mu must be held.
func (t *domainTracker) add(m map[string]*seenBy, key, dev string) {
	s := m[key]
	if s == nil {
		if len(m) >= maxTrackedNames {
			if !t.warned {
				t.warned = true
				slog.Warn("privacy: too many distinct names today; further rare names are hidden")
			}
			return
		}
		s = &seenBy{}
		m[key] = s
	}
	if s.common {
		return
	}
	for _, d := range s.devs {
		if d == dev {
			return
		}
	}
	s.devs = append(s.devs, dev)
	if len(s.devs) >= t.k {
		s.common, s.devs = true, nil
	}
}

// common reports whether key reached k devices.
func common(m map[string]*seenBy, key string) bool {
	s := m[key]
	return s != nil && s.common
}

// canonical is the lowercased name with its trailing dot, as stored.
func canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}

// registered is name's registered domain in stored form ("" if none).
func registered(name string) string {
	reg := classifier.RegisteredDomain(name)
	if reg == "" {
		return ""
	}
	return reg + "."
}
