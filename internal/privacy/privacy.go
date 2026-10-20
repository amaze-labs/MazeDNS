// Package privacy reduces what MazeDNS keeps about each query, after Pi-hole's
// privacy levels. Filtering always sees the real client and name; only what is
// stored, streamed to the Live view and exported is reduced:
//
//	0  show everything
//	1  hide domains: every name is stored as "hidden" or, with a domain
//	   threshold k, only the rare ones (k-anonymity for domains: a name is kept
//	   when at least k devices queried it)
//	2  also hide clients: each client becomes a pseudonym ("anon-…") that is
//	   stable for one UTC day and cannot be linked to the next day's
//	3  anonymous: no query is kept; only the dashboard counts (by action and
//	   content category) remain
//
// A detail window can keep full detail for a few hours (for troubleshooting)
// before the level applies. The control plane applies the level as queries
// arrive when they are already past the window, and a background scrub
// applies it to everything stored once the window passes.
package privacy

import (
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// The privacy levels.
const (
	LevelShowAll     = 0
	LevelHideDomains = 1
	LevelHideClients = 2
	LevelAnonymous   = 3
)

// MaxDetailHours bounds the detail window (one week).
const MaxDetailHours = 168

// Hidden replaces a name the level does not keep.
const Hidden = "hidden"

// Policy is the operator's choice: the level, how many hours a query keeps
// full detail before the level applies (0 = as it arrives), and, at levels 1
// and 2, the domain threshold: 0 hides every domain, k >= 2 only those fewer
// than k devices queried that day (or the day before).
type Policy struct {
	Level       int
	DetailHours int
	DomainK     int
}

// Normalize clamps a policy into range.
func Normalize(p Policy) Policy {
	p.Level = min(max(p.Level, LevelShowAll), LevelAnonymous)
	p.DetailHours = min(max(p.DetailHours, 0), MaxDetailHours)
	if p.DomainK < 2 {
		p.DomainK = 0 // a threshold of 1 keeps every domain: not a privacy setting
	}
	p.DomainK = min(p.DomainK, MaxDomainK)
	return p
}

// rareOnly reports whether domains are hidden only when rare.
func (p Policy) rareOnly() bool {
	return p.DomainK > 0 && (p.Level == LevelHideDomains || p.Level == LevelHideClients)
}

// domainStrictness orders how much of the domains a policy removes (0 none,
// k for rare-only, above MaxDomainK all), so the scrub can tell when it must
// redo the history.
func (p Policy) domainStrictness() int64 {
	switch {
	case p.Level == LevelShowAll:
		return 0
	case p.rareOnly():
		return int64(p.DomainK)
	default:
		return MaxDomainK + 1 // every domain hidden
	}
}

// Cutoff is the time (unix millis) before which a query is past its detail
// window, so the level applies to it.
func (p Policy) Cutoff(now time.Time) int64 {
	return now.Add(-time.Duration(p.DetailHours) * time.Hour).UnixMilli()
}

// Anonymizer applies the current policy to query-log entries.
type Anonymizer struct {
	policy  func() Policy
	keys    *Keyring
	domains *domainTracker
}

// New returns an Anonymizer reading the current policy from policy (so a
// settings change applies at once) and pseudonymizing clients with keys.
func New(policy func() Policy, keys *Keyring) *Anonymizer {
	return &Anonymizer{policy: policy, keys: keys, domains: newDomainTracker(keys, nil)}
}

// SetDaySeeder lets the domain counts start from what the store holds (after
// a restart, or for history scrubbed after a policy change). Call before use.
func (a *Anonymizer) SetDaySeeder(seed DaySeeder) { a.domains.seed = seed }

// Policy returns the current, normalized policy.
func (a *Anonymizer) Policy() Policy {
	if a == nil || a.policy == nil {
		return Policy{}
	}
	return Normalize(a.policy())
}

// Ingest applies the level, in place, to the entries already past the detail
// window (all of them when there is none). Called as entries arrive, after
// they were labelled and queued for the classifier.
func (a *Anonymizer) Ingest(entries []store.QueryLogEntry, now time.Time) {
	p := a.Policy()
	if p.Level == LevelShowAll {
		return
	}
	if p.rareOnly() {
		// Count every query (with its real name and device) before deciding,
		// so a batch counts toward its own names.
		for _, e := range entries {
			a.domains.observe(e.Name, e.Client, e.TS, p.DomainK)
		}
	}
	cutoff := p.Cutoff(now)
	for i := range entries {
		if entries[i].TS < cutoff || p.DetailHours == 0 {
			a.apply(p, &entries[i])
		}
	}
}

// Export reduces the entries leaving MazeDNS (the VictoriaLogs export) to what
// the level keeps, regardless of the detail window: the window is for local
// troubleshooting only. At level 3 nothing is exported.
func (a *Anonymizer) Export(entries []store.QueryLogEntry) []store.QueryLogEntry {
	p := a.Policy()
	switch p.Level {
	case LevelShowAll:
		return entries
	case LevelAnonymous:
		return nil
	}
	for i := range entries {
		a.apply(p, &entries[i])
	}
	return entries
}

func (a *Anonymizer) apply(p Policy, e *store.QueryLogEntry) {
	level := p.Level
	switch {
	case p.rareOnly():
		e.Name = a.domains.keep(e.Name, e.TS, p.DomainK)
	case level >= LevelHideDomains:
		e.Name = Hidden
	}
	switch {
	case level >= LevelAnonymous:
		e.Client = ""
	case level >= LevelHideClients && e.Client != "" && !IsPseudonym(e.Client):
		e.Client = a.keys.Pseudonym(e.Client, e.TS)
	}
}
