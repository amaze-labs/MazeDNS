package privacy

import (
	"context"
	"log/slog"
	"time"

	"github.com/IPMaze/MazeDNS/internal/store"
)

const (
	// scrubCursorKey is how far (unix millis) the query log has been scrubbed;
	// scrubLevelKey the level that scrub applied. Raising the level resets the
	// cursor, so the new level reaches everything already stored.
	scrubCursorKey = "privacy_scrub_ts"
	scrubLevelKey  = "privacy_scrub_level"
	// scrubDomainKey is the domain strictness that scrub applied: raising it
	// (hiding more domains) resets the cursor too.
	scrubDomainKey = "privacy_scrub_domains"
	// scrubOverlap re-scrubs the tail of the last pass, for entries that
	// arrived (with a timestamp just past the window) while it ran.
	scrubOverlap = 10 * time.Minute
	// scrubEvery is how often the scrub runs.
	scrubEvery = time.Minute
)

// Scrubber applies the level to stored history once the detail window passes:
// on the cluster-wide query log and the per-client rollup, on the control plane.
type Scrubber struct {
	st *store.Store
	a  *Anonymizer
}

// NewScrubber returns a scrubber over st applying a's policy.
func NewScrubber(st *store.Store, a *Anonymizer) *Scrubber {
	return &Scrubber{st: st, a: a}
}

// Run scrubs every scrubEvery until ctx ends.
func (s *Scrubber) Run(ctx context.Context) {
	t := time.NewTicker(scrubEvery)
	defer t.Stop()
	for {
		if err := s.Scrub(time.Now()); err != nil {
			slog.Warn("privacy scrub failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Scrub applies the current level to everything stored before its cutoff.
func (s *Scrubber) Scrub(now time.Time) error {
	p := s.a.Policy()
	if p.Level == LevelShowAll {
		if err := s.st.SetMetaInt(scrubDomainKey, 0); err != nil {
			return err
		}
		return s.st.SetMetaInt(scrubLevelKey, 0)
	}
	cutoff := p.Cutoff(now)
	from, _ := s.st.GetMetaInt(scrubCursorKey)
	lastLevel, _ := s.st.GetMetaInt(scrubLevelKey)
	lastDomains, _ := s.st.GetMetaInt(scrubDomainKey)
	redo := int64(p.Level) > lastLevel || p.domainStrictness() > lastDomains
	if redo {
		from = 0 // stricter than what was applied: redo all history
	} else {
		from = max(from-scrubOverlap.Milliseconds(), 0)
	}
	// Nothing before the oldest entry needs scrubbing (and an empty log needs
	// no pass at all).
	first, err := s.st.OldestQueryLogTS()
	if err != nil {
		return err
	}
	from = max(from, first)
	// One day per statement, so scrubbing a long history never holds the
	// database for long.
	var hidden, renamed int64
	for lo := from; first > 0 && lo < cutoff; {
		hi := min((lo/dayMs+1)*dayMs, cutoff)
		switch {
		case !p.rareOnly():
			n, err := s.st.HideQueryLogNames(lo, hi, Hidden)
			if err != nil {
				return err
			}
			hidden += n
		case p.DetailHours > 0 || redo:
			// Rare-only: decide name by name. With no detail window, ingest
			// already decided every new query, so only a redo needs this.
			n, err := s.st.ReduceQueryLogNames(lo, hi, Hidden, func(name string, ts int64) string {
				return s.a.domains.keep(name, ts, p.DomainK)
			})
			if err != nil {
				return err
			}
			hidden += n
		}
		if p.Level == LevelHideClients {
			n, err := s.st.PseudonymizeQueryLog(lo, hi, PseudonymPrefix, s.a.keys.Pseudonym)
			if err != nil {
				return err
			}
			renamed += n
		}
		lo = hi
	}
	cutoffHour := cutoff / 3600000
	switch p.Level {
	case LevelHideClients:
		if err := s.st.RekeyClientRollup(from/3600000, cutoffHour, PseudonymPrefix, s.a.keys.Pseudonym); err != nil {
			return err
		}
	case LevelAnonymous:
		n, err := s.st.DeleteRolledUpQueryLog(cutoff)
		if err != nil {
			return err
		}
		if n > 0 {
			slog.Debug("privacy: anonymous mode removed counted queries", "removed", n)
		}
		if err := s.st.DeleteClientRollup(cutoffHour); err != nil {
			return err
		}
	}
	if hidden > 0 || renamed > 0 {
		slog.Info("privacy scrub", "level", p.Level, "names_reduced", hidden, "clients_pseudonymized", renamed)
	}
	// Day keys only matter while a day can still receive a pseudonym: keep the
	// cutoff's day (late entries) and drop the rest, so older pseudonyms can
	// no longer be tied back to an address.
	s.a.keys.Prune(cutoff)
	s.a.domains.prune(cutoff/dayMs - 1) // the cutoff's day still uses the day before
	if err := s.st.SetMetaInt(scrubCursorKey, cutoff); err != nil {
		return err
	}
	if err := s.st.SetMetaInt(scrubDomainKey, p.domainStrictness()); err != nil {
		return err
	}
	return s.st.SetMetaInt(scrubLevelKey, int64(p.Level))
}
