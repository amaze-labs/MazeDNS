package classifier

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// Before 0.113.10 two trust shortcuts were too generous, and a domain is
// classified only once, so their verdicts would stand forever:
//
//   - nameserver trust: any domain on a CDN's nameservers (all of Cloudflare's
//     DNS customers) or merely LISTING a brand's nameservers scored 100;
//   - CDN trust: every customer site on a CDN-run hosting platform (web.app,
//     firebaseapp.com, azurewebsites.net, …) scored 100.
//
// rescoreLegacyTrusted removes those verdicts (only while still trusted-clean:
// a human decision is never touched) and queues the domains again, once.

const rescoreTrustedKey = "classifier.rescore_trusted_v1"

// Reason texts the old shortcuts recorded (recordTrusted: "legitimacy 100%. " +
// the factor detail).
const (
	legacyNSTrustReason  = "authoritative nameservers on trusted infrastructure"
	legacyCDNTrustReason = "CDN / cloud-edge infrastructure"
)

// legacyTrustToRescore reports whether a trusted-clean verdict came from one of
// the retired shortcuts and so must be scored again.
func legacyTrustToRescore(domain, reason string) bool {
	if strings.Contains(reason, legacyNSTrustReason) {
		return true
	}
	return strings.Contains(reason, legacyCDNTrustReason) && !cdnInfrastructure(domain)
}

func (w *Worker) rescoreLegacyTrusted(ctx context.Context) {
	s := w.get()
	if !s.Enabled || ParseMode(s.Mode) == ModeOff {
		return // retried on the next start with the classifier on
	}
	if done, _ := w.store.GetMeta(rescoreTrustedKey); done != "" {
		return
	}
	verdicts, err := w.store.TrustedCleanVerdicts()
	if err != nil {
		slog.Warn("rescore trusted verdicts: list failed", "err", err)
		return
	}
	var queued []string
	for _, v := range verdicts {
		if !legacyTrustToRescore(v.Domain, v.Reason) {
			continue
		}
		removed, err := w.store.DeleteTrustedCleanVerdict(v.Domain)
		if err != nil {
			slog.Warn("rescore trusted verdicts: delete failed", "domain", v.Domain, "err", err)
			return // not marked done: the rest is retried on the next start
		}
		if removed {
			queued = append(queued, v.Domain)
		}
	}
	if err := w.store.SetMeta(rescoreTrustedKey, "done"); err != nil {
		slog.Warn("rescore trusted verdicts: mark done failed", "err", err)
	}
	if len(queued) > 0 {
		slog.Info("re-scoring verdicts trusted by retired shortcuts", "count", len(queued))
	}
	// Queue them all, waiting for room rather than dropping like Enqueue: the
	// verdicts are already gone, and a domain not queued here would only be
	// re-scored on its next sighting.
	for _, d := range queued {
		w.mu.Lock()
		delete(w.recent, d)
		w.mu.Unlock()
		select {
		case w.queue <- d:
		case <-ctx.Done():
			return
		}
	}
}

// Verdicts are scored once, from the evidence of that moment, but some of it
// ages. rescoreLoop sends a machine verdict (never a human decision) back to
// scoring when:
//
//   - the domain was young: its age moves to the next bracket, and at two
//     years it counts as established (every rescoreYoungAfter until then);
//   - its registration date was unknown (the lookup failed): try again;
//   - it was flagged by threat feeds that no longer list it.
const (
	rescoreEvery         = 24 * time.Hour
	rescoreFirstAfter    = 10 * time.Minute
	rescoreBatch         = 200
	rescoreYoungAfter    = 30 * 24 * time.Hour
	rescoreUnknownAfter  = 7 * 24 * time.Hour
	rescoreUnlistedAfter = 24 * time.Hour
)

func (w *Worker) rescoreLoop(ctx context.Context) {
	t := time.NewTimer(rescoreFirstAfter)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.rescoreAged(time.Now())
			t.Reset(rescoreEvery)
		}
	}
}

// rescoreAged re-queues the verdicts whose evidence has aged (see above).
func (w *Worker) rescoreAged(now time.Time) int {
	s := w.get()
	if !s.Enabled || ParseMode(s.Mode) == ModeOff {
		return 0
	}
	n := 0
	ms := func(d time.Duration) int64 { return now.Add(-d).UnixMilli() }

	// Feed-flagged verdicts whose feeds dropped the domain.
	if vs, err := w.store.MachineVerdictsMatching(ms(rescoreUnlistedAfter), "", true, rescoreBatch); err == nil {
		for _, v := range vs {
			if w.threat.hits(v.Domain) > 0 {
				_ = w.store.TouchMachineVerdict(v.Domain) // still listed: check again tomorrow
				continue
			}
			if w.rescoreDomain(v.Domain, "no longer on any threat feed") {
				n++
			}
		}
	} else {
		slog.Warn("rescore: list flagged verdicts failed", "err", err)
	}
	// Young domains: a "registered N days ago" factor (under two years).
	if vs, err := w.store.MachineVerdictsMatching(ms(rescoreYoungAfter), `%"label":"Domain age","detail":"registered %`, false, rescoreBatch); err == nil {
		for _, v := range vs {
			if w.rescoreDomain(v.Domain, "domain has aged since it was scored") {
				n++
			}
		}
	}
	// Unknown registration date, when lookups are on.
	if s.WhoisEnabled {
		if vs, err := w.store.MachineVerdictsMatching(ms(rescoreUnknownAfter), `%registration date unknown%`, false, rescoreBatch); err == nil {
			for _, v := range vs {
				if w.rescoreDomain(v.Domain, "registration date was unknown") {
					n++
				}
			}
		}
	}
	if n > 0 {
		slog.Info("rescore: verdicts sent back to scoring", "count", n)
	}
	return n
}

// rescoreDomain removes a machine verdict and queues the domain again. A
// verdict that was enforcing a block stops enforcing it until the new one
// lands. It reports whether the domain was queued.
func (w *Worker) rescoreDomain(domain, why string) bool {
	removed, wasAuto, err := w.store.DeleteMachineVerdict(domain)
	if err != nil || !removed {
		return false
	}
	slog.Info("rescore", "domain", domain, "why", why)
	if wasAuto && w.reload != nil {
		_ = w.reload()
	}
	select {
	case w.queue <- domain:
		return true
	default:
		return false // queue full: it is classified again on its next sighting
	}
}
