package classifier

import (
	"context"
	"log/slog"
	"strings"
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
