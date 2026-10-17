package classifier

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestRescoreLegacyTrusted(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	const (
		nsReason  = "legitimacy 100%. authoritative nameservers on trusted infrastructure (cloudflare.com) — cannot be malicious"
		cdnReason = "legitimacy 100%. CDN / cloud-edge infrastructure — trusted (a verdict would apply to the whole provider)"
		topReason = "legitimacy 100%. on the trusted top-domains list — cannot be malicious"
	)
	for _, c := range []store.Classification{
		{Domain: "phish-on-cloudflare.com", Status: store.ClassClean, Trusted: true, Reason: nsReason}, // re-score
		{Domain: "evil.web.app", Status: store.ClassClean, Trusted: true, Reason: cdnReason},           // re-score
		{Domain: "cloudfront.net", Status: store.ClassClean, Trusted: true, Reason: cdnReason},         // provider: keep
		{Domain: "google.com", Status: store.ClassClean, Trusted: true, Reason: topReason},             // list: keep
		{Domain: "reviewed.com", Status: store.ClassRejected, Trusted: true, Reason: nsReason},         // human: keep
		{Domain: "untrusted.com", Status: store.ClassClean, Trusted: false, Reason: "legitimacy 80%."}, // keep
	} {
		if _, err := st.InsertClassification(c); err != nil {
			t.Fatal(err)
		}
	}

	w := NewWorker(st, func() Settings { return Settings{Enabled: true, Mode: string(ModeSuggest)} }, nil)
	w.rescoreLegacyTrusted(context.Background())

	var queued []string
	for len(w.queue) > 0 {
		queued = append(queued, <-w.queue)
	}
	sort.Strings(queued)
	if want := []string{"evil.web.app", "phish-on-cloudflare.com"}; len(queued) != 2 || queued[0] != want[0] || queued[1] != want[1] {
		t.Fatalf("queued = %v, want %v", queued, want)
	}
	for d, want := range map[string]bool{
		"phish-on-cloudflare.com": false, "evil.web.app": false,
		"cloudfront.net": true, "google.com": true, "reviewed.com": true, "untrusted.com": true,
	} {
		if got, _ := st.IsClassified(d); got != want {
			t.Errorf("%s classified = %v, want %v", d, got, want)
		}
	}

	// Runs once: a later start doesn't touch new verdicts.
	if _, err := st.InsertClassification(store.Classification{Domain: "later.com", Status: store.ClassClean, Trusted: true, Reason: nsReason}); err != nil {
		t.Fatal(err)
	}
	w.rescoreLegacyTrusted(context.Background())
	if len(w.queue) != 0 {
		t.Error("second run queued domains again")
	}
	if got, _ := st.IsClassified("later.com"); !got {
		t.Error("second run deleted a verdict")
	}
}

// With the classifier off nothing is done, and the one-off stays pending.
func TestRescoreLegacyTrustedWaitsForClassifier(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	w := NewWorker(st, func() Settings { return Settings{Enabled: false} }, nil)
	w.rescoreLegacyTrusted(context.Background())
	if v, _ := st.GetMeta(rescoreTrustedKey); v != "" {
		t.Errorf("marked done (%q) while the classifier was off", v)
	}
}
