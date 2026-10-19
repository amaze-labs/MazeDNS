package classifier

import (
	"strings"
	"time"
)

// Names the classifier never looks at. Classifying a domain sends it to
// third parties (RDAP/WHOIS, the nameserver DoH check, reputation services,
// the language model), so names the network serves itself must stay out:
// queries a local record answered (the control plane drops those before
// enqueueing), names under a conditional forwarder's domain, and the domains
// the operator lists in Settings → Classification.

// fwdRefresh is how often the worker re-reads the forwarders.
const fwdRefresh = time.Minute

// NormalizeExcludes cleans an exclusion list: lower case, no wildcard
// prefix or trailing dot, no blanks or duplicates, only hostname characters.
func NormalizeExcludes(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "*.")
		d = strings.Trim(d, ".")
		if d == "" || seen[d] || !hostnameish(d) {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func hostnameish(d string) bool {
	if len(d) > 253 {
		return false
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return false
		}
	}
	return true
}

// underAny reports whether name is one of suffixes or under one of them.
func underAny(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if s != "" && (name == s || strings.HasSuffix(name, "."+s)) {
			return true
		}
	}
	return false
}

// Excluded reports whether name must never be classified: it is under one
// of the operator's excluded domains or a conditional forwarder's domain.
func (w *Worker) Excluded(name string) bool {
	name = strings.ToLower(strings.Trim(strings.TrimSpace(name), "."))
	if name == "" {
		return false
	}
	if underAny(name, w.get().ExcludeDomains) {
		return true
	}
	return underAny(name, w.forwarderSuffixes())
}

// forwarderSuffixes returns the conditional forwarders' domains (every
// scope: a name a forwarder serves anywhere in the cluster is internal),
// re-read at most once a minute.
func (w *Worker) forwarderSuffixes() []string {
	w.fwdMu.Lock()
	defer w.fwdMu.Unlock()
	if time.Since(w.fwdAt) < fwdRefresh {
		return w.fwdSuffixes
	}
	w.fwdAt = time.Now()
	fws, err := w.store.ListForwarders()
	if err != nil {
		return w.fwdSuffixes // keep the last good list
	}
	out := make([]string, 0, len(fws))
	for _, f := range fws {
		out = append(out, strings.ToLower(strings.Trim(f.Suffix, ".")))
	}
	w.fwdSuffixes = out
	return out
}
