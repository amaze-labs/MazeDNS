package classifier

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// TrustedSet is an immutable set of registered domains considered well-known and
// legitimate (e.g. a popularity list like Tranco/Umbrella, or a curated
// allowlist). It is used to catch AI false positives: when the model flags a
// trusted domain, MazeDNS does not auto-block it — it asks for review instead.
type TrustedSet struct {
	domains map[string]struct{}
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

// Count returns the number of trusted registered domains.
func (t *TrustedSet) Count() int {
	if t == nil {
		return 0
	}
	return len(t.domains)
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
		// Pull the domain out of common formats:
		//   "example.com"          plain
		//   "1,example.com"        ranked CSV (Tranco)
		//   "0.0.0.0 example.com"  hosts
		field := line
		if i := strings.LastIndexByte(field, ','); i >= 0 {
			field = field[i+1:]
		}
		if parts := strings.Fields(field); len(parts) > 1 {
			field = parts[len(parts)-1]
		}
		if d := RegisteredDomain(field); d != "" {
			set.domains[d] = struct{}{}
			if topN > 0 && len(set.domains) >= topN {
				break
			}
		}
	}
	return set, sc.Err()
}
