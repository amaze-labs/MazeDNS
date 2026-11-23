package classifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Certificate Transparency: every publicly trusted certificate is logged, and
// crt.sh (free, no key) searches the logs. When a domain got its first
// certificate tells when its site went up — a stand-in for the registration
// date where the registry publishes none (many country domains). Phishing
// sites get their certificate minutes before the first victim.

const (
	ctTimeout  = 15 * time.Second
	ctMaxBody  = 4 << 20 // a domain with this many certificates is no new site
	ctCacheTTL = 24 * time.Hour
	ctMinGap   = 2 * time.Second // crt.sh is a shared free service
)

type ctEntry struct {
	age int
	at  time.Time
}

type ctCache struct {
	mu   sync.Mutex
	m    map[string]ctEntry
	last time.Time
	base string // crt.sh URL; tests point it elsewhere
	http *http.Client
}

func newCTCache() *ctCache {
	return &ctCache{m: map[string]ctEntry{}, base: "https://crt.sh/", http: &http.Client{Timeout: ctTimeout}}
}

// ctOld is returned for a domain with more certificates than worth reading:
// established enough.
const ctOld = 10000

// firstCertAge returns the age in days of the domain's first logged
// certificate: 0 for none at all, -1 when crt.sh couldn't say.
func (c *ctCache) firstCertAge(ctx context.Context, domain string) int {
	c.mu.Lock()
	if e, ok := c.m[domain]; ok && time.Since(e.at) < ctCacheTTL {
		c.mu.Unlock()
		return e.age
	}
	if len(c.m) > 20000 {
		c.m = map[string]ctEntry{}
	}
	if wait := ctMinGap - time.Since(c.last); wait > 0 {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return -1
		case <-time.After(wait):
		}
		c.mu.Lock()
	}
	c.last = time.Now()
	c.mu.Unlock()

	age := c.query(ctx, domain)
	if age >= 0 {
		c.mu.Lock()
		c.m[domain] = ctEntry{age: age, at: time.Now()}
		c.mu.Unlock()
	}
	return age
}

func (c *ctCache) query(ctx context.Context, domain string) int {
	ctx, cancel := context.WithTimeout(ctx, ctTimeout)
	defer cancel()
	u := c.base + "?output=json&deduplicate=Y&q=" + url.QueryEscape(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return -1
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ctMaxBody+1))
	if err != nil {
		return -1
	}
	if len(body) > ctMaxBody {
		return ctOld
	}
	var certs []struct {
		NotBefore string `json:"not_before"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		return -1
	}
	if len(certs) == 0 {
		return 0
	}
	var first time.Time
	for _, cert := range certs {
		t, err := time.Parse("2006-01-02T15:04:05", cert.NotBefore)
		if err == nil && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}
	if first.IsZero() {
		return -1
	}
	days := int(time.Since(first).Hours() / 24)
	if days < 1 {
		days = 1 // "issued today" must not read as "no certificate"
	}
	return days
}
