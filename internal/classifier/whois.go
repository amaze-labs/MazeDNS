package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WhoisInfo is the registration data MazeDNS surfaces for a domain. It is sourced
// via RDAP (the JSON successor to port-43 WHOIS), so no free-text parsing.
type WhoisInfo struct {
	Domain      string   `json:"domain"`
	Registrar   string   `json:"registrar"`
	Registrant  string   `json:"registrant"` // registrant org, when not redacted (a strong ownership signal)
	Created     string   `json:"created"`    // registration date (RFC3339)
	Expires     string   `json:"expires"`
	Updated     string   `json:"updated"`
	AgeDays     int      `json:"age_days"` // days since registration (0 if unknown)
	Status      []string `json:"status"`
	Nameservers []string `json:"nameservers"`
}

// summary is a compact one-line form fed to the model as a signal. Domain age and
// — crucially — ownership (registrant org and nameservers) help the model avoid
// flagging a brand's own domain (e.g. aaplimg.com is Apple's) as phishing.
func (w WhoisInfo) summary() string {
	var parts []string
	if w.AgeDays > 0 {
		s := fmt.Sprintf("registered %d days ago", w.AgeDays)
		if w.AgeDays < 90 {
			s += " (very new — treat with suspicion)"
		}
		parts = append(parts, s)
	} else if w.Created != "" {
		parts = append(parts, "registered "+w.Created)
	}
	if w.Registrant != "" {
		parts = append(parts, fmt.Sprintf("registrant org %q", w.Registrant))
	}
	if w.Registrar != "" {
		parts = append(parts, fmt.Sprintf("registrar %q", w.Registrar))
	}
	if len(w.Nameservers) > 0 {
		ns := w.Nameservers
		if len(ns) > 4 {
			ns = ns[:4]
		}
		parts = append(parts, "nameservers "+strings.Join(ns, ", "))
	}
	return strings.Join(parts, "; ")
}

// rdapResp is the subset of an RDAP domain object MazeDNS reads.
type rdapResp struct {
	Status []string `json:"status"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VcardArray []any    `json:"vcardArray"`
	} `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

// LookupWhois queries RDAP for a domain via the public bootstrap (rdap.org),
// which redirects to the authoritative RDAP server for the TLD.
func LookupWhois(ctx context.Context, domain string) (WhoisInfo, error) {
	domain = RegisteredDomain(domain)
	if domain == "" {
		return WhoisInfo{}, fmt.Errorf("whois: invalid domain")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/domain/"+domain, nil)
	if err != nil {
		return WhoisInfo{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return WhoisInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return WhoisInfo{}, fmt.Errorf("whois: rdap status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	var rd rdapResp
	if err := json.Unmarshal(body, &rd); err != nil {
		return WhoisInfo{}, err
	}
	return parseRDAP(domain, rd), nil
}

func parseRDAP(domain string, rd rdapResp) WhoisInfo {
	info := WhoisInfo{Domain: domain, Status: rd.Status}
	for _, e := range rd.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			info.Created = e.Date
		case "expiration":
			info.Expires = e.Date
		case "last changed", "last update of rdap database":
			if info.Updated == "" {
				info.Updated = e.Date
			}
		}
	}
	for _, e := range rd.Entities {
		if info.Registrar == "" && containsFold(e.Roles, "registrar") {
			info.Registrar = vcardField(e.VcardArray, "fn")
		}
		// Registrant org is the clearest ownership signal (often redacted, but
		// present for corporate domains — e.g. "Apple Inc.").
		if info.Registrant == "" && (containsFold(e.Roles, "registrant") || containsFold(e.Roles, "administrative")) {
			if org := vcardField(e.VcardArray, "org"); org != "" {
				info.Registrant = org
			} else if fn := vcardField(e.VcardArray, "fn"); fn != "" {
				info.Registrant = fn
			}
		}
	}
	for _, ns := range rd.Nameservers {
		if ns.LDHName != "" {
			info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	if t, err := time.Parse(time.RFC3339, info.Created); err == nil {
		if d := int(time.Since(t).Hours() / 24); d > 0 {
			info.AgeDays = d
		}
	}
	return info
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// vcardField pulls a named field (e.g. "fn") out of an RDAP vcardArray:
// ["vcard", [ ["version",{},"text","4.0"], ["fn",{},"text","Name"], ... ]].
func vcardField(vcard []any, name string) string {
	if len(vcard) < 2 {
		return ""
	}
	entries, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, e := range entries {
		row, ok := e.([]any)
		if !ok || len(row) < 4 {
			continue
		}
		if key, _ := row[0].(string); strings.EqualFold(key, name) {
			if v, ok := row[3].(string); ok {
				return v
			}
		}
	}
	return ""
}

// WhoisCache memoizes RDAP lookups (they're slow and rate-limited). Successes are
// cached for a day, failures briefly so a flaky domain isn't hammered.
type WhoisCache struct {
	mu sync.Mutex
	m  map[string]whoisEntry
}

type whoisEntry struct {
	info WhoisInfo
	err  error
	exp  time.Time
}

func NewWhoisCache() *WhoisCache { return &WhoisCache{m: make(map[string]whoisEntry)} }

// Lookup returns cached registration data, fetching it on a miss.
func (c *WhoisCache) Lookup(ctx context.Context, domain string) (WhoisInfo, error) {
	domain = RegisteredDomain(domain)
	c.mu.Lock()
	if e, ok := c.m[domain]; ok && time.Now().Before(e.exp) {
		c.mu.Unlock()
		return e.info, e.err
	}
	c.mu.Unlock()

	info, err := LookupWhois(ctx, domain)
	ttl := 24 * time.Hour
	if err != nil {
		ttl = 15 * time.Minute
	}
	c.mu.Lock()
	if len(c.m) > 20000 {
		c.m = make(map[string]whoisEntry) // crude bound — drop the lot rather than grow forever
	}
	c.m[domain] = whoisEntry{info: info, err: err, exp: time.Now().Add(ttl)}
	c.mu.Unlock()
	return info, err
}
