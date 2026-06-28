package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Reputation is the result of corroborating a domain against public reputation
// services. It is folded into the legitimacy score: a clean report raises the
// score (fewer false positives), a malicious one lowers it.
type Reputation struct {
	// VirusTotal (domain report).
	VTChecked    bool `json:"vt_checked"`
	VTMalicious  int  `json:"vt_malicious"`  // vendors flagging it malicious
	VTSuspicious int  `json:"vt_suspicious"` // vendors flagging it suspicious
	VTHarmless   int  `json:"vt_harmless"`   // vendors saying harmless
	// AbuseIPDB (on the domain's resolved IP).
	AbuseChecked bool   `json:"abuse_checked"`
	AbuseScore   int    `json:"abuse_score"` // 0-100 abuse-confidence
	AbuseReports int    `json:"abuse_reports"`
	AbuseIP      string `json:"abuse_ip"`
}

// summary is a one-line form fed to the model as an extra signal.
func (r Reputation) summary() string {
	var parts []string
	if r.VTChecked {
		parts = append(parts, fmt.Sprintf("VirusTotal %d malicious / %d suspicious / %d harmless", r.VTMalicious, r.VTSuspicious, r.VTHarmless))
	}
	if r.AbuseChecked {
		parts = append(parts, fmt.Sprintf("AbuseIPDB confidence %d%% on %s (%d reports)", r.AbuseScore, r.AbuseIP, r.AbuseReports))
	}
	return strings.Join(parts, "; ")
}

// any reports whether any source was actually checked.
func (r Reputation) any() bool { return r.VTChecked || r.AbuseChecked }

// RepCache memoizes reputation lookups (external APIs are rate-limited).
type RepCache struct {
	mu sync.Mutex
	m  map[string]repEntry
}

type repEntry struct {
	rep Reputation
	exp time.Time
}

func NewRepCache() *RepCache { return &RepCache{m: make(map[string]repEntry)} }

// Lookup returns reputation for a domain per the enabled services, cached for a
// day. Each service is best-effort: an error or disabled service just leaves its
// fields unset.
func (c *RepCache) Lookup(ctx context.Context, domain string, s Settings) Reputation {
	domain = RegisteredDomain(domain)
	if domain == "" {
		return Reputation{}
	}
	if !s.VTEnabled && !s.AbuseIPDBEnabled {
		return Reputation{}
	}
	key := fmt.Sprintf("%s|%v|%v", domain, s.VTEnabled, s.AbuseIPDBEnabled)
	c.mu.Lock()
	if e, ok := c.m[key]; ok && time.Now().Before(e.exp) {
		c.mu.Unlock()
		return e.rep
	}
	c.mu.Unlock()

	var rep Reputation
	if s.VTEnabled && s.VTAPIKey != "" {
		if mal, susp, harm, err := vtDomainReport(ctx, domain, s.VTAPIKey); err == nil {
			rep.VTChecked, rep.VTMalicious, rep.VTSuspicious, rep.VTHarmless = true, mal, susp, harm
		}
	}
	if s.AbuseIPDBEnabled && s.AbuseIPDBAPIKey != "" {
		if ip := resolveIP(ctx, domain); ip != "" {
			if score, reports, err := abuseIPDBCheck(ctx, ip, s.AbuseIPDBAPIKey); err == nil {
				rep.AbuseChecked, rep.AbuseScore, rep.AbuseReports, rep.AbuseIP = true, score, reports, ip
			}
		}
	}
	ttl := 24 * time.Hour
	if !rep.any() {
		ttl = 30 * time.Minute // retry sooner if nothing resolved
	}
	c.mu.Lock()
	if len(c.m) > 20000 {
		c.m = make(map[string]repEntry)
	}
	c.m[key] = repEntry{rep: rep, exp: time.Now().Add(ttl)}
	c.mu.Unlock()
	return rep
}

func vtDomainReport(ctx context.Context, domain, apiKey string) (mal, susp, harm int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/domains/"+domain, nil)
	if err != nil {
		return 0, 0, 0, err
	}
	req.Header.Set("x-apikey", apiKey)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return 0, 0, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode != http.StatusOK {
		return 0, 0, 0, fmt.Errorf("virustotal: status %d", resp.StatusCode)
	}
	var vr struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &vr); err != nil {
		return 0, 0, 0, err
	}
	st := vr.Data.Attributes.LastAnalysisStats
	return st.Malicious, st.Suspicious, st.Harmless, nil
}

func abuseIPDBCheck(ctx context.Context, ip, apiKey string) (score, reports int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress="+ip, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("abuseipdb: status %d", resp.StatusCode)
	}
	var ar struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
			TotalReports         int `json:"totalReports"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &ar); err != nil {
		return 0, 0, err
	}
	return ar.Data.AbuseConfidenceScore, ar.Data.TotalReports, nil
}

// resolveIP returns one IP for a domain (used to check AbuseIPDB), "" on failure.
func resolveIP(ctx context.Context, domain string) string {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].IP.String()
}
