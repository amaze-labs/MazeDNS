// Package classifier asks a local, OpenAI-compatible LLM endpoint (Ollama,
// llama.cpp, LM Studio, …) to classify domains as ads/trackers/malware/etc., so
// blocking can be driven by a model instead of hand-maintained lists. Everything
// runs against the user's own local model — no external calls.
package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// blockCategories are the security categories that warrant blocking. Everything
// else (content categories, clean, other) is recorded but never blocked.
var blockCategories = map[string]bool{
	"ads": true, "trackers": true, "malware": true, "phishing": true,
}

// contentCategories label legitimate traffic by type, so the classifier gives
// visibility into what a network is doing — not just what to block.
var contentCategories = []string{
	"social", "streaming", "shopping", "news", "gaming", "productivity",
	"search", "email", "finance", "technology", "cdn", "adult",
}

// validCategories is the full accepted set (security + content + "other").
var validCategories = func() map[string]bool {
	m := map[string]bool{"other": true}
	for c := range blockCategories {
		m[c] = true
	}
	for _, c := range contentCategories {
		m[c] = true
	}
	return m
}()

// Verdict is the model's classification of a single registered domain.
type Verdict struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// ShouldBlock reports whether this verdict's category is one we block.
func (v Verdict) ShouldBlock() bool { return blockCategories[v.Category] }

// Client talks to an OpenAI-compatible /chat/completions endpoint.
type Client struct {
	baseURL string
	model   string
	apiKey  string
	http    *http.Client
}

// NewClient builds a classifier client. baseURL is the OpenAI-compatible base
// (e.g. "http://localhost:11434/v1"); apiKey is usually empty for local models.
func NewClient(baseURL, model, apiKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: timeout},
	}
}

const systemPrompt = `You classify internet domains for a DNS filter and analytics dashboard.
Respond with ONLY a JSON object, no prose, of the form:
{"category":"<one category below>","confidence":<0..1>,"reason":"<short>"}

Blocking categories (only choose when reasonably sure):
- ads: advertising / ad-serving
- trackers: analytics / telemetry / user tracking
- malware: malware C2, drive-by, exploit kits
- phishing: credential theft / scams

Legitimate content categories (describe what the domain is for; never blocked):
- social: social networks / messaging (e.g. facebook, instagram, reddit)
- streaming: video/music streaming (e.g. youtube, netflix, spotify, twitch)
- shopping: e-commerce / retail
- news: news / media publications
- gaming: games / gaming platforms
- productivity: work / office / collaboration tools
- search: search engines
- email: webmail / email providers
- finance: banking / payments / investing
- technology: developer / software / tech services (e.g. github)
- cdn: CDNs / cloud infrastructure
- adult: adult content

Fallback:
- other: legitimate but none of the above fit, or unknown

Pick the single best-fitting category.`

type chatReq struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	Stream      bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResp struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Hints carries deterministic signals (looked up before the model runs) so the
// model can incorporate them into its verdict and reasoning.
type Hints struct {
	Trusted bool   // on a known-legitimate / popular-domains list
	Threat  bool   // on a known-malicious threat-intel feed
	Whois   string // one-line registration summary (e.g. "registered 5 days ago …")
}

// Classify returns the model's verdict for a domain, informed by any hints.
func (c *Client) Classify(ctx context.Context, domain string, h Hints) (Verdict, error) {
	user := "Classify this domain: " + domain
	if h.Threat {
		user += "\nSignal: this domain appears on a public threat-intelligence feed of domains hosting active malware — weigh this heavily."
	}
	if h.Trusted {
		user += "\nSignal: this domain is among the most popular, established domains on the internet — very unlikely to be malicious."
	}
	if h.Whois != "" {
		user += "\nRegistration (WHOIS): " + h.Whois + "."
	}
	body, err := json.Marshal(chatReq{
		Model:       c.model,
		Temperature: 0,
		Stream:      false,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return Verdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("classifier: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var cr chatResp
	if err := json.Unmarshal(raw, &cr); err != nil {
		return Verdict{}, fmt.Errorf("classifier: bad response: %w", err)
	}
	if cr.Error != nil {
		return Verdict{}, fmt.Errorf("classifier: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return Verdict{}, fmt.Errorf("classifier: empty response")
	}
	return parseVerdict(cr.Choices[0].Message.Content)
}

// parseVerdict extracts the JSON verdict from the model's reply, tolerating
// surrounding prose or markdown fences.
func parseVerdict(content string) (Verdict, error) {
	start := strings.IndexByte(content, '{')
	end := strings.LastIndexByte(content, '}')
	if start < 0 || end <= start {
		return Verdict{}, fmt.Errorf("classifier: no JSON in reply %q", truncate(content, 120))
	}
	var v Verdict
	if err := json.Unmarshal([]byte(content[start:end+1]), &v); err != nil {
		return Verdict{}, fmt.Errorf("classifier: unparseable verdict: %w", err)
	}
	v.Category = strings.ToLower(strings.TrimSpace(v.Category))
	if !validCategories[v.Category] {
		v.Category = "other" // unknown label -> treated as non-blocking
	}
	return v, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RegisteredDomain returns the eTLD+1 (the registered domain) for a name, so a
// verdict applies to the whole domain and all its subdomains — and never to a
// bare public suffix like "co.uk". Returns "" if it can't be determined.
func RegisteredDomain(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return ""
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return reg
}
