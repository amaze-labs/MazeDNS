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

// IsBlockCategory reports whether cat is a security category that warrants
// blocking (ads/trackers/malware/phishing).
func IsBlockCategory(cat string) bool { return blockCategories[cat] }

// IsContentCategory reports whether cat is a recognised non-blocking category
// (a content category or "other") — the categories valid when allowing a domain.
func IsContentCategory(cat string) bool { return validCategories[cat] && !blockCategories[cat] }

// Verdict is the model's classification of a single registered domain.
type Verdict struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// ShouldBlock reports whether this verdict's category is one we block.
func (v Verdict) ShouldBlock() bool { return blockCategories[v.Category] }

// Supported LLM providers. "openai" is any OpenAI-compatible /chat/completions
// endpoint (OpenAI, Ollama, LM Studio, llama.cpp, vLLM, …); "anthropic" is the
// Anthropic Messages API (Claude).
const (
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
)

// normalizeProvider defaults an unknown/blank provider to OpenAI-compatible.
func normalizeProvider(p string) string {
	if strings.ToLower(strings.TrimSpace(p)) == ProviderAnthropic {
		return ProviderAnthropic
	}
	return ProviderOpenAI
}

// Client talks to an LLM provider (OpenAI-compatible chat completions or the
// Anthropic Messages API) to classify a domain.
type Client struct {
	provider string
	baseURL  string
	model    string
	apiKey   string
	http     *http.Client
}

// NewClient builds a classifier client for the given provider. For "openai",
// baseURL is the OpenAI-compatible base (e.g. "http://localhost:11434/v1") and
// apiKey is usually empty for local models. For "anthropic", baseURL defaults to
// the public API and apiKey is the Anthropic API key.
func NewClient(provider, baseURL, model, apiKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	provider = normalizeProvider(provider)
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" && provider == ProviderAnthropic {
		base = "https://api.anthropic.com"
	}
	return &Client{
		provider: provider,
		baseURL:  base,
		model:    model,
		apiKey:   apiKey,
		http:     &http.Client{Timeout: timeout},
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

Important: if registration data (WHOIS) is provided, weigh it heavily. A domain
whose registrant organization or nameservers belong to a major company is
legitimately owned by that company — NOT phishing — even if the name looks like
an abbreviation or could resemble a brand (e.g. a domain on Apple's nameservers
is Apple's own infrastructure). Only call something phishing when the
registration clearly does NOT belong to the brand being imitated.

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
	Usage *Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Usage is the token accounting an OpenAI-compatible endpoint reports (0 when the
// server doesn't return it).
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Hints carries deterministic signals (looked up before the model runs) so the
// model can incorporate them into its verdict and reasoning.
type Hints struct {
	Trusted    bool   // on a known-legitimate / popular-domains list
	Threat     bool   // on a known-malicious threat-intel feed
	Whois      string // one-line registration summary (e.g. "registered 5 days ago …")
	Reputation string // reputation-service summary (VirusTotal / AbuseIPDB)
}

// buildUserPrompt renders the per-domain user message, folding in any hints.
func buildUserPrompt(domain string, h Hints) string {
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
	if h.Reputation != "" {
		user += "\nReputation services: " + h.Reputation + "."
	}
	return user
}

// Classify returns the model's verdict for a domain (and the provider's token
// usage), informed by any hints. It dispatches to the configured provider.
func (c *Client) Classify(ctx context.Context, domain string, h Hints) (Verdict, Usage, error) {
	user := buildUserPrompt(domain, h)
	if c.provider == ProviderAnthropic {
		return c.classifyAnthropic(ctx, user)
	}
	return c.classifyOpenAI(ctx, user)
}

// classifyOpenAI calls an OpenAI-compatible /chat/completions endpoint.
func (c *Client) classifyOpenAI(ctx context.Context, user string) (Verdict, Usage, error) {
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
		return Verdict{}, Usage{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Verdict{}, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Verdict{}, Usage{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, Usage{}, fmt.Errorf("classifier: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var cr chatResp
	if err := json.Unmarshal(raw, &cr); err != nil {
		return Verdict{}, Usage{}, fmt.Errorf("classifier: bad response: %w", err)
	}
	if cr.Error != nil {
		return Verdict{}, Usage{}, fmt.Errorf("classifier: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return Verdict{}, Usage{}, fmt.Errorf("classifier: empty response")
	}
	var usage Usage
	if cr.Usage != nil {
		usage = *cr.Usage
	}
	v, err := parseVerdict(cr.Choices[0].Message.Content)
	return v, usage, err
}

// Anthropic Messages API request/response (https://api.anthropic.com/v1/messages).
type anthropicReq struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// classifyAnthropic calls the Anthropic Messages API. The system prompt already
// forces a JSON-only reply, so no thinking/sampling params are needed; max_tokens
// is small because the verdict is a one-line object.
func (c *Client) classifyAnthropic(ctx context.Context, user string) (Verdict, Usage, error) {
	body, err := json.Marshal(anthropicReq{
		Model:     c.model,
		MaxTokens: 1024,
		System:    systemPrompt,
		Messages:  []anthropicMessage{{Role: "user", Content: user}},
	})
	if err != nil {
		return Verdict{}, Usage{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return Verdict{}, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	if c.apiKey != "" {
		req.Header.Set("X-Api-Key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Verdict{}, Usage{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var ar anthropicResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return Verdict{}, Usage{}, fmt.Errorf("classifier: bad response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		if ar.Error != nil {
			msg = ar.Error.Message
		}
		return Verdict{}, Usage{}, fmt.Errorf("classifier: status %d: %s", resp.StatusCode, msg)
	}
	if ar.StopReason == "refusal" {
		return Verdict{}, Usage{}, fmt.Errorf("classifier: model declined to classify the domain")
	}
	var text strings.Builder
	for _, b := range ar.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	var usage Usage
	if ar.Usage != nil {
		usage = Usage{
			PromptTokens:     ar.Usage.InputTokens,
			CompletionTokens: ar.Usage.OutputTokens,
			TotalTokens:      ar.Usage.InputTokens + ar.Usage.OutputTokens,
		}
	}
	v, err := parseVerdict(text.String())
	return v, usage, err
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
