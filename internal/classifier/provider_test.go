package classifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeProviderAndBaseURL(t *testing.T) {
	if normalizeProvider("Anthropic") != ProviderAnthropic {
		t.Error("Anthropic should normalize to anthropic")
	}
	if normalizeProvider("") != ProviderOpenAI || normalizeProvider("ollama") != ProviderOpenAI {
		t.Error("blank/unknown should default to openai")
	}
	// Anthropic with no endpoint gets the public default base.
	c := NewClient(ProviderAnthropic, "", "claude-haiku-4-5", "k", time.Second)
	if c.baseURL != "https://api.anthropic.com" {
		t.Errorf("anthropic base = %q, want public default", c.baseURL)
	}
}

// TestClassifyAnthropic verifies the Anthropic Messages API request shape and
// that the JSON verdict + token usage are parsed out of the response.
func TestClassifyAnthropic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %q, want /v1/messages", r.URL.Path)
		}
		if r.Header.Get("X-Api-Key") != "secret" {
			t.Errorf("missing x-api-key header")
		}
		if r.Header.Get("Anthropic-Version") == "" {
			t.Error("missing anthropic-version header")
		}
		var req anthropicReq
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("bad request body: %v", err)
		}
		if req.System == "" || len(req.Messages) != 1 || req.Messages[0].Role != "user" {
			t.Errorf("unexpected request: %+v", req)
		}
		if !strings.Contains(req.Messages[0].Content, "evil.example") {
			t.Errorf("user message missing domain: %q", req.Messages[0].Content)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"content":[{"type":"text","text":"{\"category\":\"malware\",\"confidence\":0.9,\"reason\":\"c2\"}"}],
			"stop_reason":"end_turn",
			"usage":{"input_tokens":120,"output_tokens":18}
		}`)
	}))
	defer srv.Close()

	c := NewClient(ProviderAnthropic, srv.URL, "claude-haiku-4-5", "secret", 5*time.Second)
	v, usage, err := c.Classify(context.Background(), "evil.example", Hints{Threat: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.Category != "malware" || !v.ShouldBlock() {
		t.Errorf("verdict = %+v, want malware/block", v)
	}
	if usage.PromptTokens != 120 || usage.CompletionTokens != 18 || usage.TotalTokens != 138 {
		t.Errorf("usage = %+v, want 120/18/138", usage)
	}
}

func TestClassifyAnthropicRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"content":[],"stop_reason":"refusal"}`)
	}))
	defer srv.Close()
	c := NewClient(ProviderAnthropic, srv.URL, "claude-haiku-4-5", "secret", 5*time.Second)
	if _, _, err := c.Classify(context.Background(), "evil.example", Hints{}); err == nil {
		t.Error("expected an error on a refusal stop_reason")
	}
}
