package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// push gathers the registry and POSTs Prometheus text to VM's import endpoint,
// applying job/instance as extra_label and optional basic auth.
func TestVMPusherPush(t *testing.T) {
	m := New()
	m.Queries.WithLabelValues("forward").Inc() // ensure there's a metric to ship

	type capture struct {
		method, path, query, body, user, pass string
		hadAuth                               bool
	}
	got := make(chan capture, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u, p, ok := r.BasicAuth()
		got <- capture{r.Method, r.URL.Path, r.URL.RawQuery, string(b), u, p, ok}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := NewVMPusher(nil, "fallback-host", m.Gatherer())
	cfg := VMConfig{
		Enabled: true, URL: srv.URL, Job: "mazedns", Instance: "node-a",
		Username: "user", Password: "secret",
	}
	if err := p.push(context.Background(), cfg); err != nil {
		t.Fatalf("push: %v", err)
	}

	c := <-got
	if c.method != http.MethodPost {
		t.Errorf("method=%s, want POST", c.method)
	}
	if c.path != "/api/v1/import/prometheus" {
		t.Errorf("path=%s, want /api/v1/import/prometheus", c.path)
	}
	if !strings.Contains(c.query, "extra_label=job%3Dmazedns") {
		t.Errorf("missing job extra_label: %s", c.query)
	}
	if !strings.Contains(c.query, "extra_label=instance%3Dnode-a") {
		t.Errorf("missing instance extra_label: %s", c.query)
	}
	if !strings.Contains(c.body, "mazedns_queries_total") {
		t.Errorf("body missing the metric:\n%s", c.body)
	}
	if !c.hadAuth || c.user != "user" || c.pass != "secret" {
		t.Errorf("basic auth not applied: ok=%v user=%q", c.hadAuth, c.user)
	}
}

// When the config leaves instance blank, the pusher's fallback (hostname) is used.
func TestVMPusherFallbackInstance(t *testing.T) {
	p := NewVMPusher(nil, "fallback-host", New().Gatherer())
	u := p.importURL(VMConfig{URL: "http://vm:8428"})
	if !strings.Contains(u, "extra_label=instance%3Dfallback-host") {
		t.Errorf("fallback instance not applied: %s", u)
	}
	if !strings.Contains(u, "extra_label=job%3Dmazedns") {
		t.Errorf("default job not applied: %s", u)
	}
}

// A non-2xx response surfaces an error (so it's logged, not silently dropped).
func TestVMPusherErrorStatus(t *testing.T) {
	m := New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer srv.Close()

	p := NewVMPusher(nil, "", m.Gatherer())
	if err := p.push(context.Background(), VMConfig{URL: srv.URL}); err == nil {
		t.Fatal("expected an error on a 400 response")
	}
}
