package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The cache should serve identical URIs from memory within the TTL (so heavy
// query_log aggregations aren't recomputed on every dashboard poll), recompute
// for a different URI, and not cache non-200 responses.
func TestCachedHandler(t *testing.T) {
	s := &Server{statsCache: newTTLCache(time.Minute)}
	var calls int
	h := s.cached(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"n":%d}`, calls)
	})

	do := func(uri string) (string, string) {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodGet, uri, nil))
		return rr.Body.String(), rr.Header().Get("X-Cache")
	}

	if body, hit := do("/api/stats/insights?hours=24"); body != `{"n":1}` || hit != "" {
		t.Fatalf("first call: body=%s hit=%q", body, hit)
	}
	if body, hit := do("/api/stats/insights?hours=24"); body != `{"n":1}` || hit != "hit" {
		t.Fatalf("cached call: body=%s hit=%q (want n:1, hit)", body, hit)
	}
	if calls != 1 {
		t.Fatalf("handler ran %d times, want 1 (second served from cache)", calls)
	}
	// Different window = different key = recompute.
	if body, _ := do("/api/stats/insights?hours=1"); body != `{"n":2}` {
		t.Fatalf("different URI should recompute: body=%s", body)
	}
}

func TestCachedSkipsErrors(t *testing.T) {
	s := &Server{statsCache: newTTLCache(time.Minute)}
	var calls int
	h := s.cached(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"boom"}`)
	})
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodGet, "/api/stats/insights", nil))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rr.Code)
		}
	}
	if calls != 2 {
		t.Fatalf("error responses must not be cached; handler ran %d times, want 2", calls)
	}
}
