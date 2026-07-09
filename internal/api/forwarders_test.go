package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestForwardersAPI(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}

	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.addForwarder(rr, httptest.NewRequest(http.MethodPost, "/api/forwarders", strings.NewReader(body)))
		return rr
	}

	// Valid add.
	if rr := post(`{"suffix":"corp.internal","upstreams":["10.0.0.2:53"],"scope_type":"sites","scope_values":["office"]}`); rr.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rr.Code, rr.Body.String())
	}
	// Missing upstreams -> 400.
	if rr := post(`{"suffix":"x.internal","upstreams":[]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("no upstreams: got %d, want 400", rr.Code)
	}
	// Unparseable upstream -> 400.
	if rr := post(`{"suffix":"x.internal","upstreams":["not a real upstream::"]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad upstream: got %d, want 400 (%s)", rr.Code, rr.Body.String())
	}
	// Documented upstream formats (plain, udp://, tcp://, tls://#name, https://) must
	// all be accepted, not just the plain host:port form.
	if rr := post(`{"suffix":"udp.internal","upstreams":["udp://1.1.1.1:53"]}`); rr.Code != http.StatusCreated {
		t.Fatalf("udp:// upstream: got %d, want 201 (%s)", rr.Code, rr.Body.String())
	}
	if rr := post(`{"suffix":"tcp.internal","upstreams":["tcp://1.1.1.1:53"]}`); rr.Code != http.StatusCreated {
		t.Fatalf("tcp:// upstream: got %d, want 201 (%s)", rr.Code, rr.Body.String())
	}
	if rr := post(`{"suffix":"tls.internal","upstreams":["tls://9.9.9.9:853#dns.quad9.net"]}`); rr.Code != http.StatusCreated {
		t.Fatalf("tls:// upstream: got %d, want 201 (%s)", rr.Code, rr.Body.String())
	}
	if rr := post(`{"suffix":"https.internal","upstreams":["https://dns.quad9.net/dns-query"]}`); rr.Code != http.StatusCreated {
		t.Fatalf("https:// upstream: got %d, want 201 (%s)", rr.Code, rr.Body.String())
	}
	// Wildcards make no sense in a suffix -> 400.
	if rr := post(`{"suffix":"*.corp.internal","upstreams":["10.0.0.2:53"]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("wildcard suffix: got %d, want 400", rr.Code)
	}
	// Overlapping sites for the same suffix -> 409.
	if rr := post(`{"suffix":"corp.internal","upstreams":["10.1.1.1:53"],"scope_type":"sites","scope_values":["office","lab"]}`); rr.Code != http.StatusConflict {
		t.Fatalf("overlap: got %d, want 409 (%s)", rr.Code, rr.Body.String())
	}

	// List returns the row with its scope.
	rr := httptest.NewRecorder()
	s.listForwarders(rr, httptest.NewRequest(http.MethodGet, "/api/forwarders", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"corp.internal"`) {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}

	// Update + delete round-trip.
	fws, _ := st.ListForwarders()
	id := fws[0].ID
	prr := httptest.NewRecorder()
	preq := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/forwarders/%d", id),
		strings.NewReader(`{"upstreams":["10.0.0.3:53"],"enabled":false,"scope_type":"sites","scope_values":["office"]}`))
	preq.SetPathValue("id", fmt.Sprint(id))
	s.updateForwarder(prr, preq)
	if prr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", prr.Code, prr.Body.String())
	}
	fws, _ = st.ListForwarders()
	if fws[0].Enabled || fws[0].Upstreams[0] != "10.0.0.3:53" {
		t.Fatalf("update not applied: %+v", fws[0])
	}
	// PUT against a non-existent id -> 404.
	nrr := httptest.NewRecorder()
	nreq := httptest.NewRequest(http.MethodPut, "/api/forwarders/9999",
		strings.NewReader(`{"upstreams":["10.0.0.3:53"],"enabled":false,"scope_type":"sites","scope_values":["office"]}`))
	nreq.SetPathValue("id", "9999")
	s.updateForwarder(nrr, nreq)
	if nrr.Code != http.StatusNotFound {
		t.Fatalf("update nonexistent: got %d, want 404 (%s)", nrr.Code, nrr.Body.String())
	}

	drr := httptest.NewRecorder()
	dreq := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/forwarders/%d", id), nil)
	dreq.SetPathValue("id", fmt.Sprint(id))
	s.deleteForwarder(drr, dreq)
	if drr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", drr.Code)
	}
	if fws, _ := st.ListForwarders(); slices.ContainsFunc(fws, func(f store.Forwarder) bool { return f.ID == id }) {
		t.Fatalf("row not deleted: %+v", fws)
	}
}
