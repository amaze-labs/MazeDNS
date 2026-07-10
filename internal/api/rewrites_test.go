package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func newRewriteServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{store: st}, st
}

func TestAddRewriteScoped(t *testing.T) {
	s, st := newRewriteServer(t)
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.addRewrite(rr, httptest.NewRequest(http.MethodPost, "/api/rewrites", strings.NewReader(body)))
		return rr
	}

	// Default scope is 'all' (legacy body unchanged).
	if rr := post(`{"domain":"nas.lan","rrtype":"A","value":"10.0.0.5"}`); rr.Code != http.StatusCreated {
		t.Fatalf("legacy add: %d %s", rr.Code, rr.Body.String())
	}
	// Site-scoped split-horizon value for the same domain.
	if rr := post(`{"domain":"nas.lan","rrtype":"A","value":"192.168.1.5","scope_type":"sites","scope_values":["office"]}`); rr.Code != http.StatusCreated {
		t.Fatalf("scoped add: %d %s", rr.Code, rr.Body.String())
	}
	// Overlapping site list at the same specificity -> 409.
	if rr := post(`{"domain":"nas.lan","rrtype":"A","value":"172.16.0.5","scope_type":"sites","scope_values":["office","lab"]}`); rr.Code != http.StatusConflict {
		t.Fatalf("overlap: got %d, want 409 (%s)", rr.Code, rr.Body.String())
	}
	// Bad scope type -> 400.
	if rr := post(`{"domain":"x.lan","rrtype":"A","value":"1.2.3.4","scope_type":"bogus"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad scope: got %d, want 400", rr.Code)
	}
	if rws, _ := st.ListRewrites(); len(rws) != 2 {
		t.Fatalf("want 2 rewrites, got %+v", rws)
	}
}

func TestUpdateRewrite(t *testing.T) {
	s, st := newRewriteServer(t)
	id, err := st.AddRewriteScoped("nas.lan", "A", "10.0.0.5", store.ScopeAll, nil)
	if err != nil {
		t.Fatal(err)
	}
	put := func(id int64, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/rewrites/%d", id), strings.NewReader(body))
		req.SetPathValue("id", fmt.Sprint(id))
		s.updateRewrite(rr, req)
		return rr
	}
	if rr := put(id, `{"value":"10.0.0.6","enabled":false,"scope_type":"nodes","scope_values":["n1"]}`); rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	rws, _ := st.ListRewrites()
	if len(rws) != 1 || rws[0].Value != "10.0.0.6" || rws[0].Enabled || rws[0].ScopeType != store.ScopeNodes {
		t.Fatalf("update not applied: %+v", rws)
	}
	if rr := put(9999, `{"value":"1.1.1.1","enabled":true}`); rr.Code != http.StatusNotFound {
		t.Fatalf("missing id: got %d, want 404", rr.Code)
	}
}

// Re-scoping a row onto another row's exact (domain+rrtype+scope) must 409,
// not fall through the overlap check (which skips identical value lists) and
// hit the UNIQUE constraint as a raw 500.
func TestUpdateRewriteExactScopeConflict(t *testing.T) {
	s, st := newRewriteServer(t)
	idA, err := st.AddRewriteScoped("nas.lan", "A", "10.0.0.1", store.ScopeSites, []string{"office"})
	if err != nil {
		t.Fatal(err)
	}
	idB, err := st.AddRewriteScoped("nas.lan", "A", "10.0.0.2", store.ScopeSites, []string{"lab"})
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/rewrites/%d", idB),
		strings.NewReader(`{"value":"10.0.0.2","enabled":true,"scope_type":"sites","scope_values":["office"]}`))
	req.SetPathValue("id", fmt.Sprint(idB))
	s.updateRewrite(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("re-scope onto identical scope: got %d, want 409 (%s)", rr.Code, rr.Body.String())
	}

	// Both rows must be unchanged.
	rws, _ := st.ListRewrites()
	if len(rws) != 2 {
		t.Fatalf("want 2 rows, got %+v", rws)
	}
	for _, rw := range rws {
		switch rw.ID {
		case idA:
			if rw.Value != "10.0.0.1" || rw.ScopeType != store.ScopeSites || len(rw.ScopeValues) != 1 || rw.ScopeValues[0] != "office" {
				t.Fatalf("row A mutated: %+v", rw)
			}
		case idB:
			if rw.Value != "10.0.0.2" || rw.ScopeType != store.ScopeSites || len(rw.ScopeValues) != 1 || rw.ScopeValues[0] != "lab" {
				t.Fatalf("row B mutated: %+v", rw)
			}
		default:
			t.Fatalf("unexpected row: %+v", rw)
		}
	}
}
