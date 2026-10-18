package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestRewriteOwnership walks the #38 contract through the real routes: an
// integration (admin token) syncing its rows next to an operator (console).
func TestRewriteOwnership(t *testing.T) {
	e := newTokenEnv(t)
	_, sync := e.mint("ipmaze-sync", roleAdmin, 0)
	console := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		rr := e.do(method, path, body, true, "")
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	integration := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		rr := e.do(method, path, body, false, bearer(sync))
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	want := func(code, wantCode int, out map[string]any, what string) {
		t.Helper()
		if code != wantCode {
			t.Fatalf("%s: %d %v, want %d", what, code, out, wantCode)
		}
	}
	idOf := func(out map[string]any) int64 { return int64(out["id"].(float64)) }

	code, out := console(http.MethodPost, "/api/rewrites", `{"domain":"nas.example.lan","rrtype":"A","value":"192.0.2.10"}`)
	want(code, http.StatusCreated, out, "manual add")
	manualID := idOf(out)

	// A sync never takes over a manual row; the 409 names the owner and row.
	code, out = integration(http.MethodPost, "/api/rewrites",
		`{"domain":"nas.example.lan","rrtype":"A","value":"192.0.2.99","source":"ipmaze","external_id":"host:0"}`)
	want(code, http.StatusConflict, out, "sync over manual")
	if out["error"] != "a manual rewrite already serves nas.example.lan A" || out["source"] != "" || idOf(out) != manualID {
		t.Fatalf("sync over manual: %v", out)
	}

	code, out = integration(http.MethodPost, "/api/rewrites",
		`{"domain":"srv-01.example.lan","rrtype":"A","value":"192.0.2.20","source":"ipmaze","external_id":"host:1"}`)
	want(code, http.StatusCreated, out, "sync add")
	ownedID := idOf(out)
	if out["source"] != "ipmaze" || out["external_id"] != "host:1" {
		t.Fatalf("sync add response: %v", out)
	}

	// A manual POST never takes over an owned row, nor does another source.
	code, out = console(http.MethodPost, "/api/rewrites", `{"domain":"srv-01.example.lan","rrtype":"A","value":"192.0.2.99"}`)
	want(code, http.StatusConflict, out, "manual over owned")
	if out["error"] != "a rewrite managed by ipmaze already serves srv-01.example.lan A" || out["source"] != "ipmaze" {
		t.Fatalf("manual over owned: %v", out)
	}
	code, out = integration(http.MethodPost, "/api/rewrites",
		`{"domain":"srv-01.example.lan","rrtype":"A","value":"192.0.2.99","source":"other"}`)
	want(code, http.StatusConflict, out, "other source over owned")

	// The same external id can't name a second record of the same type.
	code, out = integration(http.MethodPost, "/api/rewrites",
		`{"domain":"srv-02.example.lan","rrtype":"A","value":"192.0.2.21","source":"ipmaze","external_id":"host:1"}`)
	want(code, http.StatusConflict, out, "external id reused")
	code, out = integration(http.MethodPost, "/api/rewrites",
		`{"domain":"srv-01.example.lan","rrtype":"AAAA","value":"2001:db8::20","source":"ipmaze","external_id":"host:1"}`)
	want(code, http.StatusCreated, out, "sync add AAAA")
	aaaaID := idOf(out)

	// Bad ownership fields.
	code, out = integration(http.MethodPost, "/api/rewrites", `{"domain":"x.example.lan","rrtype":"A","value":"192.0.2.1","source":"IPMaze"}`)
	want(code, http.StatusBadRequest, out, "bad source slug")
	code, out = integration(http.MethodPost, "/api/rewrites", `{"domain":"x.example.lan","rrtype":"A","value":"192.0.2.1","external_id":"x"}`)
	want(code, http.StatusBadRequest, out, "external id without source")

	// ?source= filters; every row carries both fields, empty or not.
	list := func(query string) []map[string]any {
		t.Helper()
		rr := e.do(http.MethodGet, "/api/rewrites"+query, "", false, bearer(sync))
		var rows []map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil || rr.Code != http.StatusOK {
			t.Fatalf("list %q: %d %s", query, rr.Code, rr.Body.String())
		}
		return rows
	}
	if rows := list(""); len(rows) != 3 {
		t.Fatalf("all rows: %v", rows)
	}
	if rows := list("?source=ipmaze"); len(rows) != 2 || rows[0]["source"] != "ipmaze" || rows[1]["source"] != "ipmaze" {
		t.Fatalf("ipmaze rows: %v", rows)
	}
	manualRows := list("?source=")
	if len(manualRows) != 1 || manualRows[0]["domain"] != "nas.example.lan" {
		t.Fatalf("manual rows: %v", manualRows)
	}
	if src, ok := manualRows[0]["source"]; !ok || src != "" {
		t.Fatalf("manual row lacks source: %v", manualRows[0])
	}
	if ext, ok := manualRows[0]["external_id"]; !ok || ext != "" {
		t.Fatalf("manual row lacks external_id: %v", manualRows[0])
	}

	// PUT on an owned row: only its owner edits value and scope...
	owned := fmt.Sprintf("/api/rewrites/%d", ownedID)
	code, out = console(http.MethodPut, owned, `{"value":"192.0.2.30","enabled":true}`)
	want(code, http.StatusConflict, out, "manual edit of owned")
	if !strings.Contains(out["error"].(string), "managed by ipmaze") {
		t.Fatalf("manual edit of owned: %v", out)
	}
	code, out = integration(http.MethodPut, owned, `{"value":"192.0.2.30","enabled":true,"source":"other"}`)
	want(code, http.StatusConflict, out, "other source edit of owned")
	code, out = integration(http.MethodPut, owned, `{"value":"192.0.2.30","enabled":true,"source":"ipmaze"}`)
	want(code, http.StatusOK, out, "owner edit")

	// ...but the enabled toggle is the operator's, and a later sync keeps it.
	code, out = console(http.MethodPut, owned, `{"value":"192.0.2.30","enabled":false,"scope_type":"all"}`)
	want(code, http.StatusOK, out, "operator toggle")
	code, out = integration(http.MethodPost, "/api/rewrites",
		`{"domain":"srv-01.example.lan","rrtype":"A","value":"192.0.2.31","source":"ipmaze","external_id":"host:1"}`)
	want(code, http.StatusCreated, out, "sync upsert")
	if rw, _, _ := e.st.GetRewrite(ownedID); rw.Value != "192.0.2.31" || rw.Enabled {
		t.Fatalf("after sync upsert: %+v, want new value, still off", rw)
	}

	// A sync can't edit a manual row either.
	manual := fmt.Sprintf("/api/rewrites/%d", manualID)
	code, out = integration(http.MethodPut, manual, `{"value":"192.0.2.11","enabled":true,"source":"ipmaze"}`)
	want(code, http.StatusConflict, out, "sync edit of manual")
	if out["error"] != "nas.example.lan A is a manual rewrite, not managed by ipmaze" {
		t.Fatalf("sync edit of manual: %v", out)
	}

	// DELETE names the owner the same way.
	code, out = console(http.MethodDelete, owned, "")
	want(code, http.StatusConflict, out, "manual delete of owned")
	code, out = integration(http.MethodDelete, owned+"?source=other", "")
	want(code, http.StatusConflict, out, "other source delete of owned")
	code, out = integration(http.MethodDelete, manual+"?source=ipmaze", "")
	want(code, http.StatusConflict, out, "sync delete of manual")

	// Detach hands a row to the operator; the sync then meets a conflict.
	aaaa := fmt.Sprintf("/api/rewrites/%d", aaaaID)
	code, out = console(http.MethodPost, aaaa+"/detach", "")
	want(code, http.StatusOK, out, "detach")
	if out["source"] != "" || out["external_id"] != "" || out["domain"] != "srv-01.example.lan" {
		t.Fatalf("detach response: %v", out)
	}
	code, out = integration(http.MethodPost, "/api/rewrites",
		`{"domain":"srv-01.example.lan","rrtype":"AAAA","value":"2001:db8::21","source":"ipmaze","external_id":"host:1"}`)
	want(code, http.StatusConflict, out, "sync over detached")
	code, out = integration(http.MethodDelete, aaaa+"?source=ipmaze", "")
	want(code, http.StatusConflict, out, "sync delete of detached")
	code, out = console(http.MethodDelete, aaaa, "")
	want(code, http.StatusNoContent, out, "manual delete of detached")
	code, out = integration(http.MethodPost, "/api/rewrites/99999/detach", "")
	want(code, http.StatusNotFound, out, "detach missing")

	code, out = integration(http.MethodDelete, owned+"?source=ipmaze", "")
	want(code, http.StatusNoContent, out, "owner delete")
	if rows := list(""); len(rows) != 1 {
		t.Fatalf("left: %v", rows)
	}
}
