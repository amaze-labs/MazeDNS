package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// captureHandler is a slog.Handler that keeps every record it receives.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// captureLogs routes the default slog logger to a captureHandler for the test.
func captureLogs(t *testing.T) *captureHandler {
	t.Helper()
	h := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return h
}

func (h *captureHandler) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = nil
}

// attrs flattens a record's attributes into a map, plus the full text of the
// record (message + every key=value) for "must not contain" checks.
func recordAttrs(r slog.Record) (map[string]slog.Value, string) {
	m := map[string]slog.Value{}
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value
		fmt.Fprintf(&b, " %s=%s", a.Key, a.Value.String())
		return true
	})
	return m, b.String()
}

func (h *captureHandler) atLevel(l slog.Level) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.records {
		if r.Level == l {
			out = append(out, r)
		}
	}
	return out
}

// unwrapWriter is an unrelated middleware wrapper exposing Unwrap, to check
// that writeError's message still reaches the recorder through it.
type unwrapWriter struct{ http.ResponseWriter }

func (w unwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestLogRequestsWarnsOnFailures(t *testing.T) {
	logs := captureLogs(t)

	const secret = "s3cr3t-node-key"
	const password = "correcthorse7"

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus int
		wantErr    string // "" = no error attribute expected
	}{
		{
			name: "writeError message is captured",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeError(w, http.StatusBadRequest, "reserved node name")
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    "reserved node name",
		},
		{
			name: "writeError through another Unwrap-able wrapper",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeError(unwrapWriter{w}, http.StatusConflict, "name already in use")
			},
			wantStatus: http.StatusConflict,
			wantErr:    "name already in use",
		},
		{
			name: "5xx",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeError(w, http.StatusInternalServerError, "db locked")
			},
			wantStatus: http.StatusInternalServerError,
			wantErr:    "db locked",
		},
		{
			name:       "plain http.Error: status only, body is not logged",
			handler:    func(w http.ResponseWriter, r *http.Request) { http.Error(w, "body "+secret, http.StatusNotFound) },
			wantStatus: http.StatusNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs.reset()
			req := httptest.NewRequest(http.MethodPut, "/api/cluster/nodes/agent-01/name?token="+secret,
				strings.NewReader(`{"name":"master","password":"`+password+`"}`))
			req.Header.Set("Authorization", "Bearer "+secret)
			req.Header.Set("Cookie", "session="+secret)
			req.RemoteAddr = "192.0.2.10:54321"
			rr := httptest.NewRecorder()
			logRequests(tc.handler).ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("response status = %d, want %d", rr.Code, tc.wantStatus)
			}
			warns := logs.atLevel(slog.LevelWarn)
			if len(warns) != 1 {
				t.Fatalf("got %d warn records, want exactly 1", len(warns))
			}
			if n := len(logs.records); n != 1 {
				t.Fatalf("got %d records in total, want exactly 1 line per failure", n)
			}
			attrs, text := recordAttrs(warns[0])
			if got := attrs["method"].String(); got != http.MethodPut {
				t.Errorf("method = %q", got)
			}
			if got := attrs["path"].String(); got != "/api/cluster/nodes/agent-01/name" {
				t.Errorf("path = %q (query string must be dropped)", got)
			}
			if got := attrs["status"].Int64(); got != int64(tc.wantStatus) {
				t.Errorf("status = %d, want %d", got, tc.wantStatus)
			}
			if got := attrs["remote"].String(); got != "192.0.2.10" {
				t.Errorf("remote = %q", got)
			}
			if v, ok := attrs["error"]; tc.wantErr == "" && ok {
				t.Errorf("unexpected error attribute %q", v.String())
			} else if tc.wantErr != "" && v.String() != tc.wantErr {
				t.Errorf("error = %q, want %q", v.String(), tc.wantErr)
			}
			for _, bad := range []string{secret, password, "Bearer", "session="} {
				if strings.Contains(text, bad) {
					t.Errorf("log line leaks %q: %s", bad, text)
				}
			}
		})
	}
}

func TestLogRequestsSuccessIsDebugOnly(t *testing.T) {
	logs := captureLogs(t)
	for _, h := range []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
		},
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) },
		func(w http.ResponseWriter, r *http.Request) {}, // writes nothing: implicit 200
	} {
		logs.reset()
		rr := httptest.NewRecorder()
		logRequests(h).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/cluster/nodes", nil))
		if len(logs.records) != 1 || logs.records[0].Level != slog.LevelDebug {
			t.Fatalf("status %d: want exactly one debug record, got %d records", rr.Code, len(logs.records))
		}
		attrs, _ := recordAttrs(logs.records[0])
		if got := attrs["status"].Int64(); got != int64(rr.Code) {
			t.Errorf("debug status = %d, want %d", got, rr.Code)
		}
	}
}

func TestLogRequestsTruncatesLongErrors(t *testing.T) {
	logs := captureLogs(t)
	long := strings.Repeat("é", maxLoggedErrorLen) // 2 bytes per rune: the cut lands mid-rune
	h := func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusBadRequest, long) }
	logRequests(http.HandlerFunc(h)).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/x", nil))
	warns := logs.atLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("got %d warn records, want 1", len(warns))
	}
	attrs, _ := recordAttrs(warns[0])
	msg := attrs["error"].String()
	if len(msg) > maxLoggedErrorLen+len("…") {
		t.Errorf("error attribute is %d bytes, want <= %d", len(msg), maxLoggedErrorLen+len("…"))
	}
	if !strings.HasSuffix(msg, "…") || strings.ContainsRune(msg, '�') {
		t.Errorf("truncated message is malformed: %q", msg[len(msg)-8:])
	}
}

// A revoked/bad agent key polling the snapshot endpoint logs one warn line per
// poll, without the key.
func TestLogRequestsBadNodeKeySnapshot(t *testing.T) {
	s, _ := newEnrollServer(t, "", false)
	logs := captureLogs(t)
	const key = "not-a-valid-node-key-0123456789"
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rr := httptest.NewRecorder()
	logRequests(http.HandlerFunc(s.clusterSnapshot)).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	warns := logs.atLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("got %d warn records, want 1", len(warns))
	}
	attrs, text := recordAttrs(warns[0])
	if attrs["status"].Int64() != http.StatusUnauthorized || attrs["error"].String() == "" {
		t.Errorf("unexpected warn line: %s", text)
	}
	if strings.Contains(text, key) {
		t.Errorf("warn line leaks the node key: %s", text)
	}
}
