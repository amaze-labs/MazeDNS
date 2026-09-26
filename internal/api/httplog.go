package api

import (
	"log/slog"
	"net/http"
	"strings"
)

// maxLoggedErrorLen caps the error message copied into a log line so a
// pathological message can't flood the logs.
const maxLoggedErrorLen = 512

// statusRecorder wraps a ResponseWriter to remember the response status and
// the message passed to writeError. It never looks at request or response
// bodies.
type statusRecorder struct {
	http.ResponseWriter
	status int
	errMsg string
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 && code >= 200 { // ignore 1xx informational headers
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// noteError records msg on the statusRecorder wrapping w (if any), so
// logRequests can include the error returned to the client in its log line.
func noteError(w http.ResponseWriter, msg string) {
	for w != nil {
		if rec, ok := w.(*statusRecorder); ok {
			if rec.errMsg == "" {
				rec.errMsg = msg
			}
			return
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

// logRequests logs successful requests at debug and every response with
// status >= 400 at warn — exactly one line per failed request with the method,
// path (no query string), status, remote address and the error message the
// handler returned. Request bodies and headers (Authorization, cookies, keys)
// are never logged.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK // handler wrote nothing: net/http sends 200
		}
		if status < 400 {
			slog.Debug("http", "method", r.Method, "path", r.URL.Path, "status", status)
			return
		}
		attrs := []any{"method", r.Method, "path", r.URL.Path, "status", status, "remote", clientIP(r)}
		if msg := rec.errMsg; msg != "" {
			if len(msg) > maxLoggedErrorLen {
				msg = strings.ToValidUTF8(msg[:maxLoggedErrorLen], "") + "…"
			}
			attrs = append(attrs, "error", msg)
		}
		slog.Warn("http request failed", attrs...)
	})
}
