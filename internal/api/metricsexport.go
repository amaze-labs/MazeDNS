package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// getMetricsExport returns the VictoriaMetrics export settings (password masked).
func (s *Server) getMetricsExport(w http.ResponseWriter, _ *http.Request) {
	v := s.store.LoadVMExport(store.VMExport{})
	hasPassword := v.Password != ""
	v.Password = "" // never leak the password to the UI
	writeJSON(w, http.StatusOK, map[string]any{"settings": v, "has_password": hasPassword})
}

// putMetricsExport saves the VictoriaMetrics export settings. An empty password
// means "leave unchanged" so the masked field round-trips. The running pusher
// picks the new settings up on its next cycle.
func (s *Server) putMetricsExport(w http.ResponseWriter, r *http.Request) {
	var in store.VMExport
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.URL = strings.TrimSpace(in.URL)
	in.Job = strings.TrimSpace(in.Job)
	in.Instance = strings.TrimSpace(in.Instance)
	if in.IntervalSec <= 0 {
		in.IntervalSec = 15
	}
	if in.Password == "" {
		in.Password = s.store.LoadVMExport(store.VMExport{}).Password
	}
	if err := s.store.SaveVMExport(in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	in.Password = ""
	writeJSON(w, http.StatusOK, in)
}
