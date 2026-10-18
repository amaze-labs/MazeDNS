package api

import (
	"net/http"

	"github.com/IPMaze/MazeDNS/internal/updates"
)

// SetUpdates wires the release checker (control plane only).
func (s *Server) SetUpdates(u *updates.Checker) { s.updates = u }

// updateStatus reports the running version against the published releases,
// with the notes of every release newer than it. ?refresh=1 checks again now
// (the checker rate-limits that).
func (s *Server) updateStatus(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		writeError(w, http.StatusNotFound, "update checks are not available here")
		return
	}
	writeJSON(w, http.StatusOK, s.updates.Status(r.Context(), r.URL.Query().Get("refresh") == "1"))
}
