package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// maxAPITokenName bounds a token's name (it is shown in lists and the audit log).
const maxAPITokenName = 64

func (s *Server) listAPITokens(w http.ResponseWriter, _ *http.Request) {
	toks, err := s.store.ListAPITokens()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toks)
}

// createAPIToken mints a token and returns its value — the only time it is ever
// shown; only its hash is stored.
func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string `json:"name"`
		Role      string `json:"role"`
		ExpiresAt int64  `json:"expires_at"` // unix secs, 0 = never
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	switch {
	case in.Name == "":
		writeError(w, http.StatusBadRequest, "name is required")
		return
	case len(in.Name) > maxAPITokenName:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("name is longer than %d characters", maxAPITokenName))
		return
	case in.Role != roleAdmin && in.Role != roleReadonly:
		writeError(w, http.StatusBadRequest, "role must be admin or readonly")
		return
	case in.ExpiresAt < 0 || (in.ExpiresAt != 0 && in.ExpiresAt <= time.Now().Unix()):
		writeError(w, http.StatusBadRequest, "expires_at must be in the future (or 0 for never)")
		return
	}
	value, err := auth.NewAPIToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	t := store.APIToken{
		ID: uuid.NewString(), Name: in.Name, TokenPrefix: auth.APITokenDisplayPrefix(value),
		Role: in.Role, CreatedBy: auditUser(s, r), CreatedAt: time.Now().Unix(), ExpiresAt: in.ExpiresAt,
	}
	if err := s.store.CreateAPIToken(t, auth.HashAPIToken(value)); err != nil {
		writeError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	_ = s.store.AppendAudit(store.AuditEntry{
		User: t.CreatedBy, Action: "apitoken.create",
		Detail: fmt.Sprintf("created %s API token %q (%s)", t.Role, t.Name, t.ID),
	})
	slog.Info("api token created", "id", t.ID, "name", t.Name, "role", t.Role, "by", t.CreatedBy, "expires_at", t.ExpiresAt)
	writeJSON(w, http.StatusCreated, struct {
		store.APIToken
		Token string `json:"token"`
	}{t, value})
}

func (s *Server) deleteAPIToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name, err := s.store.DeleteAPIToken(id)
	switch {
	case errors.Is(err, store.ErrAPITokenNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(store.AuditEntry{
		User: auditUser(s, r), Action: "apitoken.delete",
		Detail: fmt.Sprintf("revoked API token %q (%s)", name, id),
	})
	slog.Info("api token revoked", "id", id, "name", name)
	w.WriteHeader(http.StatusNoContent)
}
