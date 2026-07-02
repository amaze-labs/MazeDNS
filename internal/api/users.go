package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// listUsers returns all accounts (admin only). Password hashes are never serialized.
func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if users == nil {
		users = []store.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

// createUser provisions a local (password) account (admin only).
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	username := strings.TrimSpace(in.Username)
	if username == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}
	if msg := passwordStrengthError(in.Password); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	role := in.Role
	if role != roleAdmin && role != roleReadonly {
		role = roleReadonly
	}
	if existing, _ := s.store.GetUserByUsername(username); existing != nil {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	id, err := s.store.CreateLocalUser(username, hash, role)
	if err != nil {
		writeError(w, http.StatusConflict, "could not create user: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "username": username, "role": role, "source": "local"})
}

// setUserRole changes a user's role (admin only), protecting the last admin.
func (s *Server) setUserRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.Role != roleAdmin && in.Role != roleReadonly {
		writeError(w, http.StatusBadRequest, "role must be admin or readonly")
		return
	}
	target, err := s.store.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if target.Role == roleAdmin && in.Role != roleAdmin && s.lastAdmin() {
		writeError(w, http.StatusBadRequest, "cannot demote the last admin")
		return
	}
	if err := s.store.UpdateUserRole(id, in.Role); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.DeleteSessionsForUser(id) // force re-login so the new role applies
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "role": in.Role})
}

// resetUserPassword sets a new password for a local user (admin only).
func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if msg := passwordStrengthError(in.Password); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	target, err := s.store.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if target.Source != "local" {
		writeError(w, http.StatusBadRequest, "cannot set a password for an SSO account")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	if err := s.store.UpdateUserPassword(id, hash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.DeleteSessionsForUser(id) // force re-login with the new password
	w.WriteHeader(http.StatusNoContent)
}

// deleteUser removes an account (admin only); cannot remove yourself or the last admin.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	target, err := s.store.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if cur, ok := s.auth.UserFromRequest(r); ok && cur.ID == id {
		writeError(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	if target.Role == roleAdmin && s.lastAdmin() {
		writeError(w, http.StatusBadRequest, "cannot delete the last admin")
		return
	}
	if err := s.store.DeleteUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.DeleteSessionsForUser(id)
	w.WriteHeader(http.StatusNoContent)
}

// changePassword lets the signed-in user change their own password.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.auth.UserFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u, err := s.store.GetUserByID(cur.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if u == nil || u.Source != "local" || u.PasswordHash == "" {
		writeError(w, http.StatusBadRequest, "password change is not available for this account")
		return
	}
	if ok, _ := auth.VerifyPassword(u.PasswordHash, in.CurrentPassword); !ok {
		writeError(w, http.StatusBadRequest, "current password is incorrect")
		return
	}
	if msg := passwordStrengthError(in.NewPassword); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	hash, err := auth.HashPassword(in.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	if err := s.store.UpdateUserPassword(u.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The current session stays valid — the user just authenticated to change it.
	w.WriteHeader(http.StatusNoContent)
}

// lastAdmin reports whether at most one admin account remains.
func (s *Server) lastAdmin() bool {
	n, err := s.store.CountAdmins()
	return err == nil && n <= 1
}
