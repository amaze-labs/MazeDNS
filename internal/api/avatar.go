package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // DecodeConfig for uploaded pictures
	_ "image/png"
	"net/http"
	"strconv"
	"strings"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// Profile pictures. A user may upload one (the browser resizes it to a small
// square first); it is stored apart from the IdP's picture, and wins over it
// for local accounts always and for SSO accounts when the administrator
// allows it (Settings → Access & sign-in). Otherwise: the IdP's picture, then
// the initial.

// maxAvatarB64 caps an uploaded picture's base64 (≈75 KB of image; a 128 px
// JPEG is 5–10 KB).
const maxAvatarB64 = 100_000

// maxAvatarSide bounds the decoded image's dimensions.
const maxAvatarSide = 1024

var errAvatar = errors.New("the picture must be a JPEG, PNG or WebP image under 75 KB")

// normalizeAvatar validates an uploaded picture — raw base64 or a data URL —
// and returns canonical base64 of its bytes. Only JPEG, PNG and WebP pass,
// recognised by their bytes (never the claimed type): the value is served
// back as an image, so SVG or HTML must never get through.
func normalizeAvatar(in string) (string, error) {
	in = strings.TrimSpace(in)
	if i := strings.Index(in, ","); strings.HasPrefix(in, "data:") && i > 0 {
		in = in[i+1:]
	}
	if in == "" || len(in) > maxAvatarB64 {
		return "", errAvatar
	}
	raw, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return "", errAvatar
	}
	switch avatarType(raw) {
	case "image/jpeg", "image/png":
		cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
		if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxAvatarSide || cfg.Height > maxAvatarSide {
			return "", errAvatar
		}
	case "image/webp":
		// No WebP decoder in the standard library: the RIFF/WEBP signature and
		// the size cap are the checks, and it is served with nosniff.
	default:
		return "", errAvatar
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// avatarType names the image format from its leading bytes ("" if none).
func avatarType(b []byte) string {
	switch {
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return "image/jpeg"
	case len(b) >= 8 && bytes.Equal(b[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}):
		return "image/png"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "image/webp"
	}
	return ""
}

// avatarVersion fingerprints a stored picture (cache-busting URL, ETag).
func avatarVersion(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:6])
}

// ssoAvatarUpload reports whether SSO accounts may use an uploaded picture.
func (s *Server) ssoAvatarUpload() bool {
	return s.store.LoadCPSettings(cpSettingsDefaults()).OIDC.AllowAvatarUpload
}

// canUploadAvatar reports whether u may set (and show) an uploaded picture.
func canUploadAvatar(u *store.User, ssoAllowed bool) bool {
	return u.Source != "oidc" || ssoAllowed
}

// effectiveAvatar is the picture URL to show for u: its upload (when it may
// use one), else the IdP's, else "" (the UI shows the initial).
func effectiveAvatar(u *store.User, ssoAllowed bool) string {
	if u.AvatarData != "" && canUploadAvatar(u, ssoAllowed) {
		return fmt.Sprintf("/api/users/%d/avatar?v=%s", u.ID, avatarVersion(u.AvatarData))
	}
	return u.AvatarURL
}

// putAvatar sets the signed-in user's own picture. Session only: API tokens
// never touch accounts.
func (s *Server) putAvatar(w http.ResponseWriter, r *http.Request) {
	u := s.avatarSelf(w, r)
	if u == nil {
		return
	}
	if !canUploadAvatar(u, s.ssoAvatarUpload()) {
		writeError(w, http.StatusForbidden, "your identity provider manages your picture")
		return
	}
	var in struct {
		Image string `json:"image"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAvatarB64+1024)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, errAvatar.Error())
		return
	}
	data, err := normalizeAvatar(in.Image)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SetUserAvatar(u.ID, data); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u.AvatarData = data
	writeJSON(w, http.StatusOK, map[string]string{"avatar_url": effectiveAvatar(u, true)})
}

// deleteAvatar removes the signed-in user's uploaded picture.
func (s *Server) deleteAvatar(w http.ResponseWriter, r *http.Request) {
	u := s.avatarSelf(w, r)
	if u == nil {
		return
	}
	if err := s.store.SetUserAvatar(u.ID, ""); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u.AvatarData = ""
	writeJSON(w, http.StatusOK, map[string]string{"avatar_url": effectiveAvatar(u, s.ssoAvatarUpload())})
}

// avatarSelf is the signed-in account (writing the error itself when there
// is none: accounts off, or not signed in).
func (s *Server) avatarSelf(w http.ResponseWriter, r *http.Request) *store.User {
	p, ok := s.principal(r)
	if !ok {
		writeError(w, http.StatusNotFound, "accounts are turned off")
		return nil
	}
	u, err := s.store.GetUserByID(p.ID)
	if err != nil || u == nil {
		writeError(w, http.StatusNotFound, "account not found")
		return nil
	}
	return u
}

// userAvatar serves a user's uploaded picture to signed-in users, as an
// image that can never be interpreted as anything else.
func (s *Server) userAvatar(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	u, err := s.store.GetUserByID(id)
	if err != nil || u == nil || u.AvatarData == "" || !canUploadAvatar(u, s.ssoAvatarUpload()) {
		writeError(w, http.StatusNotFound, "no picture")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(u.AvatarData)
	ctype := avatarType(raw)
	if err != nil || ctype == "" {
		writeError(w, http.StatusNotFound, "no picture")
		return
	}
	etag := `"` + avatarVersion(u.AvatarData) + `"`
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "private, max-age=86400")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", ctype)
	_, _ = w.Write(raw)
}
