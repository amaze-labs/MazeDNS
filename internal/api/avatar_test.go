package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/jpeg"
	"image/png"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
)

func tinyJPEG(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, image.NewRGBA(image.Rect(0, 0, 8, 8)), nil); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func TestNormalizeAvatar(t *testing.T) {
	jp := tinyJPEG(t)
	if got, err := normalizeAvatar("data:image/jpeg;base64," + jp); err != nil || got != jp {
		t.Errorf("data URL JPEG: %v", err)
	}
	var big bytes.Buffer
	_ = png.Encode(&big, image.NewRGBA(image.Rect(0, 0, 2000, 10)))
	for name, in := range map[string]string{
		"svg":          base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`)),
		"html as jpeg": "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString([]byte("<html>")),
		"too long":     strings.Repeat("A", maxAvatarB64+4),
		"not base64":   "%%%",
		"too wide":     base64.StdEncoding.EncodeToString(big.Bytes()),
		"empty":        "",
	} {
		if _, err := normalizeAvatar(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	webp := base64.StdEncoding.EncodeToString(append([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "), make([]byte, 16)...))
	if _, err := normalizeAvatar(webp); err != nil {
		t.Errorf("webp: %v", err)
	}
}

// A local account uploads, sees and removes its picture; API tokens can't;
// an SSO account can only when the administrator allows it, and its IdP
// picture shows otherwise.
func TestAvatarFlow(t *testing.T) {
	e := newTokenEnv(t)
	body := `{"image":"` + tinyJPEG(t) + `"}`

	rr := e.do(http.MethodPut, "/api/auth/avatar", body, true, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	var me map[string]any
	_ = json.Unmarshal(e.do(http.MethodGet, "/api/auth/me", "", true, "").Body.Bytes(), &me)
	url, _ := me["avatar_url"].(string)
	if !strings.HasPrefix(url, "/api/users/") || me["has_uploaded_avatar"] != true || me["can_upload_avatar"] != true {
		t.Fatalf("me after upload: %v", me)
	}
	img := e.do(http.MethodGet, url, "", true, "")
	if img.Code != http.StatusOK || img.Header().Get("Content-Type") != "image/jpeg" ||
		img.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(img.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("serve: %d %v", img.Code, img.Header())
	}
	if e.do(http.MethodGet, url, "", false, "").Code != http.StatusUnauthorized {
		t.Error("pictures are for signed-in users")
	}

	_, tok := e.mint("ipam", roleAdmin, 0)
	if rr := e.do(http.MethodPut, "/api/auth/avatar", body, false, bearer(tok)); rr.Code != http.StatusForbidden {
		t.Errorf("token upload: %d, want 403", rr.Code)
	}
	if rr := e.do(http.MethodPut, "/api/auth/avatar", `{"image":"PHN2Zz4="}`, true, ""); rr.Code != http.StatusBadRequest {
		t.Errorf("svg upload: %d, want 400", rr.Code)
	}
	if rr := e.do(http.MethodDelete, "/api/auth/avatar", "", true, ""); rr.Code != http.StatusOK {
		t.Fatalf("remove: %d", rr.Code)
	}
	if e.do(http.MethodGet, url, "", true, "").Code != http.StatusNotFound {
		t.Error("removed picture still served")
	}

	// An SSO account.
	sso, err := e.st.UpsertOIDCUser("sub-1", "alice", roleReadonly, "https://idp.example/alice.png")
	if err != nil {
		t.Fatal(err)
	}
	sess, _, err := auth.NewManager(e.st, nil, time.Hour).StartSession(sso.ID, sso.Username, roleReadonly)
	if err != nil {
		t.Fatal(err)
	}
	alice := &http.Cookie{Name: auth.CookieName, Value: sess}
	// as sends a request with whichever session e.cookie holds.
	as := func(method, path, b string) (int, map[string]any) {
		rr := e.do(method, path, b, true, "")
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	admin := e.cookie
	e.cookie = alice
	if code, _ := as(http.MethodPut, "/api/auth/avatar", body); code != http.StatusForbidden {
		t.Errorf("SSO upload while not allowed: %d, want 403", code)
	}
	if _, me := as(http.MethodGet, "/api/auth/me", ""); me["avatar_url"] != "https://idp.example/alice.png" || me["can_upload_avatar"] != false {
		t.Errorf("SSO me (not allowed): %v", me)
	}
	e.cookie = admin
	c := e.st.LoadCPSettings(cpSettingsDefaults())
	c.OIDC.AllowAvatarUpload = true
	if err := e.st.SaveCPSettings(c); err != nil {
		t.Fatal(err)
	}
	e.cookie = alice
	if code, _ := as(http.MethodPut, "/api/auth/avatar", body); code != http.StatusOK {
		t.Errorf("SSO upload when allowed: %d", code)
	}
	if _, me := as(http.MethodGet, "/api/auth/me", ""); !strings.HasPrefix(me["avatar_url"].(string), "/api/users/") {
		t.Errorf("SSO me (allowed): %v", me)
	}
	// The next SSO sign-in refreshes the IdP picture but keeps the upload.
	if _, err := e.st.UpsertOIDCUser("sub-1", "alice", roleReadonly, "https://idp.example/new.png"); err != nil {
		t.Fatal(err)
	}
	if _, me := as(http.MethodGet, "/api/auth/me", ""); !strings.HasPrefix(me["avatar_url"].(string), "/api/users/") {
		t.Errorf("upload lost at the next SSO sign-in: %v", me)
	}
	e.cookie = admin
}
