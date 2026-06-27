package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes a minimal valid config file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "mazedns.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalConfig = `
listen: { address: "0.0.0.0", port: 5300 }
upstreams: ["1.1.1.1:53"]
database: { path: "mazedns.db" }
`

func TestOIDCEnvOverrides(t *testing.T) {
	p := writeConfig(t, minimalConfig)

	t.Setenv("MAZEDNS_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("MAZEDNS_OIDC_CLIENT_ID", "mazedns")
	t.Setenv("MAZEDNS_OIDC_CLIENT_SECRET", "s3cret")
	t.Setenv("MAZEDNS_OIDC_REDIRECT_URL", "https://dns.example.com/callback")
	t.Setenv("MAZEDNS_OIDC_SCOPES", "openid, profile email")
	t.Setenv("MAZEDNS_OIDC_GROUPS_CLAIM", "groups")
	t.Setenv("MAZEDNS_OIDC_ADMIN_GROUP", "admins")

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	o := cfg.Auth.OIDC
	if !o.Enabled {
		t.Error("setting MAZEDNS_OIDC_ISSUER should enable OIDC")
	}
	if o.Issuer != "https://id.example.com" || o.ClientID != "mazedns" ||
		o.ClientSecret != "s3cret" || o.RedirectURL != "https://dns.example.com/callback" {
		t.Errorf("env overrides not applied: %+v", o)
	}
	if o.GroupsClaim != "groups" || o.AdminGroup != "admins" {
		t.Errorf("group env overrides not applied: %+v", o)
	}
	want := []string{"openid", "profile", "email"}
	if len(o.Scopes) != len(want) {
		t.Fatalf("scopes = %v, want %v", o.Scopes, want)
	}
	for i := range want {
		if o.Scopes[i] != want[i] {
			t.Errorf("scopes[%d] = %q, want %q", i, o.Scopes[i], want[i])
		}
	}
}

// MAZEDNS_OIDC_ENABLED=false must win even if the YAML enabled it.
func TestOIDCEnvDisable(t *testing.T) {
	p := writeConfig(t, minimalConfig+`
auth:
  oidc:
    enabled: true
    issuer: "https://id.example.com"
    client_id: "mazedns"
    redirect_url: "https://dns.example.com/callback"
`)
	t.Setenv("MAZEDNS_OIDC_ENABLED", "false")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Auth.OIDC.Enabled {
		t.Error("MAZEDNS_OIDC_ENABLED=false should disable OIDC")
	}
}
