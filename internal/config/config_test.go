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
listen: { address: "0.0.0.0", port: 53 }
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

func TestDefaultListenPort(t *testing.T) {
	// The default DNS port is 53 so a dns-agent container binds it directly under
	// host networking without a config override.
	if got := Default().Listen.Port; got != 53 {
		t.Errorf("default listen.port = %d, want 53", got)
	}
}

func TestListenPortEnvOverride(t *testing.T) {
	p := writeConfig(t, minimalConfig)
	t.Setenv("MAZEDNS_LISTEN_PORT", "5300")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen.Port != 5300 {
		t.Errorf("MAZEDNS_LISTEN_PORT not applied: port = %d, want 5300", cfg.Listen.Port)
	}
}

func TestMasterIPValidation(t *testing.T) {
	if _, err := Load(writeConfig(t, minimalConfig+"\ncluster: { master_ip: \"not-an-ip\" }\n")); err == nil {
		t.Error("expected an error for a non-IP cluster.master_ip")
	}
	if _, err := Load(writeConfig(t, minimalConfig+"\ncluster: { master_ip: \"10.0.0.5\" }\n")); err != nil {
		t.Errorf("a valid cluster.master_ip should load: %v", err)
	}
}

func TestBlocklistFilesEnvOverride(t *testing.T) {
	// The YAML references a relative file; the env var must replace it entirely.
	p := writeConfig(t, minimalConfig+`
filter:
  enabled: true
  blocklist_files: ["ignored.hosts"]
`)
	t.Setenv("MAZEDNS_BLOCKLIST_FILES", "/etc/mazedns/a.hosts, /etc/mazedns/b.hosts")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := cfg.Filter.BlocklistFiles
	want := []string{"/etc/mazedns/a.hosts", "/etc/mazedns/b.hosts"}
	if len(got) != len(want) {
		t.Fatalf("blocklist_files = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("blocklist_files[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestOIDCLoginFlagsEnv(t *testing.T) {
	p := writeConfig(t, minimalConfig)
	t.Setenv("MAZEDNS_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("MAZEDNS_OIDC_CLIENT_ID", "mazedns")
	t.Setenv("MAZEDNS_OIDC_REDIRECT_URL", "https://dns.example.com/api/auth/oidc/callback")
	t.Setenv("MAZEDNS_OIDC_DISABLE_PASSWORD_LOGIN", "true")
	t.Setenv("MAZEDNS_OIDC_AUTO_LOGIN", "1")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Auth.OIDC.DisablePasswordLogin {
		t.Error("MAZEDNS_OIDC_DISABLE_PASSWORD_LOGIN should disable password login")
	}
	if !cfg.Auth.OIDC.AutoLogin {
		t.Error("MAZEDNS_OIDC_AUTO_LOGIN should enable auto-login")
	}
}

// Quoted env values (a common docker-compose list-form / env_file mistake) must
// have the surrounding quotes stripped, or the OIDC redirect_uri won't match.
func TestOIDCEnvStripsQuotes(t *testing.T) {
	p := writeConfig(t, minimalConfig)
	t.Setenv("MAZEDNS_OIDC_ISSUER", `"https://id.example.com"`)
	t.Setenv("MAZEDNS_OIDC_CLIENT_ID", "mazedns")
	t.Setenv("MAZEDNS_OIDC_REDIRECT_URL", `"https://dns.example.com/api/auth/oidc/callback"`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Auth.OIDC.RedirectURL != "https://dns.example.com/api/auth/oidc/callback" {
		t.Errorf("redirect_url not unquoted: %q", cfg.Auth.OIDC.RedirectURL)
	}
	if cfg.Auth.OIDC.Issuer != "https://id.example.com" {
		t.Errorf("issuer not unquoted: %q", cfg.Auth.OIDC.Issuer)
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
