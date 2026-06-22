// Package config loads and validates MazeDNS runtime configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from strings like "10s" or "24h".
type Duration time.Duration

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Config is the full MazeDNS configuration.
type Config struct {
	Listen     Listen      `yaml:"listen"`
	Upstreams  []string    `yaml:"upstreams"`
	Forwarders []Forwarder `yaml:"forwarders"`
	Zones      []Zone      `yaml:"zones"`
	RateLimit  RateLimit   `yaml:"rate_limit"`
	DNSSEC     DNSSEC      `yaml:"dnssec"`
	DoT        Endpoint    `yaml:"dot"`
	DoH        DoHEndpoint `yaml:"doh"`
	TLS        TLS         `yaml:"tls"`
	Cache      Cache       `yaml:"cache"`
	Filter     Filter      `yaml:"filter"`
	API        API         `yaml:"api"`
	Auth       Auth        `yaml:"auth"`
	Database   Database    `yaml:"database"`
	Log        Log         `yaml:"log"`
}

// Listen is the DNS listener address.
type Listen struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// Forwarder routes a domain suffix to specific upstreams (split-horizon).
type Forwarder struct {
	Suffix    string   `yaml:"suffix"`
	Upstreams []string `yaml:"upstreams"`
}

// Zone is an authoritative zone served locally.
type Zone struct {
	Name    string       `yaml:"name"`
	Records []ZoneRecord `yaml:"records"`
}

// ZoneRecord is one record in an authoritative zone.
type ZoneRecord struct {
	Name  string `yaml:"name"` // relative label; "@" or "" = apex
	Type  string `yaml:"type"` // A | AAAA | CNAME | TXT | MX
	Value string `yaml:"value"`
	TTL   uint32 `yaml:"ttl"`
}

// RateLimit configures per-client query-rate limiting.
type RateLimit struct {
	Enabled bool `yaml:"enabled"`
	QPM     int  `yaml:"qpm"` // max queries per minute per client IP
}

// DNSSEC configures DNSSEC-aware forwarding.
type DNSSEC struct {
	Enabled bool `yaml:"enabled"` // force the DO bit upstream + surface AD
}

// Endpoint is a generic enable/address/port listener (used for DoT).
type Endpoint struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// DoHEndpoint is the DNS-over-HTTPS listener.
type DoHEndpoint struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// TLS holds the certificate used by the encrypted DNS endpoints.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Cache configures the response cache.
type Cache struct {
	Enabled    bool     `yaml:"enabled"`
	MaxEntries int      `yaml:"max_entries"`
	MinTTL     Duration `yaml:"min_ttl"`
	MaxTTL     Duration `yaml:"max_ttl"`
}

// Filter configures blocklist-based filtering.
type Filter struct {
	Enabled        bool     `yaml:"enabled"`
	BlockResponse  string   `yaml:"block_response"` // "nxdomain" | "zeroip"
	BlocklistFiles []string `yaml:"blocklist_files"`
}

// API configures the HTTP control-plane / metrics / UI server.
type API struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// Auth configures authentication for the control plane and UI.
type Auth struct {
	Enabled    bool           `yaml:"enabled"`
	SessionTTL Duration       `yaml:"session_ttl"`
	Admin      AdminBootstrap `yaml:"admin"`
	OIDC       OIDC           `yaml:"oidc"`
}

// AdminBootstrap seeds the first local admin (env overrides:
// MAZEDNS_ADMIN_USERNAME / MAZEDNS_ADMIN_PASSWORD).
type AdminBootstrap struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// OIDC configures Single Sign-On via an OpenID Connect provider (e.g. Authentik).
type OIDC struct {
	Enabled      bool     `yaml:"enabled"`
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
	GroupsClaim  string   `yaml:"groups_claim"`
	AdminGroup   string   `yaml:"admin_group"`
}

// Database configures the SQLite datastore.
type Database struct {
	Path string `yaml:"path"`
}

// Log configures logging.
type Log struct {
	Level    string `yaml:"level"` // debug|info|warn|error
	QueryLog bool   `yaml:"query_log"`
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		Listen:    Listen{Address: "0.0.0.0", Port: 5300},
		Upstreams: []string{"1.1.1.1:53", "9.9.9.9:53"},
		DoT:       Endpoint{Enabled: false, Address: "0.0.0.0", Port: 853},
		DoH:       DoHEndpoint{Enabled: false, Address: "0.0.0.0", Port: 8443, Path: "/dns-query"},
		Cache: Cache{
			Enabled:    true,
			MaxEntries: 10000,
			MinTTL:     Duration(10 * time.Second),
			MaxTTL:     Duration(24 * time.Hour),
		},
		Filter: Filter{
			Enabled:       true,
			BlockResponse: "nxdomain",
		},
		API: API{Enabled: true, Address: "127.0.0.1", Port: 8080},
		Auth: Auth{
			Enabled:    true,
			SessionTTL: Duration(24 * time.Hour),
		},
		Database: Database{Path: "mazedns.db"},
		Log:      Log{Level: "info", QueryLog: false},
	}
}

// Load reads YAML from path, overlays it onto defaults, resolves relative
// blocklist paths against the config file's directory, and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	dir := filepath.Dir(path)
	for i, f := range cfg.Filter.BlocklistFiles {
		if !filepath.IsAbs(f) {
			cfg.Filter.BlocklistFiles[i] = filepath.Join(dir, f)
		}
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.Listen.Port <= 0 || c.Listen.Port > 65535 {
		return fmt.Errorf("listen.port out of range: %d", c.Listen.Port)
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	switch c.Filter.BlockResponse {
	case "", "nxdomain", "zeroip":
	default:
		return fmt.Errorf("filter.block_response must be nxdomain or zeroip, got %q", c.Filter.BlockResponse)
	}
	if c.API.Enabled && (c.API.Port <= 0 || c.API.Port > 65535) {
		return fmt.Errorf("api.port out of range: %d", c.API.Port)
	}
	if c.Database.Path == "" {
		return fmt.Errorf("database.path is required")
	}
	if c.Auth.OIDC.Enabled {
		if c.Auth.OIDC.Issuer == "" || c.Auth.OIDC.ClientID == "" || c.Auth.OIDC.RedirectURL == "" {
			return fmt.Errorf("auth.oidc requires issuer, client_id, and redirect_url when enabled")
		}
	}
	if c.DoH.Enabled && c.DoH.Path == "" {
		return fmt.Errorf("doh.path is required when doh is enabled")
	}
	return nil
}
