// Package config loads and validates MazeDNS runtime configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	Classifier Classifier  `yaml:"classifier"`
	Cluster    Cluster     `yaml:"cluster"`
	Database   Database    `yaml:"database"`
	Log        Log         `yaml:"log"`
	Metrics    Metrics     `yaml:"metrics"`
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
// Every field can also be set from the environment (MAZEDNS_OIDC_ISSUER,
// MAZEDNS_OIDC_CLIENT_ID, MAZEDNS_OIDC_CLIENT_SECRET, MAZEDNS_OIDC_REDIRECT_URL,
// MAZEDNS_OIDC_SCOPES, MAZEDNS_OIDC_GROUPS_CLAIM, MAZEDNS_OIDC_ADMIN_GROUP,
// MAZEDNS_OIDC_ENABLED), which is the preferred way to configure SSO in
// containers. Env values override the YAML file.
type OIDC struct {
	Enabled      bool     `yaml:"enabled"`
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
	GroupsClaim  string   `yaml:"groups_claim"`
	AdminGroup   string   `yaml:"admin_group"`
	// DisablePasswordLogin removes local username/password login when SSO is
	// enabled (SSO becomes the only way in). Ignored if OIDC fails to initialize,
	// so a broken provider can't lock everyone out.
	DisablePasswordLogin bool `yaml:"disable_password_login"`
	// AutoLogin redirects straight to the SSO provider instead of showing the
	// login form (the user can still log out and choose another method).
	AutoLogin bool `yaml:"auto_login"`
}

// Classifier configures optional LLM-based domain classification against a
// local, OpenAI-compatible model endpoint (Ollama, llama.cpp, LM Studio, …).
// Disabled by default; runs only on the master. The enforcement mode is seeded
// from here and then changeable at runtime from the UI.
type Classifier struct {
	Enabled    bool   `yaml:"enabled"`
	Endpoint   string `yaml:"endpoint"`    // OpenAI-compatible base URL, e.g. http://localhost:11434/v1
	Model      string `yaml:"model"`       // model name, e.g. "llama3.2"
	APIKey     string `yaml:"api_key"`     // usually empty for local models
	Mode       string `yaml:"mode"`        // off | suggest | auto (initial enforcement mode)
	MinGapMS   int    `yaml:"min_gap_ms"`  // min spacing between model calls (rate limit)
	TimeoutSec int    `yaml:"timeout_sec"` // per-request timeout (local models warm up slowly)
	// Trusted list (reduces false positives): a built-in public default is used
	// unless TrustedDisableDefault; TrustedListURL adds a custom source.
	TrustedListURL        string `yaml:"trusted_list_url"`
	TrustedTopN           int    `yaml:"trusted_top_n"`
	TrustedDisableDefault bool   `yaml:"trusted_disable_default"`
	// Threat lists (corroborate malicious verdicts): ThreatFeeds enables built-in
	// public feeds (urlhaus, threatfox, phishing_army, hagezi_tif, …);
	// ThreatListURL adds custom sources (one per line / comma-separated).
	ThreatFeeds          []string `yaml:"threat_feeds"`
	ThreatListURL        string   `yaml:"threat_list_url"`
	ThreatDisableDefault bool     `yaml:"threat_disable_default"`
	// WhoisEnabled enriches classifications with RDAP/WHOIS registration data
	// (domain age etc.) as a signal for the model.
	WhoisEnabled bool `yaml:"whois_enabled"`
	// Reputation enrichment (optional, key-gated): VirusTotal (domain) + AbuseIPDB
	// (resolved IP) corroborate verdicts.
	VTEnabled        bool   `yaml:"vt_enabled"`
	VTAPIKey         string `yaml:"vt_api_key"`
	AbuseIPDBEnabled bool   `yaml:"abuseipdb_enabled"`
	AbuseIPDBAPIKey  string `yaml:"abuseipdb_api_key"`
}

// Cluster configures master<->worker configuration replication. The master
// serves cluster endpoints when enabled; each worker authenticates with a
// per-node API key issued by the master's "add node" flow.
type Cluster struct {
	Enabled   bool     `yaml:"enabled"`
	MasterURL string   `yaml:"master_url"` // worker: master base URL, e.g. http://master:8080
	MasterIP  string   `yaml:"master_ip"`  // worker: pin the master's IP (skip DNS); TLS still uses the URL host
	NodeKey   string   `yaml:"node_key"`   // worker: per-node API key from the master
	Interval  Duration `yaml:"interval"`   // worker: snapshot poll interval
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

// Metrics groups the metrics/logs export integrations.
type Metrics struct {
	VictoriaMetrics VictoriaMetrics `yaml:"victoria_metrics"`
	VictoriaLogs    VictoriaLogs    `yaml:"victoria_logs"`
}

// VictoriaLogs ships the (cluster-wide) query log from the master to a
// VictoriaLogs instance for long-term retention beyond the local SQLite window.
type VictoriaLogs struct {
	Enabled  bool     `yaml:"enabled"`
	URL      string   `yaml:"url"`      // base URL, e.g. http://victorialogs:9428
	Interval Duration `yaml:"interval"` // ship interval (default 15s)
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
}

// VictoriaMetrics pushes this node's Prometheus metrics to a VictoriaMetrics
// instance (its Prometheus text import endpoint) on an interval. Each node pushes
// its own metrics labelled with `instance`, so a cluster's metrics aggregate in VM
// without VM having to scrape every node.
type VictoriaMetrics struct {
	Enabled  bool     `yaml:"enabled"`
	URL      string   `yaml:"url"`      // base URL, e.g. http://victoriametrics:8428
	Interval Duration `yaml:"interval"` // push interval (default 15s)
	Job      string   `yaml:"job"`      // job label (default "mazedns")
	Instance string   `yaml:"instance"` // instance label (default: hostname)
	Username string   `yaml:"username"` // optional HTTP basic auth
	Password string   `yaml:"password"`
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
		Classifier: Classifier{
			Endpoint:     "http://localhost:11434/v1",
			Model:        "llama3.2",
			Mode:         "suggest",
			MinGapMS:     1000,
			TimeoutSec:   60,
			WhoisEnabled: true,
		},
		Cluster:  Cluster{Interval: Duration(30 * time.Second)},
		Database: Database{Path: "mazedns.db"},
		Log:      Log{Level: "info", QueryLog: false},
		Metrics: Metrics{
			VictoriaMetrics: VictoriaMetrics{
				Interval: Duration(15 * time.Second),
				Job:      "mazedns",
			},
			VictoriaLogs: VictoriaLogs{Interval: Duration(15 * time.Second)},
		},
	}
}

// Load reads YAML from path, overlays it onto defaults, resolves relative
// blocklist paths against the config file's directory, applies env overrides,
// and validates the result.
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
	// Deployment-time env overrides (handy for containers).
	if v := os.Getenv("MAZEDNS_LISTEN_ADDRESS"); v != "" {
		cfg.Listen.Address = v
	}
	// MAZEDNS_BLOCKLIST_FILES replaces filter.blocklist_files with a comma/space
	// separated list of paths — handy for pointing a container at a mounted
	// blocklist without editing the baked config. Use absolute paths (env values
	// are not resolved relative to the config file).
	if v := os.Getenv("MAZEDNS_BLOCKLIST_FILES"); v != "" {
		cfg.Filter.BlocklistFiles = splitList(v)
	}
	if v := os.Getenv("MAZEDNS_API_ADDRESS"); v != "" {
		cfg.API.Address = v
	}
	if v := os.Getenv("MAZEDNS_DB_PATH"); v != "" {
		cfg.Database.Path = v
	}
	if v := os.Getenv("MAZEDNS_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("MAZEDNS_MASTER_URL"); v != "" {
		cfg.Cluster.MasterURL = v
		cfg.Cluster.Enabled = true
	}
	if v := os.Getenv("MAZEDNS_NODE_KEY"); v != "" {
		cfg.Cluster.NodeKey = v
		cfg.Cluster.Enabled = true
	}
	if v := os.Getenv("MAZEDNS_MASTER_IP"); v != "" {
		cfg.Cluster.MasterIP = v
	}
	if v := os.Getenv("MAZEDNS_CLUSTER_ENABLED"); v == "true" || v == "1" {
		cfg.Cluster.Enabled = true
	}
	if v := os.Getenv("MAZEDNS_CLASSIFIER_ENABLED"); v == "true" || v == "1" {
		cfg.Classifier.Enabled = true
	}
	if v := os.Getenv("MAZEDNS_CLASSIFIER_ENDPOINT"); v != "" {
		cfg.Classifier.Endpoint = v
	}
	if v := os.Getenv("MAZEDNS_CLASSIFIER_MODEL"); v != "" {
		cfg.Classifier.Model = v
	}
	if v := os.Getenv("MAZEDNS_CLASSIFIER_MODE"); v != "" {
		cfg.Classifier.Mode = v
	}
	if v := os.Getenv("MAZEDNS_CLASSIFIER_API_KEY"); v != "" {
		cfg.Classifier.APIKey = v
	}
	applyOIDCEnv(&cfg.Auth.OIDC)
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// applyOIDCEnv overlays MAZEDNS_OIDC_* environment variables onto the OIDC
// config, so SSO can be configured entirely from the container environment
// (handy for Docker / Compose / Kubernetes) without editing the YAML file.
// Setting MAZEDNS_OIDC_ISSUER (or _ENABLED=true) turns SSO on.
func applyOIDCEnv(o *OIDC) {
	if v := envClean("MAZEDNS_OIDC_ISSUER"); v != "" {
		o.Issuer = v
		o.Enabled = true
	}
	if v := envClean("MAZEDNS_OIDC_CLIENT_ID"); v != "" {
		o.ClientID = v
	}
	if v := envClean("MAZEDNS_OIDC_CLIENT_SECRET"); v != "" {
		o.ClientSecret = v
	}
	if v := envClean("MAZEDNS_OIDC_REDIRECT_URL"); v != "" {
		o.RedirectURL = v
	}
	if v := envClean("MAZEDNS_OIDC_SCOPES"); v != "" {
		o.Scopes = splitList(v)
	}
	if v := envClean("MAZEDNS_OIDC_GROUPS_CLAIM"); v != "" {
		o.GroupsClaim = v
	}
	if v := envClean("MAZEDNS_OIDC_ADMIN_GROUP"); v != "" {
		o.AdminGroup = v
	}
	switch strings.ToLower(envClean("MAZEDNS_OIDC_DISABLE_PASSWORD_LOGIN")) {
	case "true", "1":
		o.DisablePasswordLogin = true
	case "false", "0":
		o.DisablePasswordLogin = false
	}
	switch strings.ToLower(envClean("MAZEDNS_OIDC_AUTO_LOGIN")) {
	case "true", "1":
		o.AutoLogin = true
	case "false", "0":
		o.AutoLogin = false
	}
	// _ENABLED is applied last so it can explicitly enable or disable.
	switch strings.ToLower(envClean("MAZEDNS_OIDC_ENABLED")) {
	case "true", "1":
		o.Enabled = true
	case "false", "0":
		o.Enabled = false
	}
}

// envClean reads an env var and strips surrounding whitespace and a single pair
// of matching surrounding quotes. This guards against a very common deployment
// mistake — quoting the value in docker-compose's list form or an env_file
// (`- KEY="value"`), where the quotes become part of the value and break exact
// matches like the OIDC redirect_uri.
func envClean(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			v = strings.TrimSpace(v[1 : len(v)-1])
		}
	}
	return v
}

// splitList parses a comma- or space-separated list, trimming blanks.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
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
