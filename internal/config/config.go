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
	Listen    Listen   `yaml:"listen"`
	Upstreams []string `yaml:"upstreams"`
	Cache     Cache    `yaml:"cache"`
	Filter    Filter   `yaml:"filter"`
	Log       Log      `yaml:"log"`
}

// Listen is the DNS listener address.
type Listen struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
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
		Log: Log{Level: "info", QueryLog: false},
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
	return nil
}
