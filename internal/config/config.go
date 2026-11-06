// Package config loads agent.yaml (design section 7.2) with OPENBEKCI_AGENT_*
// environment overrides.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// EnvPrefix is the prefix of the environment overrides.
const EnvPrefix = "OPENBEKCI_AGENT_"

// DriverConfig declares one driver instance.
type DriverConfig struct {
	Name   string         `yaml:"name"`
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:"config"`
}

// OpenRef names the instance and channel that opens a point.
type OpenRef struct {
	Instance string `yaml:"instance"`
	Channel  string `yaml:"channel"`
}

// PointWiring pairs a reader with a different opener: the point whose
// driver_ref.instance is Point (and, when set, whose channel is Channel) is
// opened through Open instead of through its own instance.
type PointWiring struct {
	Point   string  `yaml:"point"`
	Channel string  `yaml:"channel"`
	Open    OpenRef `yaml:"open"`
}

// Config is the agent's local configuration.
type Config struct {
	Server   string `yaml:"server"`
	StateDir string `yaml:"state_dir"`
	CAFile   string `yaml:"ca_file"`
	LogLevel string `yaml:"log_level"`
	// OfflineGraceHours is the grace period used until the server's
	// settings arrive; afterwards the server's value wins. Default 72.
	OfflineGraceHours int            `yaml:"offline_grace_hours"`
	Drivers           []DriverConfig `yaml:"drivers"`
	Points            []PointWiring  `yaml:"points"`
}

// DefaultPath is the platform's default config file location.
func DefaultPath() string {
	if p := os.Getenv(EnvPrefix + "CONFIG"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(programData(), "openbekci-agent", "agent.yaml")
	}
	return "/etc/openbekci-agent/agent.yaml"
}

// DefaultStateDir is the platform's default state directory.
func DefaultStateDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programData(), "openbekci-agent", "state")
	}
	return "/var/lib/openbekci-agent"
}

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

// Load reads path (a missing file is not an error: defaults and environment
// still apply) and applies environment overrides and defaults.
func Load(path string) (*Config, error) {
	c := &Config{}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.applyEnv(os.Getenv); err != nil {
		return nil, err
	}
	c.applyDefaults()
	return c, nil
}

func (c *Config) applyEnv(get func(string) string) error {
	set := func(dst *string, key string) {
		if v := get(EnvPrefix + key); v != "" {
			*dst = v
		}
	}
	set(&c.Server, "SERVER")
	set(&c.StateDir, "STATE_DIR")
	set(&c.CAFile, "CA_FILE")
	set(&c.LogLevel, "LOG_LEVEL")
	if v := get(EnvPrefix + "OFFLINE_GRACE_HOURS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%sOFFLINE_GRACE_HOURS: %w", EnvPrefix, err)
		}
		c.OfflineGraceHours = n
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir()
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.OfflineGraceHours == 0 {
		c.OfflineGraceHours = 72
	}
	c.Server = strings.TrimRight(c.Server, "/")
}

// Level converts LogLevel to a slog level.
func (c *Config) Level() (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.ToLower(c.LogLevel))); err != nil {
		return 0, fmt.Errorf("log_level %q: use debug, info, warn or error", c.LogLevel)
	}
	return l, nil
}

// Validate checks the file's static consistency. knownTypes lists the driver
// types the binary was built with (nil skips the type check).
func (c *Config) Validate(knownTypes []string) error {
	if c.Server != "" {
		if err := ValidateServerURL(c.Server); err != nil {
			return err
		}
	}
	if _, err := c.Level(); err != nil {
		return err
	}
	if c.OfflineGraceHours < 1 {
		return errors.New("offline_grace_hours must be >= 1")
	}
	names := map[string]bool{}
	for i, d := range c.Drivers {
		switch {
		case d.Name == "":
			return fmt.Errorf("drivers[%d]: name required", i)
		case names[d.Name]:
			return fmt.Errorf("drivers[%d]: duplicate name %q", i, d.Name)
		case d.Type == "":
			return fmt.Errorf("drivers[%d] (%s): type required", i, d.Name)
		}
		names[d.Name] = true
		if knownTypes != nil {
			ok := false
			for _, k := range knownTypes {
				ok = ok || k == d.Type
			}
			if !ok {
				return fmt.Errorf("drivers[%d] (%s): unknown type %q (known: %s)", i, d.Name, d.Type, strings.Join(knownTypes, ", "))
			}
		}
	}
	for i, p := range c.Points {
		if p.Point == "" || p.Open.Instance == "" {
			return fmt.Errorf("points[%d]: point and open.instance required", i)
		}
		if !names[p.Open.Instance] {
			return fmt.Errorf("points[%d]: open.instance %q is not a configured driver", i, p.Open.Instance)
		}
	}
	if c.CAFile != "" {
		if _, err := os.Stat(c.CAFile); err != nil {
			return fmt.Errorf("ca_file: %w", err)
		}
	}
	return nil
}

// ValidateServerURL requires an absolute https URL: the agent has no
// insecure mode.
func ValidateServerURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return fmt.Errorf("server %q is not a valid URL", s)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("server %q must use https (the agent has no insecure mode; private CAs go in ca_file)", s)
	}
	return nil
}

// Marshal renders a config for writing to disk.
func (c *Config) Marshal() ([]byte, error) { return yaml.Marshal(c) }
