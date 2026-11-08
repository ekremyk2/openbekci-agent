package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const sample = `
server: https://bekci.example.org/
state_dir: /var/lib/openbekci-agent
log_level: warn
offline_grace_hours: 48
drivers:
  - name: gate-relay
    type: relay
    config: { mode: http, http: { channels: { "1": { on_url: "http://10.0.0.5/relay/0?turn=on&timer=1" } } } }
  - name: gate-cam
    type: platecam
    config: { adapter: mock }
points:
  - point: main-gate-in
    open: { instance: gate-relay, channel: "1" }
`

func TestLoadParsesAndDefaults(t *testing.T) {
	c, err := Load(write(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "https://bekci.example.org" || c.OfflineGraceHours != 48 || c.LogLevel != "warn" || len(c.Drivers) != 2 || len(c.Points) != 1 {
		t.Fatalf("%+v", c)
	}
	if c.Drivers[0].Config["mode"] != "http" {
		t.Fatalf("driver config %+v", c.Drivers[0].Config)
	}
	if err := c.Validate([]string{"relay", "platecam", "mock"}); err != nil {
		t.Fatal(err)
	}
	// Missing file: defaults only.
	d, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil || d.OfflineGraceHours != 72 || d.LogLevel != "info" || d.StateDir == "" {
		t.Fatalf("defaults %+v %v", d, err)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("OPENBEKCI_AGENT_SERVER", "https://env.example")
	t.Setenv("OPENBEKCI_AGENT_STATE_DIR", "/tmp/state")
	t.Setenv("OPENBEKCI_AGENT_LOG_LEVEL", "debug")
	t.Setenv("OPENBEKCI_AGENT_OFFLINE_GRACE_HOURS", "24")
	c, err := Load(write(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "https://env.example" || c.StateDir != "/tmp/state" || c.LogLevel != "debug" || c.OfflineGraceHours != 24 {
		t.Fatalf("%+v", c)
	}
	t.Setenv("OPENBEKCI_AGENT_OFFLINE_GRACE_HOURS", "lots")
	if _, err := Load(write(t, sample)); err == nil {
		t.Fatal("bad integer accepted")
	}
}

func TestValidation(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"http server", "server: http://x.example\n", "https"},
		{"bad level", "log_level: loud\n", "log_level"},
		{"dup driver", "drivers:\n - {name: a, type: mock}\n - {name: a, type: mock}\n", "duplicate"},
		{"unknown type", "drivers:\n - {name: a, type: nope}\n", "unknown type"},
		{"point to missing instance", "drivers:\n - {name: a, type: mock}\npoints:\n - {point: p, open: {instance: zzz}}\n", "not a configured driver"},
		{"missing ca file", "ca_file: /definitely/not/here.pem\n", "ca_file"},
		{"grace too long", "offline_grace_hours: 337\n", "offline_grace_hours"},
		{"grace absurd", "offline_grace_hours: 9999999999\n", "offline_grace_hours"},
		{"grace negative", "offline_grace_hours: -1\n", "offline_grace_hours"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(write(t, tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			err = c.Validate([]string{"relay", "platecam", "mock"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want it to mention %q", err, tc.want)
			}
		})
	}
	if _, err := Load(write(t, "nonsense: true\n")); err == nil {
		t.Fatal("unknown top-level key accepted")
	}
}

func TestGraceBoundsInclusive(t *testing.T) {
	for _, h := range []string{"1", "72", "336"} {
		c, err := Load(write(t, "offline_grace_hours: "+h+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(nil); err != nil {
			t.Errorf("%s h rejected: %v", h, err)
		}
	}
}
