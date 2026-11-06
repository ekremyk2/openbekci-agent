package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/fakeserver"
)

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestCLIEnrolStatusRotateAndCheck(t *testing.T) {
	fs := fakeserver.New(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "etc", "agent.yaml")
	t.Setenv("OPENBEKCI_AGENT_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("OPENBEKCI_AGENT_CA_FILE", fs.CACertFile())

	out, err := execute(t, "--config", cfgPath, "enrol", "--server", fs.URL, "--token", fs.NewEnrolToken())
	if err != nil || !strings.Contains(out, "Enrolled as agent "+fs.AgentID) {
		t.Fatalf("enrol: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil || !strings.Contains(string(raw), "server: "+fs.URL) {
		t.Fatalf("agent.yaml not written: %v\n%s", err, raw)
	}
	if strings.Contains(string(raw), "obk_") {
		t.Fatal("the config file must never contain a token")
	}

	out, err = execute(t, "--config", cfgPath, "status")
	if err != nil || !strings.Contains(out, fs.AgentID) || !strings.Contains(out, "queue depth") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if out, err = execute(t, "--config", cfgPath, "status", "--json"); err != nil || !strings.Contains(out, `"queue_depth": 0`) {
		t.Fatalf("status --json: %v\n%s", err, out)
	}

	old := fs.CurrentToken()
	if out, err = execute(t, "--config", cfgPath, "rotate-token"); err != nil || fs.CurrentToken() == old {
		t.Fatalf("rotate: %v\n%s", err, out)
	}

	if out, err = execute(t, "--config", cfgPath, "config", "check"); err != nil || !strings.Contains(out, "ok") {
		t.Fatalf("config check: %v\n%s", err, out)
	}

	// A bad driver section is rejected before the service would start.
	bad := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(bad, []byte("drivers:\n  - name: r\n    type: relay\n    config: {mode: http, pulse_ms: 5}\n"), 0o600)
	if out, err = execute(t, "--config", bad, "config", "check"); err == nil {
		t.Fatalf("invalid driver config accepted\n%s", out)
	}
	_ = os.WriteFile(bad, []byte("drivers:\n  - name: x\n    type: teleporter\n"), 0o600)
	if _, err = execute(t, "--config", bad, "config", "check"); err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("unknown driver type: %v", err)
	}
	_ = os.WriteFile(bad, []byte("bogus_key: 1\n"), 0o600)
	if _, err = execute(t, "--config", bad, "config", "check"); err == nil {
		t.Fatal("unknown config keys must be rejected")
	}

	if _, err = execute(t, "--config", cfgPath, "enrol", "--token", "obk_enr_x", "--server", "http://plain.example"); err == nil {
		t.Fatal("plain http server accepted")
	}
}

func TestCLIVersionAndRunRefusesWithoutEnrolment(t *testing.T) {
	out, err := execute(t, "version")
	if err != nil || !strings.Contains(out, "protocol v1") {
		t.Fatalf("%v %s", err, out)
	}
	t.Setenv("OPENBEKCI_AGENT_STATE_DIR", t.TempDir())
	done := make(chan error, 1)
	go func() { _, err := execute(t, "--config", filepath.Join(t.TempDir(), "none.yaml"), "run"); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not enrolled") {
			t.Fatalf("run without enrolment: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not exit")
	}
}
