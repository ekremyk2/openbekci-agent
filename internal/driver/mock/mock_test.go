package mock

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

func recv(t *testing.T, ch <-chan driver.Presentation) driver.Presentation {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(3 * time.Second):
		t.Fatal("no presentation")
		return driver.Presentation{}
	}
}

func TestScriptAndInject(t *testing.T) {
	script := filepath.Join(t.TempDir(), "s.json")
	_ = os.WriteFile(script, []byte(`[{"after_ms":10,"channel":"in","kind":"plate","value":"34ABC123"},{"after_ms":10,"channel":"out","kind":"plate","value":"06XYZ99"}]`), 0o600)
	d, err := New("cam", Config{Script: script}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan driver.Presentation)
	done := make(chan error, 1)
	go func() { done <- d.Subscribe(ctx, out) }()
	if p := recv(t, out); p.Value != "34ABC123" || p.Channel != "in" || p.Instance != "cam" {
		t.Fatalf("first: %+v", p)
	}
	if p := recv(t, out); p.Value != "06XYZ99" {
		t.Fatalf("second: %+v", p)
	}
	d.Inject(driver.Presentation{Channel: "in", Kind: "plate", Value: "INJECTED"})
	if p := recv(t, out); p.Value != "INJECTED" || p.Instance != "cam" || p.Confidence != 1 {
		t.Fatalf("injected: %+v", p)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOpenRecordsLogsAndFails(t *testing.T) {
	log := filepath.Join(t.TempDir(), "opens.log")
	d, err := New("relay", Config{OpenLog: log}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Open(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	if o := d.Opens(); len(o) != 1 || o[0].Channel != "1" || o[0].Instance != "relay" {
		t.Fatalf("opens %+v", o)
	}
	if b, _ := os.ReadFile(log); strings.Count(string(b), "\n") != 1 {
		t.Fatalf("log %q", b)
	}
	d.SetFailOpen(true)
	if err := d.Open(context.Background(), "1"); err == nil {
		t.Fatal("expected failure")
	}
	if len(d.Opens()) != 1 {
		t.Fatal("failed open must not be recorded")
	}
}

func TestListenInjection(t *testing.T) {
	d, err := New("cam", Config{Listen: "127.0.0.1:0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan driver.Presentation, 1)
	go func() { _ = d.Subscribe(ctx, out) }()
	addr, err := d.ListenAddr(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post("http://"+addr+"/present", "application/json", bytes.NewBufferString(`{"channel":"in","value":"34 ABC 123"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if p := recv(t, out); p.Value != "34 ABC 123" || p.Kind != "plate" {
		t.Fatalf("%+v", p)
	}
	if _, err := New("x", Config{Listen: "0.0.0.0:9"}, nil); err == nil {
		t.Fatal("non-loopback listen must be refused")
	}
}
