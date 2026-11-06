package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/config"
	"github.com/openbekci/openbekci-agent/internal/driver"
	"github.com/openbekci/openbekci-agent/internal/driver/mock"
	"github.com/openbekci/openbekci-agent/internal/fakeserver"
	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/transport"
)

const pointID = "0192f1a0-0000-7000-8000-0000000000b1"

type harness struct {
	t     *testing.T
	fs    *fakeserver.Server
	cfg   *config.Config
	shift atomic.Int64 // added to the agent clock (ns)
	seq   atomic.Int64

	mu  sync.Mutex
	cur *mock.Driver
	// tune lets a test adjust transport options before agents start.
	tune func(*transport.Options)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fs := fakeserver.New(t)
	h := &harness{t: t, fs: fs}
	h.cfg = &config.Config{
		Server: fs.URL, StateDir: t.TempDir(), CAFile: fs.CACertFile(), LogLevel: "debug", OfflineGraceHours: 72,
		Drivers: []config.DriverConfig{{Name: "gate", Type: "mock"}},
	}
	fs.SetConfig([]protocol.PointConfig{{ID: pointID, Name: "Main gate", Kind: "vehicle_gate", Direction: "in", DriverRef: protocol.DriverRef{Instance: "gate", Channel: "in"}, Enabled: true}}, nil)
	h.enrol()
	return h
}

func (h *harness) enrol() {
	h.t.Helper()
	if _, err := Enrol(context.Background(), h.cfg, EnrolOptions{Server: h.fs.URL, Token: h.fs.NewEnrolToken(), Version: "test"}); err != nil {
		h.t.Fatalf("enrol: %v", err)
	}
}

func (h *harness) logger() *slog.Logger {
	if os.Getenv("AGENT_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (h *harness) registration() driver.Registration {
	return driver.Registration{Type: "mock", New: func(name string, cfg map[string]any, log *slog.Logger) (driver.Driver, error) {
		m, err := mock.New(name, mock.Config{}, log)
		h.mu.Lock()
		h.cur = m
		h.mu.Unlock()
		return m, err
	}}
}

func (h *harness) options() Options {
	return Options{
		Config: h.cfg, Registrations: []driver.Registration{h.registration()}, Version: "test", Log: h.logger(),
		Clock:          func() time.Time { return time.Now().Add(time.Duration(h.shift.Load())) },
		HeartbeatEvery: 150 * time.Millisecond, ReadyTimeout: 2 * time.Second,
		Transport: func(o *transport.Options) {
			o.Backoff = transport.Backoff{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond, Factor: 2, Jitter: 0.2}
			o.PollWait = 1
			o.HealthyAfter = time.Hour
			if h.tune != nil {
				h.tune(o)
			}
		},
	}
}

type running struct {
	cancel context.CancelFunc
	done   chan error
}

// start runs a new agent on the harness's state directory.
func (h *harness) start() *running {
	h.t.Helper()
	a, err := New(h.options())
	if err != nil {
		h.t.Fatal(err)
	}
	return h.run(a)
}

func (h *harness) run(a *Agent) *running {
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- a.Run(ctx) }()
	h.t.Cleanup(func() { r.cancel(); <-r.done })
	return r
}

// stop cancels the agent and returns Run's error.
func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err // keep the cleanup's receive working
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop")
		return nil
	}
}

// wait returns Run's error once the agent stopped by itself.
func (r *running) wait(t *testing.T, d time.Duration) (error, bool) {
	t.Helper()
	select {
	case err := <-r.done:
		r.done <- err
		return err, true
	case <-time.After(d):
		return nil, false
	}
}

func (h *harness) mock() *mock.Driver {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		m := h.cur
		h.mu.Unlock()
		if m != nil {
			return m
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatal("mock driver was never built")
	return nil
}

// resetMock forgets the captured driver so mock() waits for the next agent's.
func (h *harness) resetMock() { h.mu.Lock(); h.cur = nil; h.mu.Unlock() }

func (h *harness) entry(plate string, mod func(*protocol.Entry)) protocol.Entry {
	n := h.seq.Add(1)
	e := protocol.Entry{
		ID: fmt.Sprintf("0192f1a0-0000-7000-8000-%012d", n), Kind: "plate", Value: plate, Points: []string{pointID},
		ValidFrom: protocol.At(time.Now().Add(-time.Hour)),
	}
	if mod != nil {
		mod(&e)
	}
	return e
}

// present shows a plate to the gate reader.
func (h *harness) present(plate string) {
	h.mock().Inject(driver.Presentation{Channel: "in", Kind: "plate", Value: plate})
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func (h *harness) status() StatusInfo {
	h.t.Helper()
	s, err := ReadStatus(context.Background(), h.cfg.StateDir)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func (h *harness) waitConnected(n int) {
	h.t.Helper()
	waitFor(h.t, 10*time.Second, fmt.Sprintf("%d sessions", n), func() bool { _, _, _, c := h.fs.Counters(); return c >= n })
}

// waitSynced waits until the agent holds the server's allow-list version and
// config version.
func (h *harness) waitSynced() {
	h.t.Helper()
	waitFor(h.t, 10*time.Second, "allow-list sync", func() bool {
		s, err := ReadStatus(context.Background(), h.cfg.StateDir)
		return err == nil && s.SnapshotVersion == h.fs.Version() && s.ConfigVersion == h.fs.ConfigVersion()
	})
}

func eventFor(evs []protocol.Event, plate string) (protocol.Event, bool) {
	for _, e := range evs {
		if e.ObservedPlate == plate {
			return e, true
		}
	}
	return protocol.Event{}, false
}
