// Package mock is the scriptable driver used by tests, demos and `run --mock`.
// It works in both directions: it emits scripted or injected presentations and
// records every Open.
package mock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

// ScriptItem is one scripted presentation.
type ScriptItem struct {
	AfterMS  int    `json:"after_ms"`
	Instance string `json:"instance,omitempty"`
	Channel  string `json:"channel,omitempty"`
	Kind     string `json:"kind"`
	Value    string `json:"value"`
}

// Config is the mock driver's section of agent.yaml.
type Config struct {
	// Script is a file of ScriptItem objects (a JSON array).
	Script string `json:"script,omitempty"`
	// Loop replays the script forever.
	Loop bool `json:"loop,omitempty"`
	// Listen is an ip:port for POST /present manual injection (localhost only).
	Listen      string `json:"listen,omitempty"`
	OpenLog     string `json:"open_log,omitempty"`
	FailOpen    bool   `json:"fail_open,omitempty"`
	OpenDelayMS int    `json:"open_delay_ms,omitempty"`
}

// OpenRecord is one recorded Open.
type OpenRecord struct {
	At       time.Time `json:"at"`
	Instance string    `json:"instance"`
	Channel  string    `json:"channel"`
}

// Driver is the mock driver. Safe for concurrent use.
type Driver struct {
	name string
	cfg  Config
	log  *slog.Logger

	mu       sync.Mutex
	hook     func(ctx context.Context, channel string) error
	opens    []OpenRecord
	failOpen bool
	script   []ScriptItem
	inject   chan driver.Presentation
	boundTo  chan string // receives the listen address once bound (tests)
}

// New creates a mock driver instance.
func New(name string, cfg Config, log *slog.Logger) (*Driver, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	d := &Driver{name: name, cfg: cfg, log: log, failOpen: cfg.FailOpen, inject: make(chan driver.Presentation, 64), boundTo: make(chan string, 1)}
	if cfg.Script != "" {
		raw, err := os.ReadFile(cfg.Script)
		if err != nil {
			return nil, fmt.Errorf("mock %s: script: %w", name, err)
		}
		if err := json.Unmarshal(raw, &d.script); err != nil {
			return nil, fmt.Errorf("mock %s: script: %w", name, err)
		}
	}
	if cfg.Listen != "" {
		host, _, err := net.SplitHostPort(cfg.Listen)
		if err != nil {
			return nil, fmt.Errorf("mock %s: listen: %w", name, err)
		}
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("mock %s: listen must be a loopback address", name)
		}
	}
	return d, nil
}

// Inject queues a presentation for Subscribe to emit (tests, manual use).
func (d *Driver) Inject(p driver.Presentation) {
	if p.Instance == "" {
		p.Instance = d.name
	}
	if p.Confidence == 0 {
		p.Confidence = 1
	}
	d.inject <- p
}

// Opens returns a copy of the recorded opens.
func (d *Driver) Opens() []OpenRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]OpenRecord(nil), d.opens...)
}

// SetFailOpen makes subsequent Opens fail (or succeed again).
func (d *Driver) SetFailOpen(v bool) {
	d.mu.Lock()
	d.failOpen = v
	d.mu.Unlock()
}

// ListenAddr blocks until the injection listener is bound and returns its
// address (only when Config.Listen is set and Subscribe is running).
func (d *Driver) ListenAddr(ctx context.Context) (string, error) {
	select {
	case a := <-d.boundTo:
		d.boundTo <- a
		return a, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// SetOpenHook installs a function that runs at the start of every Open, while
// the "pulse" is in progress; it may block, inspect state or fail the open.
// Tests use it to look at the system mid-pulse.
func (d *Driver) SetOpenHook(h func(ctx context.Context, channel string) error) {
	d.mu.Lock()
	d.hook = h
	d.mu.Unlock()
}

// Open records the open and fails or delays as configured.
func (d *Driver) Open(ctx context.Context, channel string) error {
	d.mu.Lock()
	hook := d.hook
	d.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, channel); err != nil {
			return err
		}
	}
	if d.cfg.OpenDelayMS > 0 {
		select {
		case <-time.After(time.Duration(d.cfg.OpenDelayMS) * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	d.mu.Lock()
	fail := d.failOpen
	rec := OpenRecord{At: time.Now().UTC(), Instance: d.name, Channel: channel}
	if !fail {
		d.opens = append(d.opens, rec)
	}
	d.mu.Unlock()
	if fail {
		return errors.New("mock: open failed (fail_open)")
	}
	if d.cfg.OpenLog != "" {
		line, _ := json.Marshal(rec)
		f, err := os.OpenFile(d.cfg.OpenLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("mock: open log: %w", err)
		}
		_, werr := f.Write(append(line, '\n'))
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("mock: open log: %w", werr)
		}
	}
	return nil
}

// Subscribe emits scripted and injected presentations until ctx ends.
func (d *Driver) Subscribe(ctx context.Context, out chan<- driver.Presentation) error {
	emit := func(p driver.Presentation) bool {
		select {
		case out <- p:
			return true
		case <-ctx.Done():
			return false
		}
	}
	var wg sync.WaitGroup
	if d.cfg.Listen != "" {
		srv, err := d.serve(ctx)
		if err != nil {
			return err
		}
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		}()
	}
	if len(d.script) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				for _, it := range d.script {
					select {
					case <-time.After(time.Duration(it.AfterMS) * time.Millisecond):
					case <-ctx.Done():
						return
					}
					inst := it.Instance
					if inst == "" {
						inst = d.name
					}
					if !emit(driver.Presentation{Instance: inst, Channel: it.Channel, Kind: it.Kind, Value: it.Value, Confidence: 1, At: time.Now()}) {
						return
					}
				}
				if !d.cfg.Loop {
					return
				}
			}
		}()
	}
	for {
		select {
		case p := <-d.inject:
			if p.At.IsZero() {
				p.At = time.Now()
			}
			if !emit(p) {
				wg.Wait()
				return nil
			}
		case <-ctx.Done():
			wg.Wait()
			return nil
		}
	}
}

func (d *Driver) serve(ctx context.Context) (*http.Server, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", d.cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("mock %s: listen: %w", d.name, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /present", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Instance   string  `json:"instance"`
			Channel    string  `json:"channel"`
			Kind       string  `json:"kind"`
			Value      string  `json:"value"`
			Confidence float64 `json:"confidence"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Value == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Kind == "" {
			req.Kind = "plate"
		}
		d.Inject(driver.Presentation{Instance: req.Instance, Channel: req.Channel, Kind: req.Kind, Value: req.Value, Confidence: req.Confidence, At: time.Now()})
		w.WriteHeader(http.StatusAccepted)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	select {
	case d.boundTo <- ln.Addr().String():
	default:
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Error("mock listener stopped", "error", err)
		}
	}()
	return srv, nil
}

// Health is always ok.
func (d *Driver) Health(context.Context) driver.Health { return driver.Health{State: driver.StateOK} }

// Close is a no-op.
func (d *Driver) Close() error { return nil }
