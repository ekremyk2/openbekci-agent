// Package platecam is the plate-recognition camera driver (design 7.3b), input
// only. A Reader delivers camera reads; the brand-specific implementation is
// "TBD" until the first site's camera is known, so only the scripted mock
// reader exists today.
package platecam

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

// Defaults from the design.
const (
	DefaultConfidenceMin = 0.80
	DefaultDedupeS       = 30
)

// Read is one camera read, brand-independent.
type Read struct {
	Plate      string
	Confidence float64   // 0..1; 0 means "not reported" and is treated as 1
	At         time.Time // zero = receipt time
	Lane       string    // camera lane/direction value, mapped through channel_map
	RawRef     string
}

// Reader streams reads from a camera. A real brand adapter (push listener or
// poller) implements this interface.
type Reader interface {
	// Read emits reads until ctx ends.
	Read(ctx context.Context, out chan<- Read) error
	Health(ctx context.Context) driver.Health
	Close() error
}

// Config is the platecam driver's section of agent.yaml.
type Config struct {
	// Adapter selects the reader; only "mock" exists (brand TBD).
	Adapter       string            `json:"adapter"`
	ConfidenceMin *float64          `json:"confidence_min,omitempty"`
	DedupeS       *int              `json:"dedupe_s,omitempty"`
	ChannelMap    map[string]string `json:"channel_map,omitempty"`
	// Script is the mock adapter's file of {after_ms, plate, confidence, lane}.
	Script string `json:"script,omitempty"`
}

// Registration registers the "platecam" driver type.
var Registration = driver.Registration{
	Type: "platecam",
	New: func(name string, cfg map[string]any, log *slog.Logger) (driver.Driver, error) {
		var c Config
		if err := driver.DecodeConfig(cfg, &c); err != nil {
			return nil, err
		}
		var r Reader
		switch c.Adapter {
		case "mock":
			m, err := NewMockReader(c.Script)
			if err != nil {
				return nil, fmt.Errorf("platecam %s: %w", name, err)
			}
			r = m
		case "":
			return nil, fmt.Errorf("platecam %s: adapter required (only \"mock\" exists; the camera brand is not decided yet)", name)
		default:
			return nil, fmt.Errorf("platecam %s: unknown adapter %q (brand adapter not implemented)", name, c.Adapter)
		}
		return New(name, c, r, log)
	},
	Schema: `{"type":"object","required":["adapter"],"properties":{"adapter":{"enum":["mock"]},"confidence_min":{"type":"number","minimum":0,"maximum":1},"dedupe_s":{"type":"integer","minimum":0},"channel_map":{"type":"object","additionalProperties":{"type":"string"}},"script":{"type":"string"}}}`,
}

// Driver adapts a Reader to driver.Driver.
type Driver struct {
	name   string
	r      Reader
	log    *slog.Logger
	minC   float64
	dedupe time.Duration
	cmap   map[string]string

	mu   sync.Mutex
	seen map[string]time.Time
}

// New wraps r with confidence filtering, dedupe and lane mapping.
func New(name string, cfg Config, r Reader, log *slog.Logger) (*Driver, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	minC := DefaultConfidenceMin
	if cfg.ConfidenceMin != nil {
		minC = *cfg.ConfidenceMin
	}
	if minC < 0 || minC > 1 {
		return nil, fmt.Errorf("platecam %s: confidence_min must be within 0..1", name)
	}
	ded := DefaultDedupeS
	if cfg.DedupeS != nil {
		ded = *cfg.DedupeS
	}
	if ded < 0 {
		return nil, fmt.Errorf("platecam %s: dedupe_s must be >= 0", name)
	}
	return &Driver{name: name, r: r, log: log, minC: minC, dedupe: time.Duration(ded) * time.Second, cmap: cfg.ChannelMap, seen: map[string]time.Time{}}, nil
}

// Open is not supported: cameras only read.
func (d *Driver) Open(context.Context, string) error { return driver.ErrNotSupported }

// Subscribe forwards reads as presentations. Reads below confidence_min are
// forwarded with an empty value so the engine logs deny/unknown with the
// detail and does not act on them; repeated reads of one plate on one channel
// within dedupe_s are dropped.
func (d *Driver) Subscribe(ctx context.Context, out chan<- driver.Presentation) error {
	reads := make(chan Read)
	errc := make(chan error, 1)
	go func() { errc <- d.r.Read(ctx, reads) }()
	for {
		select {
		case rd := <-reads:
			p := d.convert(rd)
			if p == nil {
				continue
			}
			select {
			case out <- *p:
			case <-ctx.Done():
				return nil
			}
		case err := <-errc:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case <-ctx.Done():
			<-errc
			return nil
		}
	}
}

func (d *Driver) convert(rd Read) *driver.Presentation {
	conf := rd.Confidence
	if conf == 0 {
		conf = 1
	}
	at := rd.At
	if at.IsZero() {
		at = time.Now()
	}
	channel := rd.Lane
	if m, ok := d.cmap[rd.Lane]; ok {
		channel = m
	}
	p := &driver.Presentation{Instance: d.name, Channel: channel, Kind: "plate", Value: rd.Plate, Confidence: conf, At: at, RawRef: rd.RawRef}
	if conf < d.minC {
		p.Value = ""
		p.Detail = map[string]any{"low_confidence": true, "confidence": conf}
		return p
	}
	if d.dedupe > 0 {
		key := channel + "|" + rd.Plate
		d.mu.Lock()
		defer d.mu.Unlock()
		if t, ok := d.seen[key]; ok && at.Sub(t) < d.dedupe && at.Sub(t) >= 0 {
			return nil
		}
		if len(d.seen) > 512 {
			for k, t := range d.seen {
				if at.Sub(t) >= d.dedupe {
					delete(d.seen, k)
				}
			}
		}
		d.seen[key] = at
	}
	return p
}

// Health delegates to the reader.
func (d *Driver) Health(ctx context.Context) driver.Health { return d.r.Health(ctx) }

// Close closes the reader.
func (d *Driver) Close() error { return d.r.Close() }

// MockReader is the only Reader implementation: it plays a script and accepts
// reads through Feed.
type MockReader struct {
	script []struct {
		AfterMS    int     `json:"after_ms"`
		Plate      string  `json:"plate"`
		Confidence float64 `json:"confidence"`
		Lane       string  `json:"lane"`
	}
	feed chan Read
}

// NewMockReader loads an optional script file.
func NewMockReader(script string) (*MockReader, error) {
	m := &MockReader{feed: make(chan Read, 16)}
	if script == "" {
		return m, nil
	}
	raw, err := os.ReadFile(script)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &m.script); err != nil {
		return nil, fmt.Errorf("script: %w", err)
	}
	return m, nil
}

// Feed injects a read (tests).
func (m *MockReader) Feed(r Read) { m.feed <- r }

// Read implements Reader.
func (m *MockReader) Read(ctx context.Context, out chan<- Read) error {
	for _, it := range m.script {
		select {
		case <-time.After(time.Duration(it.AfterMS) * time.Millisecond):
		case <-ctx.Done():
			return nil
		}
		select {
		case out <- Read{Plate: it.Plate, Confidence: it.Confidence, Lane: it.Lane, At: time.Now()}:
		case <-ctx.Done():
			return nil
		}
	}
	for {
		select {
		case r := <-m.feed:
			select {
			case out <- r:
			case <-ctx.Done():
				return nil
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// Health is always ok.
func (m *MockReader) Health(context.Context) driver.Health {
	return driver.Health{State: driver.StateOK}
}

// Close is a no-op.
func (m *MockReader) Close() error { return nil }
