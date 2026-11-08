// Package relay is the generic dry-contact relay driver (design 7.3a): output
// only. A pulse is "on", wait pulse_ms, "off"; "off" is always attempted.
package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

// Defaults and bounds from the design.
const (
	DefaultPulseMS       = 800
	MinPulseMS           = 100
	MaxPulseMS           = 10_000
	DefaultMinIntervalMS = 2000
	offTimeout           = 3 * time.Second
)

// Errors.
var (
	// ErrTooSoon is returned when an open arrives before min_interval_ms.
	ErrTooSoon = errors.New("relay: open refused, previous open too recent")
	// ErrBusy is returned when a pulse is still in progress.
	ErrBusy = errors.New("relay: pulse in progress")
	// ErrUnknownChannel is returned for a channel that is not configured.
	ErrUnknownChannel = errors.New("relay: unknown channel")
)

// Config is the relay driver's section of agent.yaml.
type Config struct {
	Mode          string        `json:"mode"` // serial | http | gpio
	PulseMS       int           `json:"pulse_ms,omitempty"`
	MinIntervalMS *int          `json:"min_interval_ms,omitempty"`
	Serial        *SerialConfig `json:"serial,omitempty"`
	HTTP          *HTTPConfig   `json:"http,omitempty"`
	GPIO          *GPIOConfig   `json:"gpio,omitempty"`
}

// switcher is the hardware half: switch a channel on or off.
type switcher interface {
	On(ctx context.Context, channel string) error
	Off(ctx context.Context, channel string) error
	Health(ctx context.Context) driver.Health
	Channels() []string
	Close() error
}

// Driver is a relay instance.
type Driver struct {
	name     string
	log      *slog.Logger
	sw       switcher
	pulse    time.Duration
	interval time.Duration

	mu      sync.Mutex
	busy    bool
	lastEnd time.Time
}

// Registration registers the "relay" driver type.
var Registration = driver.Registration{
	Type: "relay",
	New: func(name string, cfg map[string]any, log *slog.Logger) (driver.Driver, error) {
		var c Config
		if err := driver.DecodeConfig(cfg, &c); err != nil {
			return nil, err
		}
		return New(name, c, log)
	},
	Schema: `{"type":"object","required":["mode"],"properties":{"mode":{"enum":["serial","http","gpio"]},"pulse_ms":{"type":"integer","minimum":100,"maximum":10000},"min_interval_ms":{"type":"integer","minimum":0},"serial":{"type":"object"},"http":{"type":"object"},"gpio":{"type":"object"}}}`,
}

// New validates cfg and builds a relay driver.
func New(name string, cfg Config, log *slog.Logger) (*Driver, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	pulse := cfg.PulseMS
	if pulse == 0 {
		pulse = DefaultPulseMS
	}
	if pulse < MinPulseMS || pulse > MaxPulseMS {
		return nil, fmt.Errorf("relay %s: pulse_ms must be %d-%d", name, MinPulseMS, MaxPulseMS)
	}
	interval := DefaultMinIntervalMS
	if cfg.MinIntervalMS != nil {
		interval = *cfg.MinIntervalMS
	}
	if interval < 0 {
		return nil, fmt.Errorf("relay %s: min_interval_ms must be >= 0", name)
	}
	var (
		sw  switcher
		err error
	)
	switch cfg.Mode {
	case "http":
		if cfg.HTTP == nil {
			return nil, fmt.Errorf("relay %s: mode http needs an http section", name)
		}
		sw, err = newHTTP(*cfg.HTTP)
	case "serial":
		if cfg.Serial == nil {
			return nil, fmt.Errorf("relay %s: mode serial needs a serial section", name)
		}
		sw, err = newSerial(*cfg.Serial)
	case "gpio":
		if cfg.GPIO == nil {
			return nil, fmt.Errorf("relay %s: mode gpio needs a gpio section", name)
		}
		sw, err = newGPIO(*cfg.GPIO)
	default:
		return nil, fmt.Errorf("relay %s: mode must be serial, http or gpio", name)
	}
	if err != nil {
		return nil, fmt.Errorf("relay %s: %w", name, err)
	}
	return newDriver(name, sw, time.Duration(pulse)*time.Millisecond, time.Duration(interval)*time.Millisecond, log), nil
}

func newDriver(name string, sw switcher, pulse, interval time.Duration, log *slog.Logger) *Driver {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Driver{name: name, log: log, sw: sw, pulse: pulse, interval: interval}
}

func (d *Driver) resolveChannel(ch string) (string, error) {
	chans := d.sw.Channels()
	if ch == "" {
		if len(chans) == 1 {
			return chans[0], nil
		}
		return "", fmt.Errorf("%w: channel required (have %v)", ErrUnknownChannel, chans)
	}
	for _, c := range chans {
		if c == ch {
			return ch, nil
		}
	}
	return "", fmt.Errorf("%w %q", ErrUnknownChannel, ch)
}

// Open pulses the channel: on, wait pulse_ms, off. off is attempted whatever
// happens (error, cancellation, panic) so a relay is never left latched.
func (d *Driver) Open(ctx context.Context, channel string) (err error) {
	ch, err := d.resolveChannel(channel)
	if err != nil {
		return err
	}
	d.mu.Lock()
	switch {
	case d.busy:
		d.mu.Unlock()
		return ErrBusy
	case d.interval > 0 && !d.lastEnd.IsZero() && time.Since(d.lastEnd) < d.interval:
		d.mu.Unlock()
		return ErrTooSoon
	}
	d.busy = true
	d.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("relay: panic during pulse: %v", r)
		}
		octx, cancel := context.WithTimeout(context.WithoutCancel(ctx), offTimeout)
		defer cancel()
		if offErr := d.sw.Off(octx, ch); offErr != nil {
			d.log.Error("relay off failed", "instance", d.name, "channel", ch, "error", offErr)
			if err == nil {
				err = fmt.Errorf("relay: off: %w", offErr)
			}
		}
		d.mu.Lock()
		d.busy = false
		d.lastEnd = time.Now()
		d.mu.Unlock()
	}()

	if err := d.sw.On(ctx, ch); err != nil {
		return fmt.Errorf("relay: on: %w", err)
	}
	t := time.NewTimer(d.pulse)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SafeState sends Off on every configured channel. An agent that died
// mid-pulse (SIGKILL, power loss) leaves a serial or HTTP relay with an
// explicit off latched open; this is called once at startup, before any
// pulse. Every channel is attempted whatever happens to the others.
func (d *Driver) SafeState(ctx context.Context) error {
	var errs []error
	for _, ch := range d.sw.Channels() {
		octx, cancel := context.WithTimeout(ctx, offTimeout)
		if err := d.sw.Off(octx, ch); err != nil {
			errs = append(errs, fmt.Errorf("channel %s: %w", ch, err))
		}
		cancel()
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("relay %s: safe-state sweep: %w", d.name, err)
	}
	return nil
}

// Subscribe reports ErrNoEvents: relays are output only.
func (d *Driver) Subscribe(context.Context, chan<- driver.Presentation) error {
	return driver.ErrNoEvents
}

// Health delegates to the hardware.
func (d *Driver) Health(ctx context.Context) driver.Health { return d.sw.Health(ctx) }

// Close releases the hardware.
func (d *Driver) Close() error { return d.sw.Close() }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
