// Package driver defines the hardware driver interface of the agent (design
// section 7.1). Drivers are registered through an explicit slice in
// cmd/openbekci-agent/drivers.go; there are no init() side effects.
package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Errors drivers return for the two optional halves of the interface.
var (
	// ErrNoEvents is returned by Subscribe of output-only drivers (relays).
	ErrNoEvents = errors.New("driver: no events (output only)")
	// ErrNotSupported is returned by Open of input-only drivers (cameras).
	ErrNotSupported = errors.New("driver: operation not supported")
)

// Presentation is something a reader showed to a point.
type Presentation struct {
	Instance   string         // driver instance name from agent.yaml
	Channel    string         // lane/reader within the instance ("" = default)
	Kind       string         // "plate" | "visitor_qr" | "tag" | "pin"
	Value      string         // raw; the agent normalizes (plate) or hashes (qr/tag/pin)
	Confidence float64        // 0..1, 1 when not applicable
	At         time.Time      // reader's time if reliable, else receipt time
	RawRef     string         // opaque local reference, e.g. snapshot file name
	Detail     map[string]any // small, non-personal (lane, direction hint)
}

// Health states.
const (
	StateOK       = "ok"
	StateDegraded = "degraded"
	StateDown     = "down"
	StateMissing  = "missing"
)

// Health is a driver instance's state.
type Health struct {
	State  string // "ok" | "degraded" | "down" | "missing"
	Detail string // short human text, no personal data
}

// Driver is one configured hardware instance.
type Driver interface {
	// Open pulses/opens the physical point; returns after the hardware
	// accepted the command or failed; honours ctx cancellation.
	Open(ctx context.Context, channel string) error
	// Subscribe streams presentations until ctx ends. Output-only drivers
	// (relays) return ErrNoEvents immediately.
	Subscribe(ctx context.Context, out chan<- Presentation) error
	Health(ctx context.Context) Health
	Close() error
}

// SafeStater is implemented by output drivers that can force their hardware
// into the safe (closed) state. The agent calls it once per instance at
// startup, before any presentation is handled: an agent killed mid-pulse
// (SIGKILL, power loss) can leave a relay latched open.
type SafeStater interface {
	SafeState(ctx context.Context) error
}

// Factory builds an instance from its section of agent.yaml.
type Factory func(name string, cfg map[string]any, log *slog.Logger) (Driver, error)

// Registration declares a driver type.
type Registration struct {
	Type   string
	New    Factory
	Schema string // JSON Schema of cfg (documentation; validation is in New)
}

// Find returns the registration of a type.
func Find(regs []Registration, typ string) (Registration, bool) {
	for _, r := range regs {
		if r.Type == typ {
			return r, true
		}
	}
	return Registration{}, false
}

// DecodeConfig decodes a driver's cfg map into out, rejecting unknown keys.
func DecodeConfig(cfg map[string]any, out any) error {
	raw, err := json.Marshal(normalizeYAML(cfg))
	if err != nil {
		return fmt.Errorf("driver config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("driver config: %w", err)
	}
	return nil
}

// normalizeYAML converts map[any]any (as some YAML decoders produce) into
// map[string]any so the value can be marshalled as JSON.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalizeYAML(e)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[fmt.Sprint(k)] = normalizeYAML(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeYAML(e)
		}
		return out
	}
	return v
}
