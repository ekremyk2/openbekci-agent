package relay

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

// GPIOChannel selects a line of the GPIO chip.
type GPIOChannel struct {
	Line      int  `json:"line"`
	ActiveLow bool `json:"active_low,omitempty"`
}

// GPIOConfig is the gpio section of the relay driver (libgpiod character
// device on a Raspberry Pi).
type GPIOConfig struct {
	Chip     string                 `json:"chip"`
	Channels map[string]GPIOChannel `json:"channels"`
}

// ErrGPIOUnsupported is returned by the GPIO stub.
var ErrGPIOUnsupported = errors.New("gpio relay is not implemented in this build")

// gpioSwitch is a stub: the configuration is validated so that
// `config check` works everywhere, but switching reports ErrGPIOUnsupported and
// Health reports "down". The libgpiod character-device implementation is a
// follow-up that only has to replace this type.
type gpioSwitch struct{ cfg GPIOConfig }

func newGPIO(cfg GPIOConfig) (*gpioSwitch, error) {
	if cfg.Chip == "" {
		return nil, errors.New("gpio: chip required")
	}
	if len(cfg.Channels) == 0 {
		return nil, errors.New("gpio: no channels")
	}
	for name, c := range cfg.Channels {
		if c.Line < 0 {
			return nil, fmt.Errorf("gpio channel %q: negative line", name)
		}
	}
	return &gpioSwitch{cfg: cfg}, nil
}

func (g *gpioSwitch) Channels() []string { return sortedKeys(g.cfg.Channels) }

func (g *gpioSwitch) On(context.Context, string) error  { return ErrGPIOUnsupported }
func (g *gpioSwitch) Off(context.Context, string) error { return ErrGPIOUnsupported }

func (g *gpioSwitch) Health(context.Context) driver.Health {
	return driver.Health{State: driver.StateDown, Detail: ErrGPIOUnsupported.Error()}
}

func (g *gpioSwitch) Close() error { return nil }
