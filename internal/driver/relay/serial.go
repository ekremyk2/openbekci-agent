package relay

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

// SerialChannel holds the hex-encoded frames of one channel, e.g. a USB relay
// board's documented on/off frames: on "A00101A2", off "A00100A1".
type SerialChannel struct {
	On  string `json:"on"`
	Off string `json:"off"`
}

// SerialConfig is the serial section of the relay driver.
type SerialConfig struct {
	Port     string                   `json:"port"`
	Baud     int                      `json:"baud,omitempty"`
	Channels map[string]SerialChannel `json:"channels"`
}

type frames struct{ on, off []byte }

// serialSwitch writes the configured frames to the serial device file. This
// release does not configure the line speed itself: use a CDC-ACM board (baud
// is ignored) or set the speed with the OS (stty/udev) beforehand. A native
// termios/Win32 implementation can replace openPort without touching the rest.
type serialSwitch struct {
	cfg      SerialConfig
	frames   map[string]frames
	openPort func(path string) (io.WriteCloser, error)
}

func newSerial(cfg SerialConfig) (*serialSwitch, error) {
	if cfg.Port == "" {
		return nil, errors.New("serial: port required")
	}
	if len(cfg.Channels) == 0 {
		return nil, errors.New("serial: no channels")
	}
	fr := map[string]frames{}
	for name, c := range cfg.Channels {
		on, err := parseHex(c.On)
		if err != nil {
			return nil, fmt.Errorf("serial channel %q on: %w", name, err)
		}
		off, err := parseHex(c.Off)
		if err != nil {
			return nil, fmt.Errorf("serial channel %q off: %w", name, err)
		}
		fr[name] = frames{on, off}
	}
	return &serialSwitch{cfg: cfg, frames: fr, openPort: func(p string) (io.WriteCloser, error) {
		return os.OpenFile(p, os.O_WRONLY, 0)
	}}, nil
}

func parseHex(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	if s == "" {
		return nil, errors.New("empty frame")
	}
	return hex.DecodeString(s)
}

func (s *serialSwitch) Channels() []string { return sortedKeys(s.frames) }

func (s *serialSwitch) write(frame []byte) error {
	w, err := s.openPort(s.cfg.Port)
	if err != nil {
		return err
	}
	_, werr := w.Write(frame)
	if cerr := w.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

func (s *serialSwitch) On(_ context.Context, ch string) error  { return s.write(s.frames[ch].on) }
func (s *serialSwitch) Off(_ context.Context, ch string) error { return s.write(s.frames[ch].off) }

func (s *serialSwitch) Health(context.Context) driver.Health {
	if _, err := os.Stat(s.cfg.Port); err != nil {
		return driver.Health{State: driver.StateDown, Detail: "serial port not present"}
	}
	return driver.Health{State: driver.StateOK}
}

func (s *serialSwitch) Close() error { return nil }
