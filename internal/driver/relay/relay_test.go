package relay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

type hit struct {
	path, query string
	at          time.Time
}

type recorder struct {
	mu   sync.Mutex
	hits []hit
	code int
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.hits = append(r.hits, hit{req.URL.Path, req.URL.RawQuery, time.Now()})
	code := r.code
	r.mu.Unlock()
	if code != 0 {
		w.WriteHeader(code)
	}
}

func (r *recorder) snapshot() []hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hit(nil), r.hits...)
}

func httpDriver(t *testing.T, base string, off bool, pulse int) *Driver {
	t.Helper()
	ch := HTTPChannel{OnURL: base + "/relay/0?turn=on&timer=1"}
	if off {
		ch.OffURL = base + "/relay/0?turn=off"
	}
	zero := 0
	d, err := New("gate-relay", Config{Mode: "http", PulseMS: pulse, MinIntervalMS: &zero, HTTP: &HTTPConfig{Channels: map[string]HTTPChannel{"1": ch}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestShellyStyleOpenSelfResets(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	d := httpDriver(t, srv.URL, false, 100)
	if err := d.Open(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	h := rec.snapshot()
	if len(h) != 1 || h[0].path != "/relay/0" || h[0].query != "turn=on&timer=1" {
		t.Fatalf("hits %+v", h)
	}
	// Default channel works with a single channel.
	if err := d.Open(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestGenericOnWaitOff(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	d := httpDriver(t, srv.URL, true, 150)
	if err := d.Open(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	h := rec.snapshot()
	if len(h) != 2 || h[0].query != "turn=on&timer=1" || h[1].query != "turn=off" {
		t.Fatalf("hits %+v", h)
	}
	if gap := h[1].at.Sub(h[0].at); gap < 140*time.Millisecond {
		t.Fatalf("pulse too short: %v", gap)
	}
}

func TestOffAttemptedOnCancelAndOnFailure(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	d := httpDriver(t, srv.URL, true, 5000)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	err := d.Open(ctx, "1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	h := rec.snapshot()
	if len(h) != 2 || h[1].query != "turn=off" {
		t.Fatalf("off must be sent after cancel: %+v", h)
	}

	// Device failing on "on": the error is reported and off is still attempted.
	rec2 := &recorder{code: 500}
	srv2 := httptest.NewServer(rec2)
	defer srv2.Close()
	d2 := httpDriver(t, srv2.URL, true, 100)
	if err := d2.Open(context.Background(), "1"); err == nil {
		t.Fatal("expected error")
	}
	if h := rec2.snapshot(); len(h) != 2 {
		t.Fatalf("off must follow a failed on: %+v", h)
	}
}

func TestMinIntervalAndBusy(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	iv := 2000
	d, err := New("r", Config{Mode: "http", PulseMS: 100, MinIntervalMS: &iv, HTTP: &HTTPConfig{Channels: map[string]HTTPChannel{"1": {OnURL: srv.URL + "/on"}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = d.Open(context.Background(), "1") }()
	time.Sleep(30 * time.Millisecond)
	if err := d.Open(context.Background(), "1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent open: %v", err)
	}
	wg.Wait()
	if err := d.Open(context.Background(), "1"); !errors.Is(err, ErrTooSoon) {
		t.Fatalf("too soon: %v", err)
	}
	if got := len(rec.snapshot()); got != 1 {
		t.Fatalf("device hit %d times", got)
	}
}

func TestUnknownChannelAndPublicAddressRefused(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	d := httpDriver(t, srv.URL, false, 100)
	if err := d.Open(context.Background(), "9"); !errors.Is(err, ErrUnknownChannel) {
		t.Fatalf("err = %v", err)
	}
	// A public IP literal must be refused at dial time.
	pub, err := New("r", Config{Mode: "http", PulseMS: 100, HTTP: &HTTPConfig{Channels: map[string]HTTPChannel{"1": {OnURL: "http://8.8.8.8/relay/0?turn=on", TimeoutMS: 500}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Open(context.Background(), "1"); err == nil {
		t.Fatal("public address must be refused")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  map[string]any
	}{
		{"no mode", map[string]any{}},
		{"bad mode", map[string]any{"mode": "wifi"}},
		{"pulse too small", map[string]any{"mode": "gpio", "pulse_ms": 10, "gpio": map[string]any{"chip": "gpiochip0", "channels": map[string]any{"1": map[string]any{"line": 17}}}}},
		{"unknown key", map[string]any{"mode": "http", "bogus": 1}},
		{"http no channels", map[string]any{"mode": "http", "http": map[string]any{"channels": map[string]any{}}}},
		{"http bad url", map[string]any{"mode": "http", "http": map[string]any{"channels": map[string]any{"1": map[string]any{"on_url": "ftp://x"}}}}},
		{"serial bad hex", map[string]any{"mode": "serial", "serial": map[string]any{"port": "/dev/ttyUSB0", "channels": map[string]any{"1": map[string]any{"on": "ZZ", "off": "00"}}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Registration.New("x", tc.cfg, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	ok, err := Registration.New("x", map[string]any{"mode": "serial", "pulse_ms": 800, "serial": map[string]any{"port": "/dev/ttyUSB0", "baud": 9600,
		"channels": map[string]any{"1": map[string]any{"on": "A00101A2", "off": "A00100A1"}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h := ok.Health(context.Background()); h.State != driver.StateDown {
		t.Fatalf("missing port must be down: %+v", h)
	}
}

func TestSerialFramesAndGPIOStub(t *testing.T) {
	s, err := newSerial(SerialConfig{Port: "X", Channels: map[string]SerialChannel{"1": {On: "A0 01 01 A2", Off: "A00100A1"}}})
	if err != nil {
		t.Fatal(err)
	}
	var wrote [][]byte
	s.openPort = func(string) (io.WriteCloser, error) { return &fakePort{&wrote}, nil }
	zero := 0
	d := newDriver("s", s, 100*time.Millisecond, time.Duration(zero), nil)
	if err := d.Open(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	if len(wrote) != 2 || string(wrote[0]) != "\xa0\x01\x01\xa2" || string(wrote[1]) != "\xa0\x01\x00\xa1" {
		t.Fatalf("frames %x", wrote)
	}

	g, err := newGPIO(GPIOConfig{Chip: "gpiochip0", Channels: map[string]GPIOChannel{"1": {Line: 17}}})
	if err != nil {
		t.Fatal(err)
	}
	gd := newDriver("g", g, 100*time.Millisecond, 0, nil)
	if err := gd.Open(context.Background(), "1"); !errors.Is(err, ErrGPIOUnsupported) {
		t.Fatalf("gpio stub: %v", err)
	}
	if err := gd.Subscribe(context.Background(), nil); !errors.Is(err, driver.ErrNoEvents) {
		t.Fatalf("subscribe: %v", err)
	}
}

type fakePort struct{ out *[][]byte }

func (f *fakePort) Write(b []byte) (int, error) {
	*f.out = append(*f.out, append([]byte(nil), b...))
	return len(b), nil
}
func (f *fakePort) Close() error { return nil }
