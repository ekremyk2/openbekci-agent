package transport

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/fakeserver"
	"github.com/openbekci/openbekci-agent/internal/protocol"
)

func TestBackoffSequenceAndJitter(t *testing.T) {
	b := DefaultBackoff()
	want := []float64{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		d := b.Next().Seconds()
		if d < w*0.8-1e-9 || d > w*1.2+1e-9 {
			t.Fatalf("step %d: %.2fs outside %.0fs +/-20%%", i, d, w)
		}
	}
	b.Reset()
	if d := b.Next().Seconds(); d > 1.2 {
		t.Fatalf("after reset: %.2fs", d)
	}
	// Extremes of the jitter range.
	lo, hi := DefaultBackoff(), DefaultBackoff()
	lo.Rand, hi.Rand = func() float64 { return 0 }, func() float64 { return 0.999999 }
	if lo.Next() != 800*time.Millisecond || hi.Next() < 1199*time.Millisecond {
		t.Fatal("jitter range")
	}
}

type env struct {
	fs     *fakeserver.Server
	client *Client
	token  atomic.Value
}

func newEnv(t *testing.T, mod func(*Options)) *env {
	t.Helper()
	fs := fakeserver.New(t)
	e := &env{fs: fs}
	hc, err := NewHTTPClient(fs.CACertFile())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Enrol(context.Background(), hc, fs.URL+"/v1/agent/enrol", protocol.EnrolRequest{EnrolmentToken: fs.NewEnrolToken(), Hostname: "h", Platform: "test", AgentVersion: "0"})
	if err != nil {
		t.Fatal(err)
	}
	e.token.Store(resp.AgentToken)
	o := Options{
		WSURL: resp.WSURL, PollURL: resp.PollURL, CAFile: fs.CACertFile(),
		Token:    func() (string, error) { return e.token.Load().(string), nil },
		Backoff:  Backoff{Min: 10 * time.Millisecond, Max: 40 * time.Millisecond, Factor: 2, Jitter: 0.2},
		PollWait: 1, HealthyAfter: time.Hour,
	}
	if mod != nil {
		mod(&o)
	}
	e.client, err = NewClient(o)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func hello(t *testing.T) protocol.Envelope {
	t.Helper()
	h, err := protocol.New(protocol.TypeHello, protocol.AgentHello{From: "agent", AgentID: "a", AgentVersion: "0", ProtocolVersions: []int{1}, Drivers: []protocol.DriverState{}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// session handler: send hello, then forward received envelopes.
func forward(t *testing.T, modes chan<- string, got chan<- protocol.Envelope) Handler {
	return func(ctx context.Context, s Session) error {
		if err := s.Send(ctx, hello(t)); err != nil {
			return err
		}
		select {
		case modes <- s.Mode():
		default:
		}
		for {
			m, err := s.Receive(ctx)
			if err != nil {
				return err
			}
			select {
			case got <- m:
			default:
			}
		}
	}
}

func run(e *env, h Handler) (cancel func(), done <-chan error) {
	ctx, c := context.WithCancel(context.Background())
	d := make(chan error, 1)
	go func() { d <- e.client.Run(ctx, h) }()
	return c, d
}

func TestWebSocketSessionAndReconnect(t *testing.T) {
	e := newEnv(t, nil)
	modes, got := make(chan string, 8), make(chan protocol.Envelope, 32)
	cancel, done := run(e, forward(t, modes, got))
	defer cancel()

	if m := <-modes; m != ModeWebSocket {
		t.Fatalf("mode %s", m)
	}
	select {
	case m := <-got:
		if m.Type != protocol.TypeHello {
			t.Fatalf("first message %s", m.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no server hello")
	}
	// A dropped connection is re-established with a new hello.
	e.fs.DropConnection()
	if !e.fs.Eventually(5*time.Second, func() bool { _, _, _, c := e.fs.Counters(); return c >= 2 }) {
		t.Fatal("no reconnect")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
}

func TestRevokedStopsWithoutRetry(t *testing.T) {
	e := newEnv(t, nil)
	modes, got := make(chan string, 8), make(chan protocol.Envelope, 32)
	cancel, done := run(e, forward(t, modes, got))
	defer cancel()
	<-modes
	e.fs.Revoke()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRevoked) {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after revocation")
	}
	attempts := e.fs.UpgradeAttempts()
	time.Sleep(150 * time.Millisecond)
	if e.fs.UpgradeAttempts() != attempts {
		t.Fatal("retried after revocation")
	}

}

// A bare 401 (WAF, captive portal, auth-cache miss) never ends Run and never
// means revoked: it is reported and retried, and a session resumes once the
// server accepts the token again.
func TestBareUnauthorizedIsRetriedNotRevoked(t *testing.T) {
	var unauth atomic.Int32
	e := newEnv(t, func(o *Options) {
		o.UnauthorizedRetry = 50 * time.Millisecond
		o.OnUnauthorized = func(error) { unauth.Add(1) }
	})
	e.fs.RejectAuth(true)
	modes, got := make(chan string, 8), make(chan protocol.Envelope, 32)
	cancel, done := run(e, forward(t, modes, got))
	defer cancel()
	if !e.fs.Eventually(5*time.Second, func() bool { return unauth.Load() >= 3 }) {
		t.Fatalf("expected repeated 401 reports, got %d", unauth.Load())
	}
	select {
	case err := <-done:
		t.Fatalf("Run ended on a bare 401: %v", err)
	default:
	}
	e.fs.RejectAuth(false)
	select {
	case <-modes:
	case <-time.After(5 * time.Second):
		t.Fatal("no session after the server accepted the token again")
	}
}

func TestLongPollFallbackAndWebSocketRetry(t *testing.T) {
	var modeChanges atomic.Int32
	e := newEnv(t, func(o *Options) {
		o.WSRetry = 400 * time.Millisecond
		o.OnModeChange = func(string) { modeChanges.Add(1) }
	})
	e.fs.FailUpgrades(-1) // proxy that never upgrades
	modes, got := make(chan string, 16), make(chan protocol.Envelope, 64)
	cancel, done := run(e, forward(t, modes, got))
	defer cancel()

	select {
	case m := <-modes:
		if m != ModePoll {
			t.Fatalf("first session mode %s, want poll", m)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no poll session")
	}
	if n := e.fs.UpgradeAttempts(); n != 3 {
		t.Fatalf("%d upgrade attempts before fallback, want 3", n)
	}
	// Server hello arrives over long-poll.
	select {
	case m := <-got:
		if m.Type != protocol.TypeHello {
			t.Fatalf("%s", m.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no hello over poll")
	}
	// A server push is delivered by a pending long poll.
	e.fs.Upsert(protocol.Entry{ID: "0192f1a0-0000-7000-8000-000000000c01", Kind: "plate", Value: "X1", Points: []string{"0192f1a0-0000-7000-8000-0000000000b1"}, ValidFrom: protocol.Now()})
	deadline := time.After(5 * time.Second)
	for seen := false; !seen; {
		select {
		case m := <-got:
			seen = m.Type == protocol.TypeDelta
		case <-deadline:
			t.Fatal("no delta over poll")
		}
	}
	// After the retry period the client probes WebSocket again; one failed
	// probe sends it back to poll, a good one makes it leave poll for good.
	before := e.fs.UpgradeAttempts()
	if !e.fs.Eventually(5*time.Second, func() bool { return e.fs.UpgradeAttempts() > before }) {
		t.Fatal("no websocket retry")
	}
	e.fs.FailUpgrades(0)
	deadline = time.After(10 * time.Second)
	for ws := false; !ws; {
		select {
		case m := <-modes:
			ws = m == ModeWebSocket
		case <-deadline:
			t.Fatal("never returned to websocket")
		}
	}
	if modeChanges.Load() < 2 {
		t.Fatalf("mode change callbacks: %d", modeChanges.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Log(err)
	}
}

func TestUntrustedCertificateIsRejected(t *testing.T) {
	fs := fakeserver.New(t)
	c, err := NewClient(Options{WSURL: fs.WSURL(), PollURL: fs.PollURL(), Token: func() (string, error) { return "x", nil }}) // no ca_file
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.dialWS(ctx)
	if err == nil {
		t.Fatal("connected to a server with an unknown CA")
	}
	if isProxyLike(err) {
		t.Fatalf("a TLS error must not count as a proxy failure: %v", err)
	}
	if _, err := NewClient(Options{WSURL: "ws://insecure.example/ws", PollURL: "https://x/poll", Token: func() (string, error) { return "", nil }}); err == nil {
		t.Fatal("plain ws:// accepted")
	}
}

func TestEnrolAndRotate(t *testing.T) {
	fs := fakeserver.New(t)
	hc, _ := NewHTTPClient(fs.CACertFile())
	tok := fs.NewEnrolToken()
	req := protocol.EnrolRequest{EnrolmentToken: tok, Hostname: "pi-gate", Platform: "linux/arm64", AgentVersion: "0.3.0"}
	resp, err := Enrol(context.Background(), hc, fs.URL+"/v1/orgs/o/sites/s/agents:enrol", req)
	if err != nil || resp.AgentToken == "" || resp.ProtocolVersions[0] != 1 {
		t.Fatalf("enrol: %+v %v", resp, err)
	}
	if _, err := Enrol(context.Background(), hc, fs.URL+"/v1/agent/enrol", req); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token reuse: %v", err)
	}
	next, err := Rotate(context.Background(), hc, fs.RotateURL(), resp.AgentToken)
	if err != nil || next == resp.AgentToken {
		t.Fatalf("rotate: %q %v", next, err)
	}
	// The old token still works for 10 minutes, a bogus one gets 401.
	if _, err := Rotate(context.Background(), hc, fs.RotateURL(), resp.AgentToken); err != nil {
		t.Fatalf("old token inside grace: %v", err)
	}
	if _, err := Rotate(context.Background(), hc, fs.RotateURL(), "obk_agt_bogus"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bogus token: %v", err)
	}
}
