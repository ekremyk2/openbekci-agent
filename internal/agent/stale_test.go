package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/config"
	"github.com/openbekci/openbekci-agent/internal/engine"
	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/store"
	"github.com/openbekci/openbekci-agent/internal/transport"
)

// stubSession records what the agent sends.
type stubSession struct {
	mu   sync.Mutex
	sent []protocol.Envelope
}

func (s *stubSession) Send(_ context.Context, env protocol.Envelope) error {
	s.mu.Lock()
	s.sent = append(s.sent, env)
	s.mu.Unlock()
	return nil
}

func (s *stubSession) Receive(ctx context.Context) (protocol.Envelope, error) {
	<-ctx.Done()
	return protocol.Envelope{}, ctx.Err()
}
func (s *stubSession) Ping(context.Context) error { return nil }
func (s *stubSession) Mode() string               { return transport.ModeWebSocket }
func (s *stubSession) Close(int, string) error    { return nil }

func (s *stubSession) lastAck(t *testing.T) protocol.Ack {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sent) - 1; i >= 0; i-- {
		if s.sent[i].Type == protocol.TypeAck {
			p, err := s.sent[i].Decode()
			if err != nil {
				t.Fatal(err)
			}
			return *p.(*protocol.Ack)
		}
	}
	t.Fatal("no ack sent")
	return protocol.Ack{}
}

type staleFixture struct {
	t    *testing.T
	st   *store.Store
	s    *sessState
	sess *stubSession
}

func newStaleFixture(t *testing.T) *staleFixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	a, err := New(Options{Config: &config.Config{StateDir: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	a.st = st
	a.eng = engine.New(engine.Options{Store: st})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sess := &stubSession{}
	return &staleFixture{t: t, st: st, sess: sess, s: &sessState{a: a, sess: sess, ctx: ctx, cancel: cancel, ready: make(chan struct{}), wantSnap: -1, wantCfg: -1, inflight: map[string]inflightBatch{}}}
}

func (f *staleFixture) snapshot(version int64, plates ...string) protocol.Ack {
	f.t.Helper()
	es := []protocol.Entry{}
	for i, p := range plates {
		es = append(es, protocol.Entry{ID: uidN(int(version)*100 + i), Kind: "plate", Value: p, Points: []string{pointID}, ValidFrom: protocol.At(time.Now().Add(-time.Hour))})
	}
	m := &protocol.Snapshot{Version: version, Part: 1, Parts: 1, Site: protocol.Site{Timezone: "UTC"}, Entries: es}
	env, err := protocol.New(protocol.TypeSnapshot, m, time.Now())
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.s.onSnapshot(env, m); err != nil {
		f.t.Fatal(err)
	}
	return f.sess.lastAck(f.t)
}

func (f *staleFixture) version() int64 {
	v, _ := f.st.SnapshotVersion(context.Background())
	return v
}

func uidN(n int) string {
	s := "000000000000" + itoa(int64(n))
	return "0192f1a0-0000-7000-8000-" + s[len(s)-12:]
}

func TestStaleSnapshotIsIgnoredUnlessRequested(t *testing.T) {
	f := newStaleFixture(t)
	if a := f.snapshot(10, "34ABC123"); a.Status != protocol.AckOK {
		t.Fatalf("v10: %+v", a)
	}

	// An unsolicited older snapshot (lagging replica, replay) must not roll back.
	if a := f.snapshot(3); a.Status != protocol.AckStale {
		t.Fatalf("unsolicited v3: %q, want stale", a.Status)
	}
	if v := f.version(); v != 10 {
		t.Fatalf("version %d after a stale snapshot, want 10", v)
	}
	if n, _ := f.st.EntryCount(context.Background()); n != 1 {
		t.Fatalf("a stale snapshot changed the allow-list (%d entries)", n)
	}

	// After the agent itself acked a gap, a replacement is accepted even if lower.
	d := &protocol.Delta{FromVersion: 50, ToVersion: 51, Changes: []protocol.Change{}}
	env, _ := protocol.New(protocol.TypeDelta, d, time.Now())
	if err := f.s.onDelta(env, d); err != nil {
		t.Fatal(err)
	}
	if a := f.sess.lastAck(t); a.Status != protocol.AckGap {
		t.Fatalf("delta ack %q", a.Status)
	}
	if a := f.snapshot(7, "06XYZ999"); a.Status != protocol.AckOK {
		t.Fatalf("snapshot after gap: %+v", a)
	}
	if v := f.version(); v != 7 {
		t.Fatalf("version %d, want 7", v)
	}
	// The permission was consumed: the next older one is stale again.
	if a := f.snapshot(2); a.Status != protocol.AckStale {
		t.Fatalf("v2 after the resync: %q", a.Status)
	}
}

func TestStaleSnapshotAcceptedWhenHelloAnnouncedIt(t *testing.T) {
	f := newStaleFixture(t)
	f.snapshot(10, "34ABC123")
	f.s.helloKnown, f.s.wantSnap = true, 4 // server DB restore: hello says 4
	if a := f.snapshot(3); a.Status != protocol.AckStale {
		t.Fatalf("v3 is not what hello announced: %q", a.Status)
	}
	if a := f.snapshot(4, "06XYZ999"); a.Status != protocol.AckOK || f.version() != 4 {
		t.Fatalf("announced version must be accepted: %+v version %d", a, f.version())
	}
}

func TestRequestSnapshotCommandAllowsReplacement(t *testing.T) {
	f := newStaleFixture(t)
	f.snapshot(10, "34ABC123")
	c := &protocol.Command{Command: protocol.CmdRequestSnapshot}
	env, _ := protocol.New(protocol.TypeCommand, c, time.Now())
	if err := f.s.onCommand(env, c); err != nil {
		t.Fatal(err)
	}
	if a := f.snapshot(5, "06XYZ999"); a.Status != protocol.AckOK || f.version() != 5 {
		t.Fatalf("%+v version %d", a, f.version())
	}
}
