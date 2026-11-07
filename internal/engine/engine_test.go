package engine

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/store"
)

var bg = context.Background()

type fixture struct {
	t      *testing.T
	st     *store.Store
	dir    string
	eng    *Engine
	mu     sync.Mutex
	now    time.Time
	last   time.Time
	opened []string
	openFn func() error
	ver    int64
	point  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := &fixture{t: t, st: st, dir: dir, now: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC), point: protocol.NewID()}
	f.last = f.now
	f.eng = New(Options{
		Store:       st,
		Clock:       func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now },
		LastContact: func() time.Time { return f.last },
		Open: func(ctx context.Context, pointID string) error {
			f.opened = append(f.opened, pointID)
			if f.openFn != nil {
				return f.openFn()
			}
			return nil
		},
	})
	return f
}

func (f *fixture) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

func (f *fixture) add(kind, value string, mod func(*protocol.Entry)) protocol.Entry {
	e := protocol.Entry{ID: protocol.NewID(), Kind: kind, Value: value, Points: []string{f.point}, ValidFrom: protocol.At(f.now.Add(-time.Hour))}
	if mod != nil {
		mod(&e)
	}
	f.ver++
	_, _, err := f.st.ApplyDelta(bg, protocol.Delta{FromVersion: f.ver - 1, ToVersion: f.ver, Changes: []protocol.Change{{Op: protocol.OpUpsert, Entry: &e}}})
	if err != nil {
		f.t.Fatal(err)
	}
	return e
}

func (f *fixture) present(kind, value string) Result {
	f.t.Helper()
	r, err := f.eng.Handle(bg, Presentation{PointID: f.point, Kind: kind, Value: value})
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func TestHandleAllowAndEvent(t *testing.T) {
	f := newFixture(t)
	e := f.add("plate", "34ABC123", nil)
	r := f.present("plate", "34 abc 123")
	if !r.Opened || r.Event.Decision != "allow" || r.Event.Reason != "match" || r.Event.CredentialID != e.ID {
		t.Fatalf("result %+v", r)
	}
	if r.Event.ObservedPlate != "34ABC123" || !protocol.IsUUIDv7(r.Event.ID) {
		t.Fatalf("event %+v", r.Event)
	}
	if len(f.opened) != 1 || f.opened[0] != f.point {
		t.Fatalf("opened %v", f.opened)
	}
	q, _ := f.st.NextBatch(bg, 0, 10, 1<<20)
	if len(q) != 1 || q[0].Event.ID != r.Event.ID {
		t.Fatalf("queue %+v", q)
	}
	if err := q[0].Event.Validate(); err != nil {
		t.Fatalf("event does not validate: %v", err)
	}
}

func TestHandleDenyUnknownIsLoggedAndDoesNotOpen(t *testing.T) {
	f := newFixture(t)
	r := f.present("plate", "06 ZZZ 999")
	if r.Opened || r.Event.Decision != "deny" || r.Event.Reason != "unknown" || r.Event.ObservedPlate != "06ZZZ999" {
		t.Fatalf("result %+v", r)
	}
	if len(f.opened) != 0 {
		t.Fatal("opened on deny")
	}
	if d, _ := f.st.QueueDepth(bg); d != 1 {
		t.Fatalf("depth %d", d)
	}
	// QR values are never stored in events.
	r = f.present("visitor_qr", "obk1.secret")
	if r.Event.ObservedPlate != "" || r.Event.Reason != "unknown" {
		t.Fatalf("qr event %+v", r.Event)
	}
}

func TestHandleDedupe(t *testing.T) {
	f := newFixture(t)
	f.add("plate", "34ABC123", nil)
	if r := f.present("plate", "34ABC123"); r.Suppressed || !r.Opened {
		t.Fatalf("first: %+v", r)
	}
	f.advance(9 * time.Second)
	if r := f.present("plate", "34-ABC-123"); !r.Suppressed {
		t.Fatalf("re-read within 10 s must be suppressed: %+v", r)
	}
	f.advance(2 * time.Second)
	if r := f.present("plate", "34ABC123"); r.Suppressed || !r.Opened {
		t.Fatalf("after window: %+v", r)
	}
	if len(f.opened) != 2 {
		t.Fatalf("opened %d times", len(f.opened))
	}
	if d, _ := f.st.QueueDepth(bg); d != 2 {
		t.Fatalf("suppressed read must not log; depth %d", d)
	}
}

func TestHandleSingleUse(t *testing.T) {
	f := newFixture(t)
	one := 1
	f.add("plate", "34ABC123", func(e *protocol.Entry) { e.MaxUses = &one })
	if r := f.present("plate", "34ABC123"); r.Event.Decision != "allow" {
		t.Fatalf("first use: %+v", r.Event)
	}
	f.advance(time.Minute)
	if r := f.present("plate", "34ABC123"); r.Event.Decision != "deny" || r.Event.Reason != "used_up" {
		t.Fatalf("second use: %+v", r.Event)
	}
}

func TestHandleWindowExpiresOffline(t *testing.T) {
	f := newFixture(t)
	f.add("plate", "34ABC123", func(e *protocol.Entry) {
		to := protocol.At(f.now.Add(time.Hour))
		e.ValidTo = &to
	})
	if r := f.present("plate", "34ABC123"); r.Event.Decision != "allow" {
		t.Fatal("inside window")
	}
	f.advance(2 * time.Hour)
	f.last = f.now // still connected; only the window moved
	if r := f.present("plate", "34ABC123"); r.Event.Decision != "deny" || r.Event.Reason != "outside_window" {
		t.Fatalf("after expiry: %+v", r.Event)
	}
}

func TestHandleStoppedAfterGrace(t *testing.T) {
	f := newFixture(t)
	f.add("plate", "34ABC123", nil)
	f.eng.SetSettings(Settings{GraceHours: 72})
	f.advance(72 * time.Hour)
	if f.eng.Stopped() {
		t.Fatal("exactly at the grace limit is still running")
	}
	if r := f.present("plate", "34ABC123"); r.Event.Decision != "allow" {
		t.Fatalf("at grace: %+v", r.Event)
	}
	f.advance(2 * time.Hour)
	if !f.eng.Stopped() {
		t.Fatal("must be stopped after grace")
	}
	r := f.present("plate", "34 ABC 123 ")
	if r.Opened || r.Event.Decision != "deny" || r.Event.Reason != "agent_stopped" || r.Event.ObservedPlate != "34ABC123" {
		t.Fatalf("stopped: %+v", r)
	}
	// Contact resumes it.
	f.last = f.now
	f.advance(11 * time.Second)
	if r := f.present("plate", "34ABC123"); r.Event.Decision != "allow" {
		t.Fatalf("after contact: %+v", r.Event)
	}
}

func TestHandleDriverError(t *testing.T) {
	f := newFixture(t)
	one := 1
	e := f.add("plate", "34ABC123", func(e *protocol.Entry) { e.MaxUses = &one })
	f.openFn = func() error { return errors.New("relay unreachable") }
	r := f.present("plate", "34ABC123")
	if r.Opened || r.Event.Decision != "deny" || r.Event.Reason != "driver_error" || r.Event.CredentialID != e.ID {
		t.Fatalf("%+v", r)
	}
	// A failed open must not consume a single-use credential.
	f.openFn = nil
	f.advance(time.Minute)
	if r := f.present("plate", "34ABC123"); r.Event.Decision != "allow" {
		t.Fatalf("retry after driver error: %+v", r.Event)
	}
}

func TestTolerantMatching(t *testing.T) {
	f := newFixture(t)
	f.add("plate", "34ABC123", nil)

	// exact (default): O/0 confusion is a miss.
	if r := f.present("plate", "34ABC1Z3"); r.Event.Reason != "unknown" {
		t.Fatalf("exact mode: %+v", r.Event)
	}
	f.eng.SetSettings(Settings{PlateMatch: PlateTolerant})
	f.advance(time.Minute)
	r := f.present("plate", "34A8C123") // B read as 8
	if !r.Opened || r.Event.Reason != "match" {
		t.Fatalf("tolerant: %+v", r.Event)
	}
	var d map[string]any
	_ = json.Unmarshal(r.Event.Detail, &d)
	if d["tolerant"] != true {
		t.Fatalf("detail.tolerant missing: %s", r.Event.Detail)
	}
	// Not an OCR pair -> no match.
	f.advance(time.Minute)
	if r := f.present("plate", "34ABC124"); r.Event.Reason != "unknown" {
		t.Fatalf("non-confusable: %+v", r.Event)
	}
	// Exact match beats tolerant: no tolerant flag.
	f.add("plate", "55XY0Z12", nil)
	f.advance(time.Minute)
	if r := f.present("plate", "55XY0Z12"); r.Event.Reason != "match" || r.Event.Detail != nil {
		t.Fatalf("exact match: %+v", r.Event)
	}
	// Ambiguous: AB8C is one OCR step from both A88C and ABBC, so nothing opens.
	f.add("plate", "A88C", nil)
	f.add("plate", "ABBC", nil)
	f.advance(time.Minute)
	if r := f.present("plate", "AB8C"); r.Opened || r.Event.Reason != "unknown" {
		t.Fatalf("ambiguous must not open: %+v", r.Event)
	}
}

func TestTagKind(t *testing.T) {
	f := newFixture(t)
	f.add("tag", "abcdef", nil)
	if r := f.present("tag", " ABCDEF "); !r.Opened {
		t.Fatalf("%+v", r.Event)
	}
	if r := f.present("unheard_of", "x"); r.Event.Reason != "unknown" {
		t.Fatalf("%+v", r.Event)
	}
}

func TestStoppedWallClockGoingBackwardsIsSuspectNotContact(t *testing.T) {
	f := newFixture(t)
	if f.eng.Stopped() {
		t.Fatal("stopped right after contact")
	}
	f.advance(-30 * time.Second) // NTP step inside the tolerance
	if f.eng.Stopped() {
		t.Fatal("a small step back must not stop the agent")
	}
	f.advance(-2 * time.Hour) // RTC-less Pi restored a stale time
	if !f.eng.Stopped() {
		t.Fatal("a wall clock behind the last contact must count as suspect (stopped), not as contact")
	}
}

func TestStoppedUsesTheLargerOfWallAndMonotonicAge(t *testing.T) {
	f := newFixture(t)
	var mono time.Duration
	f.eng.o.ContactAge = func() (time.Duration, bool) { return mono, true }
	f.advance(time.Hour)
	mono = 80 * time.Hour // the process knows 80 h passed although the wall clock says 1 h
	if !f.eng.Stopped() {
		t.Fatal("the monotonic age must be able to stop the agent")
	}
	mono = 2 * time.Hour
	f.advance(72 * time.Hour) // wall age 73 h
	if !f.eng.Stopped() {
		t.Fatal("the wall age must still count")
	}
}
