package engine

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/store"
)

// wrapStore lets a test fail or observe single store calls.
type wrapStore struct {
	*store.Store
	recordErr   error
	releaseHook func() error
}

func (w *wrapStore) RecordAllow(ctx context.Context, ev protocol.Event, now time.Time, usesID string, maxUses int) error {
	if w.recordErr != nil {
		return w.recordErr
	}
	return w.Store.RecordAllow(ctx, ev, now, usesID, maxUses)
}

func (w *wrapStore) ReleaseHeld(ctx context.Context, id string) error {
	if w.releaseHook != nil {
		if err := w.releaseHook(); err != nil {
			return err
		}
	}
	return w.Store.ReleaseHeld(ctx, id)
}

// engineOver builds an engine over s, sharing the fixture's clock.
func (f *fixture) engineOver(s Store, open func(context.Context, string) error) *Engine {
	return New(Options{
		Store: s, Open: open,
		Clock:       func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now },
		LastContact: func() time.Time { return f.last },
	})
}

// crashCopy copies the state directory as it is on disk right now: what a
// restart after a crash or power loss would find.
func crashCopy(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	for _, name := range []string{store.DBFile, store.DBFile + "-wal", "store.key"} {
		in, err := os.Open(filepath.Join(src, name))
		if err != nil {
			continue
		}
		out, err := os.Create(filepath.Join(dst, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, in); err != nil {
			t.Fatal(err)
		}
		_ = in.Close()
		_ = out.Close()
	}
	return dst
}

func reopen(t *testing.T, dir string) *store.Store {
	t.Helper()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func singleUse(f *fixture) protocol.Entry {
	one := 1
	return f.add("plate", "34ABC123", func(e *protocol.Entry) { e.MaxUses = &one })
}

func (f *fixture) handle(e *Engine) (Result, error) {
	return e.Handle(bg, Presentation{PointID: f.point, Kind: "plate", Value: "34ABC123"})
}

func TestDecisionIsDurableBeforeThePulse(t *testing.T) {
	f := newFixture(t)
	e := singleUse(f)
	var inPulse struct {
		uses, depth int
		uploadable  int
	}
	eng := f.engineOver(f.st, func(ctx context.Context, _ string) error {
		inPulse.uses, _ = f.st.Uses(bg, e.ID)
		d, _ := f.st.QueueDepth(bg)
		inPulse.depth = int(d)
		b, _ := f.st.NextBatch(bg, 0, 10, 1<<20)
		inPulse.uploadable = len(b)
		return nil
	})
	r, err := f.handle(eng)
	if err != nil || !r.Opened {
		t.Fatalf("%+v %v", r, err)
	}
	if inPulse.uses != 1 || inPulse.depth != 1 {
		t.Fatalf("at pulse time uses=%d queued=%d, want both committed (1, 1)", inPulse.uses, inPulse.depth)
	}
	if inPulse.uploadable != 0 {
		t.Fatal("the event must stay on hold until the pulse is over")
	}
	if b, _ := f.st.NextBatch(bg, 0, 10, 1<<20); len(b) != 1 || b[0].Event.Decision != "allow" {
		t.Fatalf("after the pulse the allow event must upload: %+v", b)
	}
}

// Crash between commit and pulse: the credential is spent and the event is in
// the queue; after a restart the single-use credential cannot open again.
func TestCrashAfterCommitBeforePulse(t *testing.T) {
	f := newFixture(t)
	e := singleUse(f)
	var dir string
	eng := f.engineOver(f.st, func(context.Context, string) error {
		dir = crashCopy(t, f.dir) // the process dies right here
		return errors.New("crashed")
	})
	_, _ = f.handle(eng)

	s2 := reopen(t, dir)
	if n, _ := s2.Uses(bg, e.ID); n != 1 {
		t.Fatalf("uses after crash = %d, want 1 (consumed)", n)
	}
	b, _ := s2.NextBatch(bg, 0, 10, 1<<20)
	if len(b) != 1 || b[0].Event.Decision != "allow" || b[0].Event.CredentialID != e.ID {
		t.Fatalf("the decision was lost in the crash: %+v", b)
	}
	opened := 0
	eng2 := New(Options{Store: s2, Open: func(context.Context, string) error { opened++; return nil }, Clock: eng.o.Clock, LastContact: eng.o.LastContact})
	r, err := eng2.Handle(bg, Presentation{PointID: f.point, Kind: "plate", Value: "34ABC123"})
	if err != nil || r.Opened || opened != 0 || r.Event.Reason != ReasonUsedUp {
		t.Fatalf("single-use credential reused after a crash: %+v %v opened=%d", r, err, opened)
	}
}

// Crash after the pulse, before the event is released: nothing is lost and the
// credential stays spent.
func TestCrashAfterPulse(t *testing.T) {
	f := newFixture(t)
	e := singleUse(f)
	var dir string
	ws := &wrapStore{Store: f.st}
	ws.releaseHook = func() error {
		dir = crashCopy(t, f.dir)
		return errors.New("crashed") // ReleaseHeld never ran
	}
	eng := f.engineOver(ws, func(context.Context, string) error { return nil })
	if r, err := f.handle(eng); err != nil || !r.Opened {
		t.Fatalf("%+v %v", r, err)
	}
	s2 := reopen(t, dir)
	if n, _ := s2.Uses(bg, e.ID); n != 1 {
		t.Fatalf("uses = %d, want 1", n)
	}
	if b, _ := s2.NextBatch(bg, 0, 10, 1<<20); len(b) != 1 || b[0].Event.Decision != "allow" {
		t.Fatalf("event lost after a crash following the pulse: %+v", b)
	}
	// Without a restart the stale hold is released by the maintenance sweep.
	if b, _ := f.st.NextBatch(bg, 0, 10, 1<<20); len(b) != 0 {
		t.Fatal("event must still be held")
	}
	f.advance(store.HoldTimeout + time.Second)
	if err := f.st.ReleaseStale(bg, f.now); err != nil {
		t.Fatal(err)
	}
	if b, _ := f.st.NextBatch(bg, 0, 10, 1<<20); len(b) != 1 {
		t.Fatal("stale hold was not released")
	}
}

func TestDBErrorMeansNothingOpens(t *testing.T) {
	f := newFixture(t)
	singleUse(f)
	opened := 0
	ws := &wrapStore{Store: f.st, recordErr: errors.New("disk full")}
	eng := f.engineOver(ws, func(context.Context, string) error { opened++; return nil })
	if _, err := f.handle(eng); err == nil {
		t.Fatal("a decision that cannot be recorded must be an error")
	}
	if opened != 0 {
		t.Fatal("the gate opened although the decision could not be recorded")
	}
	if eng.LostEvents() != 1 {
		t.Fatalf("lost events = %d, want 1", eng.LostEvents())
	}
}

func TestFailedPulseDowngradesEventAndGivesTheUseBack(t *testing.T) {
	f := newFixture(t)
	e := singleUse(f)
	fail := true
	eng := f.engineOver(f.st, func(context.Context, string) error {
		if fail {
			return errors.New("relay down")
		}
		return nil
	})
	r, err := f.handle(eng)
	if err != nil || r.Opened || r.Event.Decision != "deny" || r.Event.Reason != ReasonDriverError {
		t.Fatalf("%+v %v", r, err)
	}
	b, _ := f.st.NextBatch(bg, 0, 10, 1<<20)
	if len(b) != 1 || b[0].Event.Decision != "deny" || b[0].Event.Reason != ReasonDriverError {
		t.Fatalf("queued event %+v", b)
	}
	if n, _ := f.st.Uses(bg, e.ID); n != 0 {
		t.Fatalf("a pulse that never happened must not burn the single-use credential (uses=%d)", n)
	}
	fail = false
	f.advance(30 * time.Second)
	if r, err := f.handle(eng); err != nil || !r.Opened {
		t.Fatalf("retry after the relay recovered: %+v %v", r, err)
	}
}
