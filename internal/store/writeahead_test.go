package store

import (
	"errors"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

func allowEvent(n int) protocol.Event {
	return protocol.Event{ID: protocol.NewID(), PointID: uid(100), Decision: protocol.DecisionAllow, Reason: "match", CredentialID: uid(n), OccurredAt: protocol.Now()}
}

func TestRecordAllowSpendsTheUseAtomicallyAndRefusesWhenUsedUp(t *testing.T) {
	s := open(t, t.TempDir())
	if err := s.RecordAllow(ctx, allowEvent(1), time.Now(), uid(1), 1); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Uses(ctx, uid(1)); n != 1 {
		t.Fatalf("uses %d", n)
	}
	err := s.RecordAllow(ctx, allowEvent(1), time.Now(), uid(1), 1)
	if !errors.Is(err, ErrUsedUp) {
		t.Fatalf("second spend of a single-use credential: %v", err)
	}
	if d, _ := s.QueueDepth(ctx); d != 1 {
		t.Fatalf("a refused spend must not queue an event (depth %d)", d)
	}
}

func TestHeldEventsAreNotUploadedUntilReleasedAndCrashReleasesThem(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	ev := allowEvent(1)
	if err := s.RecordAllow(ctx, ev, time.Now(), "", 0); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.NextBatch(ctx, 0, 10, 1<<20); len(b) != 0 {
		t.Fatal("held event is uploadable")
	}
	if err := s.ReleaseHeld(ctx, ev.ID); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.NextBatch(ctx, 0, 10, 1<<20); len(b) != 1 {
		t.Fatal("released event not uploadable")
	}
	ev2 := allowEvent(2)
	_ = s.RecordAllow(ctx, ev2, time.Now(), "", 0)
	_ = s.Close()
	s2 := open(t, dir) // restart: the open may or may not have happened, the event must go out
	if b, _ := s2.NextBatch(ctx, 0, 10, 1<<20); len(b) != 2 {
		t.Fatalf("held event not released at startup: %d", len(b))
	}
}

func TestRevertAndDiscardHeld(t *testing.T) {
	s := open(t, t.TempDir())
	ev := allowEvent(1)
	if err := s.RecordAllow(ctx, ev, time.Now(), uid(1), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.RevertHeld(ctx, ev.ID, "driver_error", uid(1)); err != nil {
		t.Fatal(err)
	}
	b, _ := s.NextBatch(ctx, 0, 10, 1<<20)
	if len(b) != 1 || b[0].Event.Decision != protocol.DecisionDeny || b[0].Event.Reason != "driver_error" {
		t.Fatalf("%+v", b)
	}
	if n, _ := s.Uses(ctx, uid(1)); n != 0 {
		t.Fatalf("uses %d", n)
	}
	m := allowEvent(2)
	m.Decision = protocol.DecisionManualOpen
	if err := s.RecordCommandAndEvent(ctx, "cmd-1", []byte(`{"status":"failed"}`), m, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.CommandResult(ctx, "cmd-1", time.Now()); !ok {
		t.Fatal("provisional command result missing")
	}
	if err := s.DiscardHeld(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.QueueDepth(ctx); d != 1 {
		t.Fatalf("depth %d", d)
	}
}
