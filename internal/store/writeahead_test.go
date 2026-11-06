package store

import (
	"path/filepath"

	"errors"
	"github.com/openbekci/openbekci-agent/internal/fsutil"
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

func TestDurabilityPragmas(t *testing.T) {
	s := open(t, t.TempDir())
	var sync int
	if err := s.db.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&sync); err != nil {
		t.Fatal(err)
	}
	if sync != 2 { // 2 = FULL
		t.Fatalf("PRAGMA synchronous = %d, want 2 (FULL): WAL+NORMAL loses commits on power loss", sync)
	}
	var mode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode %q %v", mode, err)
	}
}

// The state directory, key and database are owner-only on every platform (a
// protected DACL on Windows, mode 0700/0600 elsewhere).
func TestStateFilesAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	if err := s.RecordAllow(ctx, allowEvent(1), time.Now(), "", 0); err != nil { // makes the WAL exist
		t.Fatal(err)
	}
	for _, name := range []string{".", keyFile, DBFile} {
		p := filepath.Join(dir, name)
		if ok, err := fsutil.OwnerOnly(p); err != nil || !ok {
			t.Errorf("%s is not owner-only (ok=%v err=%v)", p, ok, err)
		}
	}
}

// One undecryptable or unparsable queue row must not block the uploads behind
// it: it moves to dead_letter and is counted.
func TestPoisonedQueueRowsGoToDeadLetter(t *testing.T) {
	s := open(t, t.TempDir())
	mk := func(plate string) protocol.Event {
		e := allowEvent(1)
		e.Decision, e.ObservedPlate = protocol.DecisionDeny, plate
		return e
	}
	good1, poisoned, garbled, good2 := mk("34AAA111"), mk("34BBB222"), mk("34CCC333"), mk("34DDD444")
	for _, e := range []protocol.Event{good1, poisoned, garbled, good2} {
		if _, err := s.Enqueue(ctx, e, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE queue SET plate_enc = X'00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF' WHERE event_id = ?`, poisoned.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE queue SET json = '{not json' WHERE event_id = ?`, garbled.ID); err != nil {
		t.Fatal(err)
	}
	b, err := s.NextBatch(ctx, 0, 10, 1<<20)
	if err != nil {
		t.Fatalf("a poisoned row blocked the queue: %v", err)
	}
	if len(b) != 2 || b[0].Event.ID != good1.ID || b[1].Event.ID != good2.ID {
		t.Fatalf("batch %+v, want the two good events", b)
	}
	if n, _ := s.DeadLetters(ctx); n != 2 {
		t.Fatalf("dead letters %d, want 2", n)
	}
	if d, _ := s.QueueDepth(ctx); d != 2 {
		t.Fatalf("queue depth %d, want 2 (poisoned rows removed from the queue)", d)
	}
}

// An undecryptable allow-list entry makes the store forget its version so the
// next hello gets a full snapshot, and the read fails closed.
func TestCorruptEntryResetsAllowListVersion(t *testing.T) {
	s := open(t, t.TempDir())
	e := entry(uid(7), "34ABC123")
	if st, _, err := s.ApplyDelta(ctx, protocol.Delta{FromVersion: 0, ToVersion: 5, Changes: []protocol.Change{{Op: protocol.OpUpsert, Entry: &e}}}); err != nil || st != DeltaApplied {
		t.Fatal(st, err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE entry SET value_enc = X'0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20' WHERE id = ?`, e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, "plate", "34ABC123"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("lookup of a corrupt entry: %v", err)
	}
	if v, _ := s.SnapshotVersion(ctx); v != 0 {
		t.Fatalf("version %d after corruption, want 0 so the server resyncs", v)
	}
}
