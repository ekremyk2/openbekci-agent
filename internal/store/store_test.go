package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

var ctx = context.Background()

func open(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func entry(id, plate string) protocol.Entry {
	return protocol.Entry{ID: id, Kind: "plate", Value: plate, Points: []string{protocol.NewID()}, ValidFrom: protocol.Now()}
}

func uid(n int) string { return fmt.Sprintf("0192f1a0-0000-7000-8000-%012d", n) }

func TestPlateEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	d := protocol.Delta{FromVersion: 0, ToVersion: 1, Changes: []protocol.Change{{Op: "upsert", Entry: ptr(entry(uid(1), "34ABC123"))}}}
	if st, _, err := s.ApplyDelta(ctx, d); err != nil || st != DeltaApplied {
		t.Fatalf("apply: %v %v", st, err)
	}
	ev := protocol.Event{ID: protocol.NewID(), PointID: uid(9), Decision: "deny", Reason: "unknown", ObservedPlate: "06ZZZ999", OccurredAt: protocol.Now()}
	if _, err := s.Enqueue(ctx, ev, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Checkpoint the WAL, then scan every file in the state dir for plaintext.
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "store.db*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, plain := range []string{"34ABC123", "06ZZZ999"} {
			if bytes.Contains(b, []byte(plain)) {
				t.Errorf("%s contains plaintext plate %s", filepath.Base(f), plain)
			}
		}
	}
	got, err := s.Lookup(ctx, "plate", "34ABC123")
	if err != nil || len(got) != 1 || got[0].Value != "34ABC123" {
		t.Fatalf("lookup: %v %v", got, err)
	}
	if got, _ := s.Lookup(ctx, "plate", "34ABC124"); len(got) != 0 {
		t.Fatal("unexpected match")
	}
	b, err := s.NextBatch(ctx, 0, 10, 1<<20)
	if err != nil || len(b) != 1 || b[0].Event.ObservedPlate != "06ZZZ999" {
		t.Fatalf("batch: %+v %v", b, err)
	}
	info, err := os.Stat(filepath.Join(dir, "store.key"))
	if err != nil || info.Size() != 32 {
		t.Fatalf("key file: %v %v", info, err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	d := protocol.Delta{FromVersion: 0, ToVersion: 3, Changes: []protocol.Change{{Op: "upsert", Entry: ptr(entry(uid(1), "34ABC123"))}}}
	if _, _, err := s.ApplyDelta(ctx, d); err != nil {
		t.Fatal(err)
	}
	ev := protocol.Event{ID: protocol.NewID(), PointID: uid(9), Decision: "allow", Reason: "match", ObservedPlate: "34ABC123", OccurredAt: protocol.Now()}
	if _, err := s.Enqueue(ctx, ev, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s = open(t, dir)
	if v, _ := s.SnapshotVersion(ctx); v != 3 {
		t.Errorf("version %d", v)
	}
	if n, _ := s.QueueDepth(ctx); n != 1 {
		t.Errorf("queue depth %d", n)
	}
	if got, _ := s.Lookup(ctx, "plate", "34ABC123"); len(got) != 1 {
		t.Errorf("entry lost")
	}
}

func TestDeltaOrdering(t *testing.T) {
	s := open(t, t.TempDir())
	apply := func(from, to int64, es ...protocol.Entry) (DeltaStatus, int64) {
		var ch []protocol.Change
		for _, e := range es {
			ch = append(ch, protocol.Change{Op: "upsert", Entry: ptr(e)})
		}
		st, have, err := s.ApplyDelta(ctx, protocol.Delta{FromVersion: from, ToVersion: to, Changes: ch})
		if err != nil {
			t.Fatal(err)
		}
		return st, have
	}
	if st, _ := apply(0, 1, entry(uid(1), "A1")); st != DeltaApplied {
		t.Fatal("first delta")
	}
	if st, have := apply(5, 6, entry(uid(2), "B2")); st != DeltaGap || have != 1 {
		t.Fatalf("gap: %v %d", st, have)
	}
	if got, _ := s.Lookup(ctx, "plate", "B2"); len(got) != 0 {
		t.Fatal("gap delta must not be applied")
	}
	if st, _ := apply(0, 1, entry(uid(3), "C3")); st != DeltaDuplicate {
		t.Fatal("duplicate")
	}
	if st, _ := apply(1, 2, entry(uid(2), "B2")); st != DeltaApplied {
		t.Fatal("second delta")
	}
	// Remove, and version commits with the change.
	_, _, err := s.ApplyDelta(ctx, protocol.Delta{FromVersion: 2, ToVersion: 3, Changes: []protocol.Change{{Op: "remove", CredentialID: uid(1)}}})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := s.EntryCount(ctx); n != 1 {
		t.Fatalf("count %d", n)
	}
	if v, _ := s.SnapshotVersion(ctx); v != 3 {
		t.Fatalf("version %d", v)
	}
}

func TestSnapshotPartsAtomic(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	// Existing state at version 1.
	_, _, _ = s.ApplyDelta(ctx, protocol.Delta{FromVersion: 0, ToVersion: 1, Changes: []protocol.Change{{Op: "upsert", Entry: ptr(entry(uid(1), "OLD1"))}}})
	site := protocol.Site{Timezone: "Europe/Istanbul"}
	done, err := s.ApplySnapshotPart(ctx, protocol.Snapshot{Version: 10, Part: 1, Parts: 2, Site: site, Entries: []protocol.Entry{entry(uid(2), "NEW1")}})
	if err != nil || done {
		t.Fatalf("part 1: %v %v", done, err)
	}
	// Nothing visible yet, even after a restart.
	_ = s.Close()
	s = open(t, dir)
	if got, _ := s.Lookup(ctx, "plate", "NEW1"); len(got) != 0 {
		t.Fatal("partial snapshot visible")
	}
	if got, _ := s.Lookup(ctx, "plate", "OLD1"); len(got) != 1 {
		t.Fatal("old entry lost before snapshot complete")
	}
	done, err = s.ApplySnapshotPart(ctx, protocol.Snapshot{Version: 10, Part: 2, Parts: 2, Site: site, Entries: []protocol.Entry{entry(uid(3), "NEW2")}})
	if err != nil || !done {
		t.Fatalf("part 2: %v %v", done, err)
	}
	if got, _ := s.Lookup(ctx, "plate", "OLD1"); len(got) != 0 {
		t.Fatal("snapshot must replace the store")
	}
	if n, _ := s.EntryCount(ctx); n != 2 {
		t.Fatalf("count %d", n)
	}
	if v, _ := s.SnapshotVersion(ctx); v != 10 {
		t.Fatalf("version %d", v)
	}
	if tz, _ := s.Timezone(ctx); tz != "Europe/Istanbul" {
		t.Fatalf("tz %q", tz)
	}
}

func TestQueueOverflowDropsDenyFirst(t *testing.T) {
	s := open(t, t.TempDir())
	mk := func(decision string) protocol.Event {
		return protocol.Event{ID: protocol.NewID(), PointID: uid(9), Decision: decision, Reason: "x", OccurredAt: protocol.Now()}
	}
	tx, _ := s.db.Begin()
	// Fill past the limit cheaply with raw inserts: 3 allow, rest deny.
	for i := 0; i < MaxQueuedEvents+2; i++ {
		d := "deny"
		if i < 3 {
			d = "allow"
		}
		ev := mk(d)
		raw, _ := json.Marshal(ev)
		if _, err := tx.Exec(`INSERT INTO queue(event_id, decision, enqueued_ms, json) VALUES(?,?,?,?)`, ev.ID, d, 0, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	dropped, err := s.Enqueue(ctx, mk("deny"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 3 {
		t.Fatalf("dropped %d, want 3", dropped)
	}
	var allows int
	_ = s.db.QueryRow(`SELECT count(*) FROM queue WHERE decision = 'allow'`).Scan(&allows)
	if allows != 3 {
		t.Errorf("allow events must survive, have %d", allows)
	}
	if n, _ := s.QueueDepth(ctx); n != MaxQueuedEvents {
		t.Errorf("depth %d", n)
	}
	if d, _ := s.DroppedEvents(ctx); d != 3 {
		t.Errorf("dropped counter %d", d)
	}
}

func TestCommandReplayCache(t *testing.T) {
	s := open(t, t.TempDir())
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	res := json.RawMessage(`{"status":"done"}`)
	if err := s.RecordCommand(ctx, "c1", res, now); err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := s.CommandResult(ctx, "c1", now.Add(time.Hour)); !ok || string(got) != string(res) {
		t.Fatalf("lost: %s %v", got, ok)
	}
	if _, ok, _ := s.CommandResult(ctx, "c1", now.Add(25*time.Hour)); ok {
		t.Fatal("result must expire after 24 h")
	}
	// Pruning keeps the newest 1000.
	for i := 0; i < CommandKeep+5; i++ {
		_ = s.RecordCommand(ctx, fmt.Sprintf("n%d", i), res, now.Add(time.Duration(i)*time.Second))
	}
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM command_seen`).Scan(&n)
	if n != CommandKeep {
		t.Fatalf("kept %d", n)
	}
}

func TestUsesAndWipe(t *testing.T) {
	s := open(t, t.TempDir())
	_ = s.IncUses(ctx, "e1")
	_ = s.IncUses(ctx, "e1")
	if n, _ := s.Uses(ctx, "e1"); n != 2 {
		t.Fatalf("uses %d", n)
	}
	_ = s.SaveConfig(ctx, protocol.Config{ConfigVersion: 4, Site: protocol.Site{Timezone: "UTC"}, Points: []protocol.PointConfig{}})
	if v, _ := s.ConfigVersion(ctx); v != 4 {
		t.Fatal("config version")
	}
	if err := s.Wipe(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Uses(ctx, "e1"); n != 0 {
		t.Fatal("uses survive wipe")
	}
	if c, _ := s.LoadConfig(ctx); c != nil {
		t.Fatal("config survives wipe")
	}
}
