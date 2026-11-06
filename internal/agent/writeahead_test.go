package agent

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/store"
	_ "modernc.org/sqlite" // second connection used to damage the database
)

// breakQueue makes every write of an event fail, as a dying SD card would:
// the queue table disappears under the running agent.
func breakQueue(t *testing.T, dir string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, store.DBFile))+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(), `ALTER TABLE queue RENAME TO queue_broken`); err != nil {
		t.Fatal(err)
	}
}

func lostReported(h *harness) bool {
	for _, hb := range h.fs.Heartbeats() {
		if hb.LostEvents >= 1 {
			return true
		}
	}
	return false
}

func TestManualOpenRefusedWhenItCannotBeRecorded(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.waitSynced()
	m := h.mock()
	breakQueue(t, h.cfg.StateDir)

	id := h.fs.IssueOpen(pointID, 30*time.Second)
	var res protocol.Ack
	waitFor(t, 5*time.Second, "command result", func() bool { r, ok := h.fs.CommandResult(id); res = r; return ok })
	if res.Status != protocol.AckError {
		t.Fatalf("ack %q, want error: an open that cannot be recorded must be refused", res.Status)
	}
	if n := len(m.Opens()); n != 0 {
		t.Fatalf("the gate opened %d times although nothing was recorded", n)
	}
	waitFor(t, 5*time.Second, "lost_events in the heartbeat", func() bool { return lostReported(h) })
}

func TestAutomaticOpenRefusedWhenItCannotBeRecorded(t *testing.T) {
	h := newHarness(t)
	h.fs.Upsert(h.entry("34ABC123", nil))
	h.start()
	h.waitSynced()
	m := h.mock()
	breakQueue(t, h.cfg.StateDir)

	h.present("34ABC123")
	waitFor(t, 5*time.Second, "lost_events in the heartbeat", func() bool { return lostReported(h) })
	if n := len(m.Opens()); n != 0 {
		t.Fatalf("the gate opened %d times although the decision could not be recorded", n)
	}
	var withErr bool
	for _, hb := range h.fs.Heartbeats() {
		withErr = withErr || hb.StoreError != ""
	}
	if !withErr {
		t.Fatal("heartbeat must report the unreadable store")
	}
}

// A single-use visitor must not get in twice, even across a restart and a
// re-delivered presentation.
func TestSingleUseCredentialIsSpentBeforeThePulse(t *testing.T) {
	h := newHarness(t)
	one := 1
	h.fs.Upsert(h.entry("34ABC123", func(e *protocol.Entry) { e.MaxUses = &one }))
	r := h.start()
	h.waitSynced()
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "event", func() bool { return len(h.fs.Events()) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	h.resetMock()
	h.start()
	m := h.mock()
	h.waitConnected(2)
	h.waitSynced()
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "second event", func() bool { return len(h.fs.Events()) == 2 })
	if e := h.fs.Events()[1]; e.Decision != "deny" || e.Reason != "used_up" || len(m.Opens()) != 0 {
		t.Fatalf("single-use credential reused after restart: %+v opens=%d", e, len(m.Opens()))
	}
}
