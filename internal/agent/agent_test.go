package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/config"
	"github.com/openbekci/openbekci-agent/internal/driver"
	"github.com/openbekci/openbekci-agent/internal/driver/mock"
	"github.com/openbekci/openbekci-agent/internal/fakeserver"
	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/transport"
)

func TestEnrolStoresTokenAndRefusesBadTokens(t *testing.T) {
	fs := fakeserver.New(t)
	cfg := &config.Config{Server: fs.URL, StateDir: filepath.Join(t.TempDir(), "state"), CAFile: fs.CACertFile()}
	tok := fs.NewEnrolToken()

	id, err := Enrol(context.Background(), cfg, EnrolOptions{Server: fs.URL, Token: tok, Version: "9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	if id.AgentID != fs.AgentID || id.OrgID != fs.OrgID || id.SiteID != fs.SiteID {
		t.Fatalf("identity %+v", id)
	}
	got, err := readToken(cfg.StateDir)
	if err != nil || got != fs.CurrentToken() || !strings.HasPrefix(got, "obk_agt_") {
		t.Fatalf("token file %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(cfg.StateDir, TokenFile)); fi.Mode().Perm() != 0o600 {
			t.Fatalf("token mode %v", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(filepath.Join(cfg.StateDir, "store.key")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %v", fi.Mode().Perm())
		}
	}
	if reqs := fs.Enrolments(); len(reqs) != 1 || reqs[0].AgentVersion != "9.9.9" || reqs[0].Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("enrol request %+v", reqs)
	}
	st, err := ReadStatus(context.Background(), cfg.StateDir)
	if err != nil || st.Identity.AgentID != id.AgentID || st.SnapshotVersion != 0 || st.LastContact.IsZero() {
		t.Fatalf("status %+v %v", st, err)
	}

	// A used token is refused with ErrNotFound and leaves the old credential alone.
	if _, err := Enrol(context.Background(), cfg, EnrolOptions{Server: fs.URL, Token: tok}); !errors.Is(err, transport.ErrNotFound) {
		t.Fatalf("reuse: %v", err)
	}
	if after, _ := readToken(cfg.StateDir); after != got {
		t.Fatal("failed enrolment must not touch the token")
	}
	// Org/site scoped endpoint works too.
	if _, err := Enrol(context.Background(), cfg, EnrolOptions{Server: fs.URL, Org: "o", Site: "s", Token: fs.NewEnrolToken()}); err != nil {
		t.Fatalf("scoped enrol: %v", err)
	}

	// Input validation.
	for _, o := range []EnrolOptions{
		{Server: "http://insecure.example", Token: "obk_enr_x"},
		{Server: fs.URL, Token: "not-a-token"},
		{Server: fs.URL, Token: "obk_enr_x", Org: "only-org"},
	} {
		if _, err := Enrol(context.Background(), cfg, o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
	fresh := &config.Config{Server: fs.URL, StateDir: t.TempDir()} // no ca_file: server certificate is untrusted
	if _, err := Enrol(context.Background(), fresh, EnrolOptions{Server: fs.URL, Token: fs.NewEnrolToken()}); err == nil {
		t.Fatal("enrolled against an untrusted certificate")
	}
	if _, err := readToken(fresh.StateDir); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("token written despite failure: %v", err)
	}
}

func TestRunRequiresEnrolment(t *testing.T) {
	cfg := &config.Config{Server: "https://x.example", StateDir: t.TempDir()}
	a, _ := New(Options{Config: cfg})
	if err := a.Run(context.Background()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("got %v", err)
	}
}

func TestSnapshotThenDeltasAndDecisions(t *testing.T) {
	h := newHarness(t)
	resident := h.entry("34ABC123", nil)
	h.fs.Upsert(resident)
	h.start()
	h.waitSynced()

	h.present("34 ABC 123")
	waitFor(t, 5*time.Second, "allow event", func() bool { return len(h.fs.Events()) == 1 })
	ev := h.fs.Events()[0]
	if ev.Decision != "allow" || ev.Reason != "match" || ev.CredentialID != resident.ID || ev.ObservedPlate != "34ABC123" || ev.PointID != pointID {
		t.Fatalf("event %+v", ev)
	}
	if got := len(h.mock().Opens()); got != 1 {
		t.Fatalf("opens %d", got)
	}
	waitFor(t, 5*time.Second, "queue drained by ack", func() bool { return h.status().QueueDepth == 0 })

	// A visitor approved while the agent is connected arrives as a delta in seconds.
	visitor := h.entry("06ZZZ999", func(e *protocol.Entry) { one := 1; e.MaxUses = &one })
	h.fs.Upsert(visitor)
	h.waitSynced()
	h.present("06 zzz 999")
	waitFor(t, 5*time.Second, "visitor event", func() bool { return len(h.fs.Events()) == 2 })
	// Single use: a second presentation (after the dedupe window) is used_up.
	h.shift.Add(int64(time.Minute))
	h.present("06ZZZ999")
	waitFor(t, 5*time.Second, "used_up event", func() bool { return len(h.fs.Events()) == 3 })
	if e := h.fs.Events()[2]; e.Decision != "deny" || e.Reason != "used_up" {
		t.Fatalf("event %+v", e)
	}
	// Removal by delta.
	h.fs.Remove(resident.ID)
	h.waitSynced()
	h.shift.Add(int64(time.Minute))
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "unknown after removal", func() bool { return len(h.fs.Events()) == 4 })
	if e := h.fs.Events()[3]; e.Decision != "deny" || e.Reason != "unknown" {
		t.Fatalf("event %+v", e)
	}
	for _, b := range h.fs.Batches() {
		if b.ClockOffsetMS == nil {
			t.Error("event batch without clock_offset_ms")
		}
	}
}

func TestMultiPartSnapshot(t *testing.T) {
	h := newHarness(t)
	h.fs.SnapshotPart = 2
	for _, p := range []string{"A1", "B2", "C3", "D4", "E5"} {
		h.fs.Upsert(h.entry(p, nil))
	}
	h.fs.PruneLog() // no deltas possible: the agent must get a snapshot
	h.start()
	h.waitSynced()
	if s := h.status(); s.Entries != 5 || s.SnapshotVersion != 5 || s.Timezone != "Europe/Istanbul" {
		t.Fatalf("status %+v", s)
	}
	snaps := 0
	for _, e := range h.fs.Sent() {
		if e.Type == protocol.TypeSnapshot {
			snaps++
		}
	}
	if snaps != 3 {
		t.Fatalf("snapshot parts sent: %d", snaps)
	}
	acked := 0
	for _, a := range h.fs.Acks() {
		if a.Status == protocol.AckOK {
			acked++
		}
	}
	if acked < 3 {
		t.Fatalf("every part must be acked, got %d acks", acked)
	}
}

func TestDeltaGapRecoversWithSnapshot(t *testing.T) {
	h := newHarness(t)
	h.fs.Upsert(h.entry("A1", nil))
	h.start()
	h.waitSynced()

	missed := h.entry("MISSED1", nil)
	h.fs.SilentUpsert(missed)         // version bumps, the agent is not told
	h.fs.Upsert(h.entry("NEW2", nil)) // delta whose from_version the agent does not have
	waitFor(t, 5*time.Second, "gap ack", func() bool { g, _, _, _ := h.fs.Counters(); return g == 1 })
	h.waitSynced()
	if s := h.status(); s.Entries != 3 || s.SnapshotVersion != h.fs.Version() {
		t.Fatalf("after gap recovery: %+v", s)
	}
	h.present("MISSED1")
	waitFor(t, 5*time.Second, "event for the missed entry", func() bool { return len(h.fs.Events()) == 1 })
	if e := h.fs.Events()[0]; e.Decision != "allow" {
		t.Fatalf("event %+v", e)
	}
	// An old delta is acknowledged as duplicate and ignored.
	h.fs.SendRawDelta(0, 1, []protocol.Change{{Op: protocol.OpRemove, CredentialID: missed.ID}})
	waitFor(t, 5*time.Second, "duplicate ack", func() bool { _, d, _, _ := h.fs.Counters(); return d == 1 })
	if s := h.status(); s.Entries != 3 {
		t.Fatalf("duplicate delta must not apply: %+v", s)
	}
}

func TestEventBatchingAndOfflineQueue(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.waitSynced()
	h.fs.SetOffline(true)

	const n = 250
	for i := 0; i < n; i++ {
		h.present("UNK" + pad(i))
	}
	waitFor(t, 20*time.Second, "events queued offline", func() bool { return h.status().QueueDepth == n })
	if len(h.fs.Events()) != 0 {
		t.Fatal("server must not have seen anything while offline")
	}
	h.fs.SetOffline(false)
	waitFor(t, 20*time.Second, "all events delivered", func() bool { return len(h.fs.Events()) == n })
	waitFor(t, 10*time.Second, "queue drained", func() bool { return h.status().QueueDepth == 0 })
	seen := map[string]bool{}
	for _, e := range h.fs.Events() {
		if !protocol.IsUUIDv7(e.ID) || seen[e.ID] {
			t.Fatalf("bad or duplicate event id %s", e.ID)
		}
		seen[e.ID] = true
	}
	big := 0
	for _, b := range h.fs.Batches() {
		if len(b.Events) > protocol.MaxEventBatch {
			t.Fatalf("batch of %d", len(b.Events))
		}
		if len(b.Events) == protocol.MaxEventBatch {
			big++
		}
	}
	if big < 2 {
		t.Fatalf("expected full batches of 100, got %d", big)
	}
}

func pad(i int) string {
	s := "0000" + itoa(int64(i))
	return s[len(s)-4:]
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestUnackedEventsSurviveRestartAndDuplicatesAreHarmless(t *testing.T) {
	h := newHarness(t)
	h.fs.Upsert(h.entry("34ABC123", nil))
	r := h.start()
	h.waitSynced()

	h.fs.DropEventAcks(1000) // the server stores events but its acks never arrive
	for _, p := range []string{"34ABC123", "UNK1", "UNK2"} {
		h.present(p)
	}
	waitFor(t, 5*time.Second, "server stored the events", func() bool { return len(h.fs.Events()) == 3 })
	time.Sleep(200 * time.Millisecond)
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if q := h.status().QueueDepth; q != 3 {
		t.Fatalf("unacked events must stay on disk, queue depth %d", q)
	}

	// Restart: the same events are sent again; the server answers duplicates.
	h.fs.DropEventAcks(0)
	h.resetMock()
	h.start()
	waitFor(t, 10*time.Second, "queue drained after restart", func() bool { return h.status().QueueDepth == 0 })
	if got := len(h.fs.Events()); got != 3 {
		t.Fatalf("server holds %d distinct events, want 3 (idempotent ingest)", got)
	}
	sent := 0
	for _, b := range h.fs.Batches() {
		sent += len(b.Events)
	}
	if sent < 6 {
		t.Fatalf("events were not re-sent after restart (%d sent in total)", sent)
	}
}

func TestOfflineDecisionsAndReconcile(t *testing.T) {
	h := newHarness(t)
	resident := h.entry("34ABC123", nil)
	soon := h.entry("06SOON11", func(e *protocol.Entry) { to := protocol.At(time.Now().Add(time.Hour)); e.ValidTo = &to })
	h.fs.Upsert(resident)
	h.fs.Upsert(soon)
	h.start()
	h.waitSynced()
	h.fs.SetOffline(true)
	waitFor(t, 5*time.Second, "offline", func() bool { return !h.fs.Connected() })

	h.present("34ABC123")
	h.present("99UNK999")
	h.present("06SOON11") // inside its window
	waitFor(t, 5*time.Second, "offline decisions", func() bool { return h.status().QueueDepth == 3 })
	if got := len(h.mock().Opens()); got != 2 {
		t.Fatalf("gate opened %d times offline, want 2", got)
	}
	// An entry that expires while offline denies exactly like online.
	h.shift.Add(int64(2 * time.Hour))
	h.present("06SOON11")
	waitFor(t, 5*time.Second, "expired decision", func() bool { return h.status().QueueDepth == 4 })
	if got := len(h.mock().Opens()); got != 2 {
		t.Fatalf("expired credential opened the gate (%d opens)", got)
	}

	h.shift.Store(0)
	_, _, _, before := h.fs.Counters()
	reconnectAt := time.Now()
	h.fs.SetOffline(false)
	h.waitConnected(before + 1)
	waitFor(t, 10*time.Second, "events reconciled", func() bool { return len(h.fs.Events()) == 4 })
	evs := h.fs.Events()
	want := []struct{ plate, decision, reason string }{
		{"34ABC123", "allow", "match"}, {"99UNK999", "deny", "unknown"}, {"06SOON11", "allow", "match"}, {"06SOON11", "deny", "outside_window"},
	}
	for i, w := range want {
		if evs[i].ObservedPlate != w.plate || evs[i].Decision != w.decision || evs[i].Reason != w.reason {
			t.Fatalf("event %d = %+v, want %+v", i, evs[i], w)
		}
	}
	// Events keep the time of the decision, not the time of the upload.
	for i, e := range evs {
		if !e.OccurredAt.Before(reconnectAt) {
			t.Fatalf("event %d occurred_at %v is not before the reconnect at %v", i, e.OccurredAt, reconnectAt)
		}
	}
	waitFor(t, 5*time.Second, "queue drained", func() bool { return h.status().QueueDepth == 0 })
}

func TestStoppedAfterGraceThenResumes(t *testing.T) {
	h := newHarness(t)
	h.fs.Upsert(h.entry("34ABC123", nil))
	h.start()
	h.waitSynced()
	h.fs.SetOffline(true)
	waitFor(t, 5*time.Second, "offline", func() bool { return !h.fs.Connected() })

	h.shift.Add(int64(70 * time.Hour)) // inside the 72 h grace
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "decision inside grace", func() bool { return h.status().QueueDepth == 1 })
	if len(h.mock().Opens()) != 1 {
		t.Fatal("must still open inside the grace period")
	}
	h.shift.Add(int64(3 * time.Hour)) // 73 h without contact: stopped
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "decision after grace", func() bool { return h.status().QueueDepth == 2 })
	if len(h.mock().Opens()) != 1 {
		t.Fatal("stopped agent must not open")
	}

	_, _, _, before := h.fs.Counters()
	h.fs.SetOffline(false)
	h.waitConnected(before + 1)
	waitFor(t, 10*time.Second, "events delivered", func() bool { return len(h.fs.Events()) == 2 })
	if e := h.fs.Events()[1]; e.Decision != "deny" || e.Reason != "agent_stopped" || e.ObservedPlate != "34ABC123" {
		t.Fatalf("stopped event %+v", e)
	}
	// Contact resumed it (a fresh hello followed).
	h.shift.Add(int64(11 * time.Second))
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "resumed decision", func() bool { return len(h.fs.Events()) == 3 })
	if e := h.fs.Events()[2]; e.Decision != "allow" {
		t.Fatalf("after resume %+v", e)
	}
}

func TestCommandOpenTTLAndReplay(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.waitSynced()
	m := h.mock()

	// Normal open: ack done, one pulse, manual_open event naming the command.
	id := h.fs.IssueOpen(pointID, 15*time.Second)
	var res protocol.Ack
	waitFor(t, 5*time.Second, "open result", func() bool { r, ok := h.fs.CommandResult(id); res = r; return ok })
	if res.Status != protocol.AckDone || len(m.Opens()) != 1 {
		t.Fatalf("ack %+v opens %d", res, len(m.Opens()))
	}
	waitFor(t, 5*time.Second, "manual_open event", func() bool { return len(h.fs.Events()) == 1 })
	if e := h.fs.Events()[0]; e.Decision != "manual_open" || e.Reason != "guard" || e.CommandID != id || e.PointID != pointID {
		t.Fatalf("event %+v", e)
	}

	// Replay: the same command id is answered from the cache and not executed again.
	ackedBefore := len(h.fs.Acks())
	h.fs.Redeliver(id)
	waitFor(t, 5*time.Second, "replay ack", func() bool { return len(h.fs.Acks()) > ackedBefore })
	if last := h.fs.Acks()[len(h.fs.Acks())-1]; last.Ref != id || last.Status != protocol.AckDone {
		t.Fatalf("replay ack %+v", last)
	}
	if len(m.Opens()) != 1 {
		t.Fatalf("replayed command executed again (%d opens)", len(m.Opens()))
	}

	// Expired: issued 30 s ago with a 15 s TTL, never executed.
	old := h.fs.IssueOpenAt(pointID, time.Now().Add(-30*time.Second), 15*time.Second)
	waitFor(t, 5*time.Second, "expired result", func() bool { r, ok := h.fs.CommandResult(old); res = r; return ok })
	if res.Status != protocol.AckExpired || len(m.Opens()) != 1 {
		t.Fatalf("expired: %+v opens %d", res, len(m.Opens()))
	}
	// A TTL longer than 60 s is capped at 60 s: issued 2 min ago with a 10 min TTL is expired.
	long := h.fs.IssueOpenAt(pointID, time.Now().Add(-2*time.Minute), 10*time.Minute)
	waitFor(t, 5*time.Second, "capped ttl result", func() bool { r, ok := h.fs.CommandResult(long); res = r; return ok })
	if res.Status != protocol.AckExpired {
		t.Fatalf("ttl cap: %+v", res)
	}

	// Unknown and disabled points.
	unk := h.fs.IssueOpen("0192f1a0-0000-7000-8000-0000000000ff", 15*time.Second)
	waitFor(t, 5*time.Second, "unknown_point result", func() bool { r, ok := h.fs.CommandResult(unk); res = r; return ok })
	if res.Status != protocol.AckUnknownPoint {
		t.Fatalf("unknown point: %+v", res)
	}

	// Driver failure: failed/driver_error, and a re-delivery does not retry the pulse.
	m.SetFailOpen(true)
	bad := h.fs.IssueOpen(pointID, 15*time.Second)
	waitFor(t, 5*time.Second, "failed result", func() bool { r, ok := h.fs.CommandResult(bad); res = r; return ok })
	var det map[string]any
	_ = json.Unmarshal(res.Detail, &det)
	if res.Status != protocol.AckFailed || det["reason"] != "driver_error" {
		t.Fatalf("failed: %+v %s", res, res.Detail)
	}
	m.SetFailOpen(false)
	h.fs.Redeliver(bad)
	time.Sleep(300 * time.Millisecond)
	if len(m.Opens()) != 1 {
		t.Fatalf("a failed open must not be retried automatically (%d opens)", len(m.Opens()))
	}
}

func TestCommandReplayAcrossRestart(t *testing.T) {
	h := newHarness(t)
	r := h.start()
	h.waitSynced()
	id := h.fs.IssueOpen(pointID, 60*time.Second)
	waitFor(t, 5*time.Second, "done", func() bool { r, ok := h.fs.CommandResult(id); return ok && r.Status == protocol.AckDone })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	h.resetMock()
	h.start()
	m := h.mock()
	h.waitConnected(2)
	h.fs.Redeliver(id)
	waitFor(t, 5*time.Second, "replay ack", func() bool {
		n := 0
		for _, a := range h.fs.Acks() {
			if a.Ref == id && a.Status == protocol.AckDone {
				n++
			}
		}
		return n == 2
	})
	if len(m.Opens()) != 0 {
		t.Fatalf("replayed command executed after restart (%d opens)", len(m.Opens()))
	}
}

func TestUpdateConfigMissingDriverAndUnsupported(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.waitSynced()
	ghostPoint := "0192f1a0-0000-7000-8000-0000000000b2"
	h.fs.SetConfig([]protocol.PointConfig{
		{ID: pointID, Name: "Main gate", Kind: "vehicle_gate", Direction: "in", DriverRef: protocol.DriverRef{Instance: "gate", Channel: "in"}, Enabled: true},
		{ID: ghostPoint, Name: "Side gate", Kind: "vehicle_gate", Direction: "out", DriverRef: protocol.DriverRef{Instance: "ghost", Channel: "1"}, Enabled: true},
		{ID: "0192f1a0-0000-7000-8000-0000000000b3", Name: "Disabled", Kind: "pedestrian_door", Direction: "both", DriverRef: protocol.DriverRef{Instance: "gate", Channel: "x"}, Enabled: false},
	}, &protocol.Settings{OfflineGraceHours: 48, PlateMatch: "tolerant", HeartbeatSeconds: 30, MaintenanceHour: 3})
	h.waitSynced()
	waitFor(t, 5*time.Second, "missing driver in heartbeat", func() bool {
		hbs := h.fs.Heartbeats()
		if len(hbs) == 0 {
			return false
		}
		for _, d := range hbs[len(hbs)-1].Drivers {
			if d.Instance == "ghost" && d.State == "missing" {
				return true
			}
		}
		return false
	})
	// The point cannot open: failed / driver_error.
	id := h.fs.IssueOpen(ghostPoint, 15*time.Second)
	var res protocol.Ack
	waitFor(t, 5*time.Second, "result", func() bool { r, ok := h.fs.CommandResult(id); res = r; return ok })
	if res.Status != protocol.AckFailed {
		t.Fatalf("%+v", res)
	}
	dis := h.fs.IssueOpen("0192f1a0-0000-7000-8000-0000000000b3", 15*time.Second)
	waitFor(t, 5*time.Second, "refused", func() bool { r, ok := h.fs.CommandResult(dis); res = r; return ok })
	if res.Status != protocol.AckRefused {
		t.Fatalf("disabled point: %+v", res)
	}

	// Forward compatibility: unknown message types and commands are acked "unsupported".
	_, _, before, _ := h.fs.Counters()
	h.fs.SendEnvelope("telepathy", map[string]any{"x": 1})
	h.fs.Command(protocol.Command{Command: "reboot"}) // fails schema validation on the agent side too
	h.fs.SendEnvelope(protocol.TypeCommand, map[string]any{"command": "open_point"})
	waitFor(t, 5*time.Second, "unsupported ack", func() bool { _, _, u, _ := h.fs.Counters(); return u > before })
}

func TestClockOffsetReporting(t *testing.T) {
	h := newHarness(t)
	h.fs.ClockSkew = 5 * time.Second
	h.start()
	h.waitConnected(1)
	waitFor(t, 5*time.Second, "heartbeat with offset", func() bool {
		hbs := h.fs.Heartbeats()
		return len(hbs) > 0 && hbs[len(hbs)-1].ClockOffsetMS != nil
	})
	hb := h.fs.Heartbeats()
	last := hb[len(hb)-1]
	if off := *last.ClockOffsetMS; off < 4000 || off > 6000 || last.ClockSuspect {
		t.Fatalf("offset %d suspect %v", off, last.ClockSuspect)
	}
	// A 10 minute skew is reported as clock_suspect, and the agent keeps working.
	h.fs.ClockSkew = 10 * time.Minute
	h.fs.DropConnection()
	waitFor(t, 5*time.Second, "suspect heartbeat", func() bool {
		hbs := h.fs.Heartbeats()
		return len(hbs) > 0 && hbs[len(hbs)-1].ClockSuspect
	})
	hellos := h.fs.Hellos()
	if len(hellos) < 2 || hellos[len(hellos)-1].ClockOffsetMS == nil {
		t.Fatalf("second hello must carry the measured offset: %+v", hellos)
	}
}

func TestRevocationWipesState(t *testing.T) {
	h := newHarness(t)
	h.fs.Upsert(h.entry("34ABC123", nil))
	r := h.start()
	h.waitSynced()
	h.fs.DropEventAcks(1000)
	h.present("UNK1")
	waitFor(t, 5*time.Second, "unacked event", func() bool { return h.status().QueueDepth == 1 })

	h.fs.Revoke()
	err, ok := r.wait(t, 10*time.Second)
	if !ok || !errors.Is(err, ErrRevoked) {
		t.Fatalf("run: %v (stopped=%v)", err, ok)
	}
	for _, f := range []string{TokenFile, IdentityFile, "store.db", "store.key"} {
		if _, err := os.Stat(filepath.Join(h.cfg.StateDir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the wipe (%v)", f, err)
		}
	}
	if !IsRevoked(h.cfg.StateDir) {
		t.Fatal("revoked marker missing")
	}
	// It refuses to start until re-enrolled.
	a, _ := New(h.options())
	if err := a.Run(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("restart after revocation: %v", err)
	}
	if _, err := ReadStatus(context.Background(), h.cfg.StateDir); !errors.Is(err, ErrRevoked) {
		t.Fatalf("status: %v", err)
	}
	// Re-enrolling brings it back with an empty store.
	h.resetMock()
	h.enrol()
	if IsRevoked(h.cfg.StateDir) {
		t.Fatal("marker must be removed by enrolment")
	}
	h.start()
	h.waitSynced()
	if s := h.status(); s.QueueDepth != 0 {
		t.Fatalf("stale queue after re-enrol: %+v", s)
	}
}

func TestUnauthorizedAtConnectIsRevoked(t *testing.T) {
	h := newHarness(t)
	h.fs.Revoke() // revoked while the agent was down
	r := h.start()
	err, ok := r.wait(t, 10*time.Second)
	if !ok || !errors.Is(err, ErrRevoked) {
		t.Fatalf("run: %v (stopped=%v)", err, ok)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.StateDir, TokenFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("token survived a 401")
	}
}

func TestTokenRotation(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.waitConnected(1)
	if h.fs.Rotations() != 0 {
		t.Fatal("rotated without a reason (rotate_by is months away)")
	}
	old := h.fs.CurrentToken()

	h.fs.ForceRotate() // rotate_now in the next hello
	h.fs.DropConnection()
	waitFor(t, 10*time.Second, "rotation", func() bool { return h.fs.Rotations() == 1 })
	waitFor(t, 5*time.Second, "token file replaced", func() bool {
		tok, err := readToken(h.cfg.StateDir)
		return err == nil && tok == h.fs.CurrentToken() && tok != old
	})
	if h.fs.PrevToken() != old {
		t.Fatal("server must keep the old token as previous")
	}
	if matches, _ := filepath.Glob(filepath.Join(h.cfg.StateDir, "*.tmp-*")); len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}

	// After the 10 minute grace the old token is dead: the agent must reconnect with the new one.
	h.fs.ExpirePrevToken()
	_, _, _, before := h.fs.Counters()
	h.fs.DropConnection()
	h.waitConnected(before + 1)

	// rotate_by inside 14 days triggers rotation without rotate_now.
	h.fs.SetRotateBy(time.Now().Add(5 * 24 * time.Hour))
	h.fs.DropConnection()
	waitFor(t, 10*time.Second, "rotation by rotate_by", func() bool { return h.fs.Rotations() == 2 })
}

func TestRotateTokenCommandLine(t *testing.T) {
	h := newHarness(t)
	old, _ := readToken(h.cfg.StateDir)
	if err := RotateToken(context.Background(), h.cfg); err != nil {
		t.Fatal(err)
	}
	cur, _ := readToken(h.cfg.StateDir)
	if cur == old || cur != h.fs.CurrentToken() {
		t.Fatalf("token %q old %q server %q", cur, old, h.fs.CurrentToken())
	}
	h.fs.Revoke()
	if err := RotateToken(context.Background(), h.cfg); !errors.Is(err, transport.ErrRevoked) {
		t.Fatalf("revoked rotate: %v", err)
	}
}

func TestWorksOverLongPoll(t *testing.T) {
	h := newHarness(t)
	h.tune = func(o *transport.Options) { o.WSRetry = time.Hour }
	h.fs.FailUpgrades(-1)
	h.fs.Upsert(h.entry("34ABC123", nil))
	h.start()
	h.waitSynced()
	if n := h.fs.UpgradeAttempts(); n != 3 {
		t.Fatalf("upgrade attempts %d, want 3 before falling back", n)
	}
	h.present("34ABC123")
	waitFor(t, 10*time.Second, "event over poll", func() bool { return len(h.fs.Events()) == 1 })
	id := h.fs.IssueOpen(pointID, 30*time.Second)
	waitFor(t, 10*time.Second, "command over poll", func() bool { r, ok := h.fs.CommandResult(id); return ok && r.Status == protocol.AckDone })
	waitFor(t, 10*time.Second, "heartbeats over poll", func() bool { return len(h.fs.Heartbeats()) > 0 })
}

func TestMockModeRoutesEveryInstance(t *testing.T) {
	h := newHarness(t)
	h.fs.Upsert(h.entry("34ABC123", nil))
	o := h.options()
	o.Mock = true
	o.Registrations = nil
	h.cfg.Drivers = nil // no real drivers needed
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	h.run(a)
	h.waitSynced()
	a.MockDriver().Inject(driver.Presentation{Channel: "in", Kind: "plate", Value: "34 ABC 123"})
	waitFor(t, 10*time.Second, "event", func() bool { return len(h.fs.Events()) == 1 })
	if e := h.fs.Events()[0]; e.Decision != "allow" || e.PointID != pointID {
		t.Fatalf("event %+v", e)
	}
	if len(a.MockDriver().Opens()) != 1 {
		t.Fatal("mock driver did not record the open")
	}
}

func TestWiringOpensThroughSeparateInstance(t *testing.T) {
	h := newHarness(t)
	h.cfg.Drivers = []config.DriverConfig{{Name: "gate", Type: "mock"}, {Name: "gate-relay", Type: "mock"}}
	h.cfg.Points = []config.PointWiring{{Point: "gate", Open: config.OpenRef{Instance: "gate-relay", Channel: "1"}}}
	h.fs.Upsert(h.entry("34ABC123", nil))
	o := h.options()
	instances := map[string]driver.Driver{}
	o.Registrations = []driver.Registration{{Type: "mock", New: func(name string, cfg map[string]any, log *slog.Logger) (driver.Driver, error) {
		d, err := mock.New(name, mock.Config{}, log)
		h.mu.Lock()
		instances[name] = d
		h.mu.Unlock()
		return d, err
	}}}
	a, _ := New(o)
	h.run(a)
	h.waitSynced()
	waitFor(t, 5*time.Second, "instances", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return len(instances) == 2 })
	h.mu.Lock()
	reader, relay := instances["gate"].(*mock.Driver), instances["gate-relay"].(*mock.Driver)
	h.mu.Unlock()
	reader.Inject(driver.Presentation{Channel: "in", Kind: "plate", Value: "34ABC123"})
	waitFor(t, 5*time.Second, "event", func() bool { return len(h.fs.Events()) == 1 })
	if len(reader.Opens()) != 0 || len(relay.Opens()) != 1 || relay.Opens()[0].Channel != "1" {
		t.Fatalf("reader opens %d, relay opens %+v", len(reader.Opens()), relay.Opens())
	}
}

// A connected agent on a site with no deltas, commands or events must not go
// stopped: pongs (WebSocket) and empty 2xx poll answers are server contact.
func TestQuietServerStaysRunningWebSocket(t *testing.T) {
	h := newHarness(t)
	h.fs.Upsert(h.entry("34ABC123", nil))
	h.start()
	h.waitSynced()
	hbBefore := len(h.fs.Heartbeats())
	h.shift.Add(int64(73 * time.Hour)) // 73 h of fake clock, the server says nothing
	waitFor(t, 5*time.Second, "heartbeats on the shifted clock", func() bool { return len(h.fs.Heartbeats()) >= hbBefore+3 })
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "decision", func() bool { return h.status().QueueDepth >= 1 || len(h.fs.Events()) >= 1 })
	if n := len(h.mock().Opens()); n != 1 {
		t.Fatalf("connected agent on a quiet server must stay running, got %d opens", n)
	}
}

func TestQuietServerStaysRunningLongPoll(t *testing.T) {
	h := newHarness(t)
	h.tune = func(o *transport.Options) { o.WSRetry = time.Hour }
	h.fs.FailUpgrades(-1)
	h.fs.Upsert(h.entry("34ABC123", nil))
	h.start()
	h.waitSynced()
	h.shift.Add(int64(73 * time.Hour))
	// Two full empty polls (PollWait 1 s) happen on the shifted clock.
	time.Sleep(2500 * time.Millisecond)
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "decision", func() bool { return h.status().QueueDepth >= 1 || len(h.fs.Events()) >= 1 })
	if n := len(h.mock().Opens()); n != 1 {
		t.Fatalf("long-poll agent on a quiet server must stay running, got %d opens", n)
	}
}
