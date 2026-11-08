package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

func (h *harness) commandResult(id string) protocol.Ack {
	h.t.Helper()
	var res protocol.Ack
	waitFor(h.t, 5*time.Second, "command result", func() bool { r, ok := h.fs.CommandResult(id); res = r; return ok })
	return res
}

// A Pi whose RTC died boots days in the past: a command from 6 h ago with a
// 15 s TTL looks fresh on that clock. Every open must be refused.
func TestOpenRefusedWhenClockOffsetIsHuge(t *testing.T) {
	for _, shift := range []time.Duration{-48 * time.Hour, 48 * time.Hour} {
		h := newHarness(t)
		h.shift.Store(int64(shift))
		h.start()
		h.waitSynced()
		m := h.mock()

		stale := h.fs.IssueOpenAt(pointID, time.Now().Add(shift).Add(-6*time.Hour), 15*time.Second) // looks fresh on the agent clock
		fresh := h.fs.IssueOpen(pointID, 15*time.Second)
		for _, id := range []string{stale, fresh} {
			res := h.commandResult(id)
			if res.Status != protocol.AckRefused || !strings.Contains(string(res.Detail), "clock_suspect") {
				t.Fatalf("shift %v: ack %q %s, want refused/clock_suspect", shift, res.Status, res.Detail)
			}
		}
		if n := len(m.Opens()); n != 0 {
			t.Fatalf("shift %v: %d opens with an untrustworthy clock", shift, n)
		}
		waitFor(t, 5*time.Second, "clock_suspect heartbeat", func() bool {
			hbs := h.fs.Heartbeats()
			return len(hbs) > 0 && hbs[len(hbs)-1].ClockSuspect
		})
	}
}

func TestOpenRefusedForImplausibleTimestamps(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.waitSynced()
	m := h.mock()
	cases := []struct {
		name   string
		issued time.Time
		ttl    time.Duration
		reason string
	}{
		{"issued 30 h ago", time.Now().Add(-30 * time.Hour), 15 * time.Second, "issued_at_out_of_range"},
		{"issued 30 h ahead", time.Now().Add(30 * time.Hour), 15 * time.Second, "issued_at_out_of_range"},
		{"ttl 61 s", time.Now(), 61 * time.Second, "ttl_too_long"},
		{"ttl 0", time.Now(), 0, "invalid_ttl"},
	}
	for _, c := range cases {
		res := h.commandResult(h.fs.IssueOpenAt(pointID, c.issued, c.ttl))
		if res.Status != protocol.AckRefused || !strings.Contains(string(res.Detail), c.reason) {
			t.Errorf("%s: ack %q %s, want refused/%s", c.name, res.Status, res.Detail, c.reason)
		}
	}
	if n := len(m.Opens()); n != 0 {
		t.Fatalf("%d opens for implausible commands", n)
	}
	// A sane command still works.
	if res := h.commandResult(h.fs.IssueOpen(pointID, 60*time.Second)); res.Status != protocol.AckDone {
		t.Fatalf("sane command: %+v", res)
	}
}

// A restart on a clock that is behind the persisted last contact (no RTC) must
// not count as being in contact: the agent stays stopped until the server talks.
func TestRestartWithClockBehindLastContactStaysStopped(t *testing.T) {
	h := newHarness(t)
	h.fs.Upsert(h.entry("34ABC123", nil))
	r := h.start()
	h.waitSynced()
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	h.fs.SetOffline(true)
	h.shift.Add(int64(-3 * time.Hour)) // the Pi boots with a stale clock
	h.resetMock()
	h.start()
	m := h.mock()
	h.present("34ABC123")
	waitFor(t, 5*time.Second, "decision", func() bool { return h.status().QueueDepth >= 1 })
	if n := len(m.Opens()); n != 0 {
		t.Fatalf("opened %d times on a clock that is behind the last contact", n)
	}
}
