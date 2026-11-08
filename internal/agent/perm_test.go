package agent

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/openbekci/openbekci-agent/internal/store"
	"github.com/openbekci/openbekci-agent/internal/transport"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/fsutil"
)

func TestEnrolledStateIsOwnerOnly(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{".", TokenFile, IdentityFile, "store.key", "store.db"} {
		p := filepath.Join(h.cfg.StateDir, name)
		if ok, err := fsutil.OwnerOnly(p); err != nil || !ok {
			t.Errorf("%s is not owner-only after enrolment (ok=%v err=%v)", name, ok, err)
		}
	}
}

// A torn (0-byte) store.key is a fatal, explicit startup error; only a fresh
// enrolment, on the operator's say-so, discards the unreadable store.
func TestEmptyKeyIsFatalAtStartupAndEnrolRecovers(t *testing.T) {
	h := newHarness(t)
	key := filepath.Join(h.cfg.StateDir, "store.key")
	if err := os.WriteFile(key, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(h.options())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Run(context.Background()); !errors.Is(err, store.ErrKeyUnusable) || !strings.Contains(err.Error(), "enrol") {
		t.Fatalf("Run with an empty key: %v", err)
	}
	if b, _ := os.ReadFile(key); len(b) != 0 {
		t.Fatal("key was re-created")
	}
	h.enrol() // new agent: the dead store is discarded
	if b, err := os.ReadFile(key); err != nil || len(b) != 32 {
		t.Fatalf("after re-enrol: %d bytes, %v", len(b), err)
	}
	h.start()
	h.waitSynced()
}

func TestEventRetriesBackOffExponentially(t *testing.T) {
	s := &sessState{retry: transport.Backoff{Min: time.Second, Max: 8 * time.Second, Factor: 2, Rand: func() float64 { return 0.5 }}}
	var delays []time.Duration
	for range 6 {
		s.needRetry = false
		before := time.Now()
		s.mu.Lock()
		s.scheduleRetryLocked()
		s.mu.Unlock()
		delays = append(delays, s.retryAt.Sub(before).Round(100*time.Millisecond))
	}
	want := []time.Duration{1, 2, 4, 8, 8, 8}
	for i, w := range want {
		if delays[i] != w*time.Second {
			t.Fatalf("delays %v, want 1s,2s,4s,8s then capped at 8s", delays)
		}
	}
	// One round schedules once: a second failure in the same round does not push it out.
	s.needRetry = false
	s.scheduleRetryLocked()
	at := s.retryAt
	s.scheduleRetryLocked()
	if !s.retryAt.Equal(at) {
		t.Fatal("scheduling twice in one round moved the retry time")
	}
	s.retry.Reset()
	s.needRetry = false
	s.scheduleRetryLocked()
	if d := time.Until(s.retryAt); d > 1500*time.Millisecond {
		t.Fatalf("after a success the backoff must restart at its minimum, got %v", d)
	}
}
