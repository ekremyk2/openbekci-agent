package agent

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/openbekci/openbekci-agent/internal/store"
	"path/filepath"
	"testing"

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
