package agent

import (
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
