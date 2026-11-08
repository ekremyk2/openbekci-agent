//go:build windows

package fsutil

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// aclSIDs returns the SIDs granted by path's DACL and whether the DACL is
// protected from inheritance.
func aclSIDs(t *testing.T, path string) (sids []string, protected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	protected = ctrl&windows.SE_DACL_PROTECTED != 0
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("no DACL: %v", err)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	sort.Strings(sids)
	return sids, protected
}

func wantSIDs(t *testing.T) []string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	w := []string{"S-1-5-18", u.User.Sid.String()}
	sort.Strings(w)
	return w
}

func TestSecureDirAndFileAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, "store.key")
	if err := os.WriteFile(existing, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	want := wantSIDs(t)
	check := func(path string) {
		t.Helper()
		got, protected := aclSIDs(t, path)
		if !protected {
			t.Errorf("%s: DACL inherits from the parent (ProgramData lets Users read)", path)
		}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("%s: DACL grants %v, want exactly %v", path, got, want)
		}
	}
	check(dir)
	check(existing) // files already inside are re-protected

	// A file written atomically (token, identity) is owner-only too, and the
	// state dir's own handling keeps working for the owner.
	tok := filepath.Join(dir, "agent.token")
	if err := WriteFileAtomic(tok, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check(tok)
	for _, p := range []string{dir, existing, tok} {
		if ok, err := OwnerOnly(p); err != nil || !ok {
			t.Errorf("OwnerOnly(%s) = %v, %v", p, ok, err)
		}
	}
	open := filepath.Join(t.TempDir(), "open.txt")
	if err := os.WriteFile(open, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := OwnerOnly(open); err != nil || ok {
		t.Errorf("a file with an inherited DACL must not count as owner-only: %v, %v", ok, err)
	}
	if b, err := os.ReadFile(tok); err != nil || string(b) != "secret\n" {
		t.Fatalf("owner cannot read its own token: %v", err)
	}
}

// A file listed by SecureDir may vanish before its ACL is set (SQLite removes
// -wal/-shm when the previous process closes the database).
func TestSecureDirToleratesFilesDeletedAfterListing(t *testing.T) {
	dir := t.TempDir()
	gone := filepath.Join(dir, "store.db-shm")
	kept := filepath.Join(dir, "store.key")
	for _, p := range []string{gone, kept} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	afterList = func() { _ = os.Remove(gone) }
	defer func() { afterList = nil }()
	if err := SecureDir(dir); err != nil {
		t.Fatalf("SecureDir failed on a file that vanished: %v", err)
	}
	if ok, err := OwnerOnly(kept); err != nil || !ok {
		t.Fatalf("remaining file not secured: %v %v", ok, err)
	}
	if err := SecureFile(gone); err != nil {
		t.Fatalf("SecureFile of a missing file: %v", err)
	}
}
