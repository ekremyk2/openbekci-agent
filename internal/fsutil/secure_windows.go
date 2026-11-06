//go:build windows

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the 0600/0700 permission bits mean nothing: files inherit the
// ProgramData ACL, which usually lets the Users group read them. SecureDir and
// SecureFile replace the DACL with a protected one (no inheritance from the
// parent) that grants full control to SYSTEM and to the account the agent runs
// as, and to nobody else. Administrators can still take ownership, as on Unix
// root can read anything.

func ownerSDDL() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("current user: %w", err)
	}
	// P: protected, no inherited ACEs. OI/CI: children inherit (directories).
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + u.User.Sid.String() + ")", nil
}

func setOwnerOnlyDACL(path string) error {
	sddl, err := ownerSDDL()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// SecureDir restricts dir (and, through inheritance, everything created in it
// later) to SYSTEM and the current account, and re-applies the DACL to the
// files already inside.
func SecureDir(dir string) error {
	if err := setOwnerOnlyDACL(dir); err != nil {
		return fmt.Errorf("restrict %s to its owner: %w", dir, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := setOwnerOnlyDACL(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("restrict %s to its owner: %w", e.Name(), err)
		}
	}
	return nil
}

// SecureFile restricts one file to SYSTEM and the current account.
func SecureFile(path string) error {
	if err := setOwnerOnlyDACL(path); err != nil {
		return fmt.Errorf("restrict %s to its owner: %w", path, err)
	}
	return nil
}

// OwnerOnly reports whether path grants access to SYSTEM and the current
// account only (a directory additionally needs a protected DACL).
func OwnerOnly(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	// A directory must be protected (nothing inherited from above); a file
	// created inside it may carry the directory's inherited ACEs.
	if fi, err := os.Stat(path); err != nil {
		return false, err
	} else if fi.IsDir() && ctrl&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return false, err
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	allowed := map[string]bool{"S-1-5-18": true, u.User.Sid.String(): true}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return false, err
		}
		if !allowed[(*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()] { //nolint:gosec // reading the SID that follows the ACE header
			return false, nil
		}
	}
	return true, nil
}
