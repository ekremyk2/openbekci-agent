//go:build !windows

package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// SecureDir makes dir accessible to its owner only (mode 0700) and, like the
// Windows build, restricts the files already inside it to mode 0600. A file
// that vanishes meanwhile (SQLite removes its -wal and -shm on close) is not an
// error.
func SecureDir(dir string) error {
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // 0700 is the owner-only directory mode, not too permissive
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := SecureFile(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("restrict %s to its owner: %w", e.Name(), err)
		}
	}
	return nil
}

// SecureFile makes path readable and writable by its owner only (mode 0600).
// A file that no longer exists is not an error.
func SecureFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// OwnerOnly reports whether path grants nothing to group or others.
func OwnerOnly(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().Perm()&0o077 == 0, nil
}
