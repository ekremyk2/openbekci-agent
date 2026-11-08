//go:build !windows

package fsutil

import "os"

// SecureDir makes dir accessible to its owner only (mode 0700).
func SecureDir(dir string) error { return os.Chmod(dir, 0o700) }

// SecureFile makes path readable and writable by its owner only (mode 0600).
func SecureFile(path string) error { return os.Chmod(path, 0o600) }

// OwnerOnly reports whether path grants nothing to group or others.
func OwnerOnly(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().Perm()&0o077 == 0, nil
}
