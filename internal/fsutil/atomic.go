// Package fsutil holds the small file-system primitives the agent's secrets
// and state depend on: crash-safe atomic writes and owner-only permissions
// that mean the same thing on Linux and on Windows.
package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
)

// WriteFileAtomic writes data to path through a temp file in the same
// directory: write, fsync, rename, fsync of the directory. A crash or power
// loss leaves either the old or the new file, never a partial one. The file
// is owner-only (see SecureFile).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if err := f.Chmod(perm); err != nil && !isWindows() {
		_ = f.Close()
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := SecureFile(tmp); err != nil {
		cleanup()
		return err
	}
	if err := RenameDurable(tmp, path); err != nil {
		cleanup()
		return err
	}
	// The rename itself must survive a power loss, or the old content comes
	// back after a rotation.
	return SyncDir(dir)
}

func isWindows() bool { return runtime.GOOS == "windows" }
