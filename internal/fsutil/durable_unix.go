//go:build !windows

package fsutil

import "os"

// RenameDurable renames tmp over path; durability of the rename comes from
// SyncDir.
func RenameDurable(tmp, path string) error { return os.Rename(tmp, path) }

// SyncDir fsyncs a directory so a completed rename survives a power loss.
func SyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // dir is the agent's own state directory
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}
