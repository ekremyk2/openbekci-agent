//go:build !windows

package agent

import "os"

// renameDurable renames tmp over path; durability of the rename comes from
// syncDir.
func renameDurable(tmp, path string) error { return os.Rename(tmp, path) }

// syncDir fsyncs a directory so a completed rename survives a power loss.
func syncDir(dir string) error {
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
