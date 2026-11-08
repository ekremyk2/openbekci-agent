//go:build windows

package fsutil

import "golang.org/x/sys/windows"

// RenameDurable replaces path with tmp and does not return before the rename
// is on disk (MOVEFILE_WRITE_THROUGH): Windows cannot fsync a directory.
func RenameDurable(tmp, path string) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// SyncDir is a no-op on Windows; RenameDurable already wrote through.
func SyncDir(string) error { return nil }
