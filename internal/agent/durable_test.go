package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicReplacesAndSyncsDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFile)
	for _, v := range []string{"first", "second"} {
		if err := writeFileAtomic(path, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(path); string(b) != v {
			t.Fatalf("got %q want %q", b, v)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*")); len(m) != 0 {
		t.Fatalf("temp files left: %v", m)
	}
	if err := syncDir(dir); err != nil {
		t.Fatalf("syncDir: %v", err)
	}
	if err := syncDir(filepath.Join(dir, "missing")); err == nil && os.PathSeparator == '/' {
		t.Fatal("syncDir of a missing directory must fail where directories can be synced")
	}
}
