//go:build unix

package jobs

import (
	"path/filepath"
	"testing"
)

func TestSingleExecutor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executor.lock")
	first, err := LockExecutor(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := LockExecutor(path); err == nil {
		other.Close()
		t.Fatal("second executor acquired lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := LockExecutor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
}
