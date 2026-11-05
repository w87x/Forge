//go:build unix

package jobs

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ExecutorLock ensures a SQLite installation has only one active executor.
type ExecutorLock struct{ file *os.File }

func LockExecutor(path string) (*ExecutorLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("executor already running or lock unavailable: %w", err)
	}
	return &ExecutorLock{file: f}, nil
}
func (l *ExecutorLock) Close() error {
	if l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return closeErr
}
