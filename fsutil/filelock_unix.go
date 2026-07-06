//go:build !windows

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

// ErrLocked is returned by TryLock* when another process already holds the lock.
var ErrLocked = errors.New("fsutil: file is locked by another process")

// TryLockExclusive attempts a non-blocking exclusive lock on f. Returns
// ErrLocked if another process holds any lock on f. The lock is released
// automatically when f is closed, or explicitly via Unlock.
func TryLockExclusive(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == syscall.EWOULDBLOCK {
		return ErrLocked
	}
	return err
}

// LockExclusive blocks until an exclusive lock can be acquired on f.
func LockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// LockShared blocks until a shared (read) lock can be acquired on f.
// Multiple shared holders may coexist, but no exclusive holder.
func LockShared(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_SH)
}

// TryLockShared attempts a non-blocking shared lock on f. Returns ErrLocked
// if an exclusive holder exists.
func TryLockShared(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == syscall.EWOULDBLOCK {
		return ErrLocked
	}
	return err
}

// Unlock releases whatever lock is held on f. Safe to defer; closing f also
// releases the lock (this is idempotent).
func Unlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
