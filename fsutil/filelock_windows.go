//go:build windows

package fsutil

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// ErrLocked is returned by TryLock* when another process already holds the lock.
var ErrLocked = errors.New("fsutil: file is locked by another process")

// Lock the entire file by claiming the maximum byte range. Unlock must use
// the same range.
const (
	lockRangeLow  = ^uint32(0)
	lockRangeHigh = ^uint32(0)
)

// TryLockExclusive attempts a non-blocking exclusive lock on f. Returns
// ErrLocked if another process holds any lock on f. The lock is released
// when f is closed, or via Unlock.
func TryLockExclusive(f *os.File) error {
	ol := &windows.Overlapped{}
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		lockRangeLow, lockRangeHigh,
		ol,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
			errors.Is(err, windows.ERROR_IO_PENDING) {
			return ErrLocked
		}
		return err
	}
	return nil
}

// LockExclusive blocks until an exclusive lock can be acquired on f.
func LockExclusive(f *os.File) error {
	ol := &windows.Overlapped{}
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		lockRangeLow, lockRangeHigh,
		ol,
	)
}

// LockShared blocks until a shared (read) lock can be acquired on f.
// LockFileEx with no flags = shared, blocking.
func LockShared(f *os.File) error {
	ol := &windows.Overlapped{}
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		0,
		0,
		lockRangeLow, lockRangeHigh,
		ol,
	)
}

// TryLockShared attempts a non-blocking shared lock on f.
func TryLockShared(f *os.File) error {
	ol := &windows.Overlapped{}
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		lockRangeLow, lockRangeHigh,
		ol,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
			errors.Is(err, windows.ERROR_IO_PENDING) {
			return ErrLocked
		}
		return err
	}
	return nil
}

// Unlock releases whatever lock is held on f over the full range.
func Unlock(f *os.File) error {
	ol := &windows.Overlapped{}
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0,
		lockRangeLow, lockRangeHigh,
		ol,
	)
}
