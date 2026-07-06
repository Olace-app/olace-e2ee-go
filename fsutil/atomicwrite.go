// Package fsutil provides the atomic file persistence used by the Olace
// daemon for key material and shared state files. A torn write to a file
// like identity.enc would lock a user out of their paired sessions, so
// every persisted write goes through tmp file + fsync + rename.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteFileAtomic writes data to path via a tmp file + fsync + rename. On
// POSIX (and same-volume Windows moves) rename is atomic, so a concurrent
// reader either sees the old contents or the new contents — never a partial
// write. Callers writing state files that other processes read (the Olace
// app and daemon share a state directory) should use this instead of
// os.WriteFile.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if we bail before the rename succeeds.
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename tmp: %w", err)
	}
	return nil
}

// sweepTmpMinAge is the minimum age a tmp file must reach before sweep
// will remove it. A well-behaved atomic rename completes in <1ms, so any
// sub-30s `.tmp` is by definition still in-flight — typically another
// process sharing the state directory racing this process's startup.
// A caller's own writes are expected to be serialized (the Olace daemon
// holds a startup flock), so the threshold only guards the cross-process
// case.
const sweepTmpMinAge = 30 * time.Second

// SweepStaleTempsIn removes leftover tmp files from dir — both the
// `<base>.tmp.<suffix>` form produced by os.CreateTemp and the bare
// `<base>.tmp` form used by other atomic writers sharing the directory.
// Tmp files are normally cleaned up on success by rename or on error by
// deferred Remove, but a SIGKILL or forced shutdown between write and
// rename leaves orphans behind. Call this once at startup. Files newer
// than sweepTmpMinAge are left alone to avoid stealing another writer's
// in-flight rename target.
func SweepStaleTempsIn(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read dir: %w", err)
	}
	cutoff := time.Now().Add(-sweepTmpMinAge)
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Match `<base>.tmp.<suffix>` (os.CreateTemp output) AND
		// `<base>.tmp` (bare suffix used by manual atomic writers).
		// The substring test must come first so a literal `.tmp.x`
		// filename (no real base name before `.tmp`) is excluded by
		// the same guard the original implementation had.
		if !strings.Contains(name, ".tmp.") && !strings.HasSuffix(name, ".tmp") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			// In-flight write — leave it to its owner's rename.
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err == nil {
			removed++
		}
	}
	return removed, nil
}
