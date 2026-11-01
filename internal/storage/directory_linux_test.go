//go:build linux

package storage

import (
	"os"
	"syscall"
	"testing"
)

func TestDirectoryLockExcludesCleanupTraversal(t *testing.T) {
	path := t.TempDir()
	unlock, err := lockDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	other, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	err = syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != syscall.EWOULDBLOCK {
		t.Fatalf("directory lock is not held: %v", err)
	}
}
