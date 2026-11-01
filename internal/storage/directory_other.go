//go:build !linux

package storage

// Local portability only. Production requires Linux directory locks for safe
// coordination with systemd-tmpfiles and directory fsync for durability.
func lockDirectory(path string) (func(), error) { return func() {}, nil }
func syncDirectory(path string) error           { return nil }
