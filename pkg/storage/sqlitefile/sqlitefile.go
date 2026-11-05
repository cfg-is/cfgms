// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package sqlitefile holds the owner-only file-mode helper shared by every
// controller-side SQLite open site. It is stateless and is not a storage provider.
package sqlitefile

import (
	"os"
	"path/filepath"
	"strings"
)

// Prepare pre-creates the database file owner-only (0600) so that SQLite, which
// gives the -wal and -shm side files the main file's mode, never creates any of
// them world-readable. An existing file is left untouched. In-memory and empty
// targets are ignored. Call it immediately before sql.Open("sqlite", ...).
// Unix mode bits only; Windows ACLs are not handled here.
func Prepare(dsnOrPath string) error {
	if strings.Contains(dsnOrPath, "mode=memory") {
		return nil
	}
	path := strings.TrimPrefix(dsnOrPath, "file:")
	if path != dsnOrPath {
		path = strings.TrimPrefix(path, "//")
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" || path == ":memory:" {
		return nil
	}
	path = filepath.Clean(path)
	// #nosec G304 -- operator-configured database path (storage config/DSN); same target sql.Open opens next
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}
