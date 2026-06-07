// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Layout describes the on-disk binary layout the launcher manages.
//
//	<Root>/
//	    cfgms-steward-launcher.exe       ← the OS service binary
//	    current.txt                       ← name of the currently-active version
//	    previous.txt                      ← name of the previous-good version (for rollback)
//	    versions/
//	        <name1>/
//	            cfgms-steward(.exe)
//	        <name2>/
//	            cfgms-steward(.exe)
//
// Version "name" is operator-chosen — typically a content hash, semver, or
// short slug. The launcher never assigns one; the caller of swap() decides.
// This keeps the launcher boring + free of any hashing/dependency surface.
type Layout struct {
	// Root is the install directory. On Windows that's C:\Program Files\CFGMS;
	// on Linux it might be /opt/cfgms or /usr/local/cfgms; on macOS
	// /usr/local/cfgms. Default flag picks the OS-conventional location;
	// operators can override with --root for testing or non-standard installs.
	Root string

	// StewardBinaryName is the file name the steward binary lives under
	// inside each versions/<name>/ directory. Platform-default
	// "cfgms-steward.exe" on Windows; "cfgms-steward" on Unix. The launcher
	// never opens this file directly — only exec's it — so the lookup
	// happens just before fork.
	StewardBinaryName string
}

// CurrentPath returns the path of the file recording the active version
// name. The file's contents (a single line, no decoration) name the
// subdirectory under versions/ to exec from.
func (l Layout) CurrentPath() string { return filepath.Join(l.Root, "current.txt") }

// PreviousPath returns the path of the file recording the previous-good
// version name. Used by Rollback().
func (l Layout) PreviousPath() string { return filepath.Join(l.Root, "previous.txt") }

// VersionsDir returns the path of the directory holding all installed
// steward binary versions.
func (l Layout) VersionsDir() string { return filepath.Join(l.Root, "versions") }

// StewardExeFor returns the path of the steward binary inside the named
// version directory. The version is the operator-chosen subdirectory
// name; the launcher never validates it beyond rejecting empty strings
// and obvious path traversal.
func (l Layout) StewardExeFor(version string) (string, error) {
	if err := validateVersion(version); err != nil {
		return "", err
	}
	return filepath.Join(l.VersionsDir(), version, l.StewardBinaryName), nil
}

// validateVersion rejects empty strings and path-traversal candidates so a
// malformed current.txt or operator typo can't read or write outside the
// versions directory. The launcher never tries to *interpret* the version
// name beyond this check — version IDs are opaque tags chosen by the
// operator (typically a content hash or semver).
func validateVersion(v string) error {
	if v == "" {
		return errors.New("launcher: version name must not be empty")
	}
	if strings.Contains(v, "..") || strings.ContainsRune(v, '/') || strings.ContainsRune(v, '\\') {
		return fmt.Errorf("launcher: version name must not contain path separators or dot sequences: %q", v)
	}
	return nil
}

// ReadCurrent returns the version name recorded in current.txt. Empty
// string + nil error means "no version currently active" — caller decides
// whether that's a fresh install or a configuration error.
func (l Layout) ReadCurrent() (string, error) {
	return readVersionFile(l.CurrentPath())
}

// ReadPrevious returns the version name recorded in previous.txt. Empty
// string + nil error means "no rollback target available."
func (l Layout) ReadPrevious() (string, error) {
	return readVersionFile(l.PreviousPath())
}

// WriteCurrent atomically updates the active version. The previous value
// is preserved in previous.txt so Rollback() can restore it.
//
// Atomicity is achieved by writing to a sibling temp file then renaming
// over the target — on every supported OS, rename of a file within the
// same directory is atomic with respect to readers that open by path.
func (l Layout) WriteCurrent(version string) error {
	if err := validateVersion(version); err != nil {
		return err
	}
	// Stash the existing current as previous (so rollback can restore it).
	if existing, err := l.ReadCurrent(); err == nil && existing != "" && existing != version {
		if writeErr := writeVersionFile(l.PreviousPath(), existing); writeErr != nil {
			return fmt.Errorf("launcher: stage previous version: %w", writeErr)
		}
	}
	return writeVersionFile(l.CurrentPath(), version)
}

// Rollback swaps current and previous: the previously-recorded version
// becomes active, and the currently-active version is recorded as the new
// previous (so the rollback itself is reversible).
//
// Returns the name of the newly-active version on success.
func (l Layout) Rollback() (string, error) {
	current, err := l.ReadCurrent()
	if err != nil {
		return "", fmt.Errorf("launcher: read current: %w", err)
	}
	previous, err := l.ReadPrevious()
	if err != nil {
		return "", fmt.Errorf("launcher: read previous: %w", err)
	}
	if previous == "" {
		return "", errors.New("launcher: no previous version recorded — nothing to roll back to")
	}
	if err := writeVersionFile(l.CurrentPath(), previous); err != nil {
		return "", fmt.Errorf("launcher: write current during rollback: %w", err)
	}
	if err := writeVersionFile(l.PreviousPath(), current); err != nil {
		return "", fmt.Errorf("launcher: write previous during rollback: %w", err)
	}
	return previous, nil
}

func readVersionFile(p string) (string, error) {
	b, err := os.ReadFile(p) //#nosec G304 -- launcher owns these paths
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeVersionFile(p, value string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(value+"\n"), 0o644); err != nil { //#nosec G306 -- version pointers are plaintext, no secrets
		return err
	}
	return os.Rename(tmp, p)
}
