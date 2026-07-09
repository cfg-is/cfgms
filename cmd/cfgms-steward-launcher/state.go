// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Layout describes the on-disk binary layout the launcher manages.
//
//	<Root>/
//	    cfgms-steward-launcher.exe   ← the OS service binary
//	    state.json                    ← {current, previous} written atomically
//	    versions/
//	        <name1>/cfgms-steward(.exe)
//	        <name2>/cfgms-steward(.exe)
//
// Version "name" is operator-chosen — typically a content hash, semver, or
// short slug. The launcher never assigns one; the caller of swap() decides.
// This keeps the launcher boring + free of any hashing/dependency surface.
//
// # Why a single state.json
//
// Earlier revisions stored current + previous in separate files
// (current.txt, previous.txt). A crash between writing one and writing
// the other could leave the launcher's pointer state inconsistent
// (e.g. current.txt pointed at the broken upgrade but previous.txt
// still pointed at the version BEFORE the previous-known-good). A
// single JSON document written via temp-file + rename is atomic under
// every supported filesystem and removes the two-write window
// entirely. Old single-file pointers (current.txt / previous.txt) are
// still read on startup if state.json is missing — one-time migration
// for installations that booted before this commit.
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

// pointerState is the JSON document persisted to state.json. Older
// installations may not have this file yet, in which case the loader
// falls back to the deprecated single-line pointer files (current.txt /
// previous.txt).
type pointerState struct {
	Current             string `json:"current"`
	Previous            string `json:"previous,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures,omitempty"`
	// KnownGood and KnownGoodHash record the version and SHA-256 content
	// hash of the last binary that survived StartupWindow. Both fields
	// must match the live binary for the marker to be considered valid —
	// a version-tag reuse or an on-disk replacement voids it.
	// The marker gates auto-rollback policy only; it is not a security
	// control (see security note in Issue #2033).
	KnownGood     string `json:"known_good,omitempty"`
	KnownGoodHash string `json:"known_good_hash,omitempty"`
}

// StatePath returns the path of the single JSON document that records
// both the active version and the previous-good version.
func (l Layout) StatePath() string { return filepath.Join(l.Root, "state.json") }

// CurrentPath returns the path of the legacy single-line pointer file
// recording the active version name. Kept for the one-time migration
// path; new writes always go to state.json.
func (l Layout) CurrentPath() string { return filepath.Join(l.Root, "current.txt") }

// PreviousPath returns the path of the legacy single-line pointer file
// recording the previous-good version name. Kept for the migration path.
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
// malformed state file or operator typo can't read or write outside the
// versions directory. The launcher never tries to *interpret* the version
// name beyond this check — version IDs are opaque tags chosen by the
// operator (typically a content hash or semver).
//
// The ".." check rejects the substring (not just the exact value)
// because filepath.Join("a..b") still produces an in-bounds path on
// every platform — but a value like "../../etc/passwd" would escape.
// Multi-dot semver pre-release tags ("v1.2.3-beta..1") are rejected;
// operators using semver should drop the empty segment.
func validateVersion(v string) error {
	if v == "" {
		return errors.New("launcher: version name must not be empty")
	}
	if strings.Contains(v, "..") || strings.ContainsRune(v, '/') || strings.ContainsRune(v, '\\') {
		return fmt.Errorf("launcher: version name must not contain path separators or dot sequences: %q", v)
	}
	return nil
}

// computeBinaryHash returns the hex-encoded SHA-256 digest of the file at path.
// The hash is paired with the version tag in the known-good marker so that a
// tag reused for different binary content cannot suppress rollback for that
// new content.
func computeBinaryHash(path string) (string, error) {
	f, err := os.Open(path) //#nosec G304 -- path comes from Layout.StewardExeFor which validates the version tag
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// loadState reads the combined pointer state. If state.json exists it
// is the source of truth; otherwise the loader falls back to the two
// legacy pointer files for the one-time migration. Missing state with
// missing legacy files is reported as zero-value (Current=="", no error)
// so callers can distinguish "fresh install" from "read error."
func (l Layout) loadState() (pointerState, error) {
	if raw, err := os.ReadFile(l.StatePath()); err == nil { //#nosec G304 -- launcher owns its install root
		var ps pointerState
		if jerr := json.Unmarshal(raw, &ps); jerr != nil {
			return pointerState{}, fmt.Errorf("launcher: parse state.json: %w", jerr)
		}
		return ps, nil
	} else if !os.IsNotExist(err) {
		return pointerState{}, err
	}
	// Legacy fallback: synthesise from the old single-line files.
	cur, err := readLegacyPointer(l.CurrentPath())
	if err != nil {
		return pointerState{}, err
	}
	prev, err := readLegacyPointer(l.PreviousPath())
	if err != nil {
		return pointerState{}, err
	}
	return pointerState{Current: cur, Previous: prev}, nil
}

// saveState writes the combined pointer state atomically. The whole
// document lands via temp-file + rename so a reader is guaranteed to
// observe either the pre-write state or the post-write state — never
// a partially-updated one.
func (l Layout) saveState(ps pointerState) error {
	if err := os.MkdirAll(l.Root, 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	statePath := l.StatePath()
	dir := filepath.Dir(statePath)
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, statePath); err != nil {
		return err
	}
	success = true
	return nil
}

// readLegacyPointer reads a deprecated single-line pointer file.
// Returns "" on os.IsNotExist so callers can treat "no legacy file"
// as "no pointer" without distinguishing it from "couldn't read."
func readLegacyPointer(p string) (string, error) {
	b, err := os.ReadFile(p) //#nosec G304 -- launcher owns these paths
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ReadCurrent returns the version name currently active. Empty string +
// nil error means "no version currently active."
func (l Layout) ReadCurrent() (string, error) {
	ps, err := l.loadState()
	return ps.Current, err
}

// ReadPrevious returns the version name recorded as the previous-good
// rollback target. Empty string + nil error means "no rollback target
// available."
func (l Layout) ReadPrevious() (string, error) {
	ps, err := l.loadState()
	return ps.Previous, err
}

// WriteCurrent atomically updates the active version. The previously
// active version (if any, and if different) is preserved in the
// "previous" slot so Rollback() can restore it.
//
// Both fields land in one rename operation, so a crash mid-call leaves
// the launcher in either the pre-call or post-call state — never a
// partial one. This is the property that the earlier two-file
// representation could not provide.
func (l Layout) WriteCurrent(version string) error {
	if err := validateVersion(version); err != nil {
		return err
	}
	ps, err := l.loadState()
	if err != nil {
		return err
	}
	if ps.Current != "" && ps.Current != version {
		ps.Previous = ps.Current
		// Changing to a new version: the incoming binary enters probation
		// regardless of any prior known-good marker. Clearing here ensures
		// a controller-pushed security patch (vB) cannot be rolled back to
		// a known-good-but-vulnerable vA if vB fast-exits (Issue #2033 AC6).
		ps.KnownGood = ""
		ps.KnownGoodHash = ""
	}
	ps.Current = version
	return l.saveState(ps)
}

// Rollback swaps current and previous: the previously-recorded version
// becomes active, and the currently-active version is recorded as the new
// previous (so the rollback itself is reversible). Both fields update
// in one atomic rename.
//
// Returns the name of the newly-active version on success.
func (l Layout) Rollback() (string, error) {
	ps, err := l.loadState()
	if err != nil {
		return "", err
	}
	if ps.Previous == "" {
		return "", errors.New("launcher: no previous version recorded — nothing to roll back to")
	}
	newPS := pointerState{
		Current:             ps.Previous,
		Previous:            ps.Current,
		ConsecutiveFailures: ps.ConsecutiveFailures, // preserve counter across rollback
	}
	if err := l.saveState(newPS); err != nil {
		return "", err
	}
	return newPS.Current, nil
}
