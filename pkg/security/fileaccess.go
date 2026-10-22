// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package security provides secure file access utilities for CFGMS.
//
// This package implements centralized security controls for file operations,
// including path validation, directory traversal prevention, and secure
// permission defaults.
//
// Basic usage:
//
//	// Secure file reading with path validation
//	data, err := security.SecureReadFile("/safe/base/path", userProvidedPath)
//
//	// Secure file writing with proper permissions
//	err := security.SecureWriteFile("/safe/base/path", userProvidedPath, data)
package security

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SecureReadFile safely reads a file with path validation and directory traversal prevention.
//
// basePath is the allowed base directory - all file access must be within this directory.
// userPath is the user-provided path that will be cleaned and validated.
//
// Returns an error if:
// - The resolved path is outside the base directory (directory traversal attempt)
// - The file cannot be read
// - Path validation fails
func SecureReadFile(basePath, userPath string) ([]byte, error) {
	validatedPath, err := ValidateAndCleanPath(basePath, userPath)
	if err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	// ValidateAndCleanPath returns the symlink-resolved path, so a link that
	// exists now would never reach openNoFollow. Refuse it on the caller's
	// pre-resolution path.
	rawAbsBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base path: %w", err)
	}
	callerPath := filepath.Clean(userPath)
	if !filepath.IsAbs(callerPath) {
		callerPath = filepath.Join(rawAbsBasePath, callerPath)
	}
	if info, lerr := os.Lstat(callerPath); lerr == nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fmt.Errorf("refusing to read %q: %w", userPath, ErrSymlinkInPath)
	}

	return readValidatedFile(validatedPath)
}

// readValidatedFile opens path without following a link at the final
// component, requires a regular file on the open handle, and reads from that
// handle, so a link swapped in after validation is refused.
func readValidatedFile(path string) ([]byte, error) {
	f, err := openNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrNotRegularFile, path)
	}
	return io.ReadAll(f)
}

// ErrNotRegularFile reports that a path names something other than a regular file.
var ErrNotRegularFile = errors.New("not a regular file")

// ErrSymlinkInPath reports that a path component is a symbolic link.
var ErrSymlinkInPath = errors.New("symbolic link in path")

// ReadRegularFileNoSymlinks reads relPath from inside the directory baseDir
// without following any symbolic link. The read goes through an os.Root scoped
// to baseDir, so nothing can resolve outside it. Every path component is
// checked with Lstat and a link anywhere in the path (including a directory in
// the middle) is refused with ErrSymlinkInPath. The type is checked on the open
// handle, and anything but a regular file is refused with ErrNotRegularFile.
// A missing file returns an error satisfying os.IsNotExist. The handle's
// FileInfo is returned so callers need not stat the path a second time.
func ReadRegularFileNoSymlinks(baseDir, relPath string) ([]byte, os.FileInfo, error) {
	rel := filepath.FromSlash(relPath)
	if !filepath.IsLocal(rel) {
		return nil, nil, fmt.Errorf("path %q escapes the base directory", relPath)
	}
	rel = filepath.Clean(rel)

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()

	parts := strings.Split(rel, string(filepath.Separator))
	for i := range parts {
		info, lerr := root.Lstat(filepath.Join(parts[:i+1]...))
		if lerr != nil {
			return nil, nil, lerr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, ErrSymlinkInPath
		}
	}

	f, err := root.Open(rel)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ErrNotRegularFile
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return data, info, nil
}

// SecureWriteFile safely writes a file with path validation and secure permissions.
//
// Files are written with 0600 permissions (owner read/write only) by default.
// Directories are created with 0750 permissions if they don't exist.
func SecureWriteFile(basePath, userPath string, data []byte) error {
	validatedPath, err := ValidateAndCleanPath(basePath, userPath)
	if err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	return writeFileInRoot(basePath, userPath, validatedPath, data, 0600)
}

// SecureWriteFileWithPerms writes a file with custom permissions after path validation.
//
// Use this when you need specific permissions (e.g., 0700 for executable files).
func SecureWriteFileWithPerms(basePath, userPath string, data []byte, perm os.FileMode) error {
	validatedPath, err := ValidateAndCleanPath(basePath, userPath)
	if err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	return writeFileInRoot(basePath, userPath, validatedPath, data, perm)
}

// SecureOpenFile safely opens a file with path validation.
//
// Returns an *os.File that must be closed by the caller.
func SecureOpenFile(basePath, userPath string, flag int, perm os.FileMode) (*os.File, error) {
	validatedPath, err := ValidateAndCleanPath(basePath, userPath)
	if err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	// #nosec G304 - Secure file access wrapper with comprehensive path validation
	// This function specifically prevents directory traversal attacks
	return openNoFollow(validatedPath, flag, perm)
}

// ValidateAndCleanPath validates a user-provided path against a base directory.
//
// This function:
//  1. Cleans the user path using filepath.Clean()
//  2. Resolves both paths to absolute paths
//  3. Eval-symlinks the base path so the final containment comparison uses canonical paths.
//     The pre-resolution form (rawAbsBasePath) is kept for the raw-form containment checks
//     so both sides are compared in the same (unresolved) form.
//  4. Performs a preliminary containment check in raw form BEFORE touching the filesystem:
//     a path already outside the base is rejected as a traversal attempt without calling
//     EvalSymlinks on it (so out-of-base, possibly access-restricted, files are never
//     touched and are reported as traversal rather than as a permission error — #2120)
//  5. Resolves symlinks in the user path; for non-existent targets, walks up to the
//     deepest existing ancestor, eval-symlinks it, and re-joins the non-existing remainder
//  6. Validates containment after symlink resolution using filepath.Rel (not strings.HasPrefix)
//     to prevent sibling-prefix attacks (e.g. /base_extra/secret incorrectly matching /base)
//     and symlink-escape attacks (an in-base symlink that resolves outside the base)
//
// On macOS /tmp is a symlink to /private/tmp, so t.TempDir() paths under /var/folders
// resolve to /private/var/folders after EvalSymlinks. On Windows, short path names
// (RUNNER~1) expand to long names (runneradmin). The raw-form containment checks use the
// pre-resolution base so both sides match.
//
// Returns the validated, canonicalized absolute path.
func ValidateAndCleanPath(basePath, userPath string) (string, error) {
	if basePath == "" {
		return "", fmt.Errorf("base path cannot be empty")
	}
	if userPath == "" {
		return "", fmt.Errorf("user path cannot be empty")
	}

	cleanUserPath := filepath.Clean(userPath)

	rawAbsBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base path: %w", err)
	}
	// Eval-symlink base so the final containment comparison uses canonical paths.
	// rawAbsBasePath (pre-resolution) is used for the preliminary check below.
	absBasePath, err := filepath.EvalSymlinks(rawAbsBasePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base path symlinks: %w", err)
	}

	var absUserPath string
	if filepath.IsAbs(cleanUserPath) {
		absUserPath = cleanUserPath
	} else {
		// Join with rawAbsBasePath so both sides of the preliminary containment check
		// are in the same pre-symlink-resolved form.
		absUserPath = filepath.Join(rawAbsBasePath, cleanUserPath)
	}

	// Preliminary containment check in raw (pre-symlink-resolution) form, BEFORE
	// touching the filesystem. If the path is already outside the base, it is a
	// traversal attempt — reject it now rather than calling EvalSymlinks on a path
	// outside the sandbox. This both (a) avoids touching out-of-base files at all,
	// and (b) ensures an out-of-base path that exists but is inaccessible (e.g. an
	// ACL-protected file on Windows such as C:\Windows\System32\config\sam) is
	// reported as a traversal attempt instead of an incidental "permission denied"
	// from EvalSymlinks (#2120). A symlink inside the base that escapes is still
	// caught by the final containmentCheck after resolution below.
	if rawRel, rawRelErr := filepath.Rel(rawAbsBasePath, absUserPath); rawRelErr != nil ||
		rawRel == ".." || strings.HasPrefix(rawRel, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(rawRel) {
		return "", fmt.Errorf("path traversal attempt detected: %s is outside %s", userPath, absBasePath)
	}

	// Resolve symlinks in the user path, with fallback for non-existent targets.
	// This must happen before the final containment check so both paths are canonical.
	resolved, resolveErr := filepath.EvalSymlinks(absUserPath)
	if resolveErr == nil {
		// EvalSymlinks leaves a Windows junction unresolved (Go 1.23+), so an existing path
		// is walked component by component like a missing tail: every reparse point on it
		// must lead back inside the base.
		rel, relErr := filepath.Rel(absBasePath, resolved)
		if relErr != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return "", fmt.Errorf("path traversal attempt detected: %s is outside %s", userPath, absBasePath)
		}
		walked, walkErr := resolveMissingTail(absBasePath, rel, userPath)
		if walkErr != nil {
			return "", walkErr
		}
		absUserPath = walked
	} else if errors.Is(resolveErr, os.ErrNotExist) {
		// Non-existent target: resolve the deepest existing ancestor, then re-join the
		// non-existing tail components. This handles paths like "newdir/newfile.txt"
		// where the parent dirs don't yet exist, and also catches ancestors that are
		// malicious or dangling symlinks.
		//
		// Preliminary check uses rawAbsBasePath (not the already-resolved absBasePath)
		// so both sides are in the same pre-resolution form. On macOS, absBasePath is
		// /private/var/... while absUserPath is still /var/...; on Windows, absBasePath
		// is the long form while absUserPath may still use short names. Using the raw
		// form avoids false "path traversal" errors for valid paths.
		rawRel, rawRelErr := filepath.Rel(rawAbsBasePath, absUserPath)
		if rawRelErr != nil || strings.HasPrefix(rawRel, "..") || filepath.IsAbs(rawRel) {
			return "", fmt.Errorf("path traversal attempt detected: %s is outside %s", userPath, absBasePath)
		}
		resolvedPath, tailErr := resolveMissingTail(absBasePath, rawRel, userPath)
		if tailErr != nil {
			return "", tailErr
		}
		absUserPath = resolvedPath
	} else {
		return "", fmt.Errorf("failed to evaluate symlinks: %w", resolveErr)
	}

	// Final containment check after full symlink resolution prevents both sibling-prefix
	// and symlink-escape attacks using canonical paths for both sides.
	if err := containmentCheck(absBasePath, absUserPath, userPath); err != nil {
		return "", err
	}

	return absUserPath, nil
}

// resolveMissingTail resolves rel (relative to the canonical base absBasePath) when the full
// path does not exist. It walks the components top-down, resolving each existing prefix with
// filepath.EvalSymlinks so the walk always stands in a fully resolved directory inside the
// base. The first component that does not resolve is probed with os.Lstat, which never follows
// the leaf, on the canonical directory already checked to be inside the base. A missing
// component starts the non-existent tail. A symlink or Windows reparse point that does not
// resolve is rejected, because re-joining it unresolved would let a later create follow it.
// An existing reparse point that EvalSymlinks returns unchanged (a live Windows junction) is
// followed to its target by followReparsePoints. A prefix that resolves outside the base,
// directly or through a junction, is rejected as traversal.
func resolveMissingTail(absBasePath, rel, userPath string) (string, error) {
	resolvedDir := absBasePath
	var components []string
	if rel != "." {
		components = strings.Split(rel, string(filepath.Separator))
	}
components:
	for i, component := range components {
		// A plain component that another process creates between EvalSymlinks failing and
		// Lstat succeeding is resolved again rather than rejected; the bound keeps a path
		// that keeps flipping from looping forever.
		for attempt := 0; attempt < maxResolveAttempts; attempt++ {
			if resolved, evalErr := filepath.EvalSymlinks(filepath.Join(resolvedDir, component)); evalErr == nil {
				inBase, err := containedPath(absBasePath, resolved, userPath)
				if err != nil {
					return "", err
				}
				followed, err := followReparsePoints(absBasePath, inBase, userPath)
				if err != nil {
					return "", err
				}
				resolvedDir = followed
				continue components
			}
			// resolvedDir is canonical and inside the base, so joining one component onto it
			// cannot traverse a link. os.Lstat never follows the leaf; on Windows it reports a
			// dangling junction as a reparse point where a Root-relative Lstat did not.
			candidate, err := containedPath(absBasePath, filepath.Join(resolvedDir, component), userPath)
			if err != nil {
				return "", err
			}
			info, lstatErr := os.Lstat(candidate)
			if lstatErr != nil {
				if os.IsPermission(lstatErr) {
					return "", fmt.Errorf("failed to inspect path component of %s: %w", userPath, lstatErr)
				}
				// Any other failure means the component does not exist (ErrNotExist, or Windows
				// ERROR_INVALID_NAME for "a:b"): it and everything after it are the new tail.
				return filepath.Join(append([]string{resolvedDir}, components[i:]...)...), nil
			}
			if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				return "", fmt.Errorf("dangling link or reparse point in path %s: refusing to follow", userPath)
			}
		}
		return "", fmt.Errorf("failed to resolve path component of %s", userPath)
	}
	return resolvedDir, nil
}

// maxResolveAttempts bounds how often resolveMissingTail re-resolves one component that
// appeared concurrently between its EvalSymlinks and Lstat checks.
const maxResolveAttempts = 3

// maxReparseHops bounds followReparsePoints so a junction cycle cannot loop forever.
const maxReparseHops = 32

// followReparsePoints returns the canonical in-base path that p, already checked to be inside
// the base, leads to. On Windows, EvalSymlinks does not evaluate mount points (Go 1.23+): a
// junction comes back unchanged with no error, and Lstat reports it as irregular. Each such
// reparse point is read with os.Readlink, its target canonicalized, and that target checked
// to be inside the base before it is followed. A dangling target, a target that cannot be
// read, or a target outside the base is rejected, so a later create can never pass through it.
func followReparsePoints(absBasePath, p, userPath string) (string, error) {
	for hops := 0; ; hops++ {
		info, err := os.Lstat(p)
		if err != nil {
			return "", fmt.Errorf("failed to inspect path component of %s: %w", userPath, err)
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			return p, nil
		}
		if hops >= maxReparseHops {
			return "", fmt.Errorf("too many links or reparse points in path %s: refusing to follow", userPath)
		}
		// Stat follows the reparse point; a dangling one fails here.
		if _, statErr := os.Stat(p); statErr != nil {
			return "", fmt.Errorf("dangling link or reparse point in path %s: refusing to follow", userPath)
		}
		target, err := os.Readlink(p)
		if err != nil {
			return "", fmt.Errorf("unresolvable link or reparse point in path %s: refusing to follow", userPath)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(p), target)
		}
		canonical, err := filepath.EvalSymlinks(target)
		if err != nil {
			return "", fmt.Errorf("unresolvable link or reparse point in path %s: refusing to follow", userPath)
		}
		if p, err = containedPath(absBasePath, canonical, userPath); err != nil {
			return "", err
		}
	}
}

// containedPath returns absPath rebuilt as absBasePath joined with its relative path, after
// the same containment rule as containmentCheck, then confirms the rebuilt path still starts
// with the base. Probes in resolveMissingTail touch only this returned path, so every
// filesystem call on a path under validation is guarded by the containment check itself.
// filepath.IsLocal is not used: on Windows it rejects a component such as "a:b", which must
// stay a not-yet-existing tail component.
func containedPath(absBasePath, absPath, userPath string) (string, error) {
	rel, err := filepath.Rel(absBasePath, absPath)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path traversal attempt detected: %s is outside %s", userPath, absBasePath)
	}
	joined := filepath.Join(absBasePath, rel)
	if !strings.HasPrefix(joined, absBasePath) {
		return "", fmt.Errorf("path traversal attempt detected: %s is outside %s", userPath, absBasePath)
	}
	return joined, nil
}

// containmentCheck verifies that absUserPath is within absBasePath using filepath.Rel.
// filepath.Rel (not strings.HasPrefix) correctly rejects sibling-prefix attacks where a
// path like /base_extra/secret would falsely pass a HasPrefix("/base") check.
func containmentCheck(absBasePath, absUserPath, userPath string) error {
	rel, err := filepath.Rel(absBasePath, absUserPath)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return fmt.Errorf("path traversal attempt detected: %s is outside %s", userPath, absBasePath)
	}
	return nil
}
