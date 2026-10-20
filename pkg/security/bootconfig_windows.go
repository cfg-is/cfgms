// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// fileID is the Windows file identity: it is the same for every name (8.3
// short name, junction path, hard link, case variant) that reaches one file.
type fileID struct {
	volume    uint32
	indexHigh uint32
	indexLow  uint32
}

// canonPath is the deepest existing ancestor's identity plus the normalized
// names of the not-yet-existing components below it. A target that does not
// exist yet is therefore compared by its canonical parent plus leaf name.
type canonPath struct {
	id   fileID
	rest string // normalized, separator-joined, empty when the path exists
}

// isProtectedBootConfigPath fails closed: whenever the canonical identity of
// the target or of a boot-config location cannot be established, the path is
// reported protected.
func isProtectedBootConfigPath(path string) bool {
	if hasDeviceOrStreamSyntax(path) {
		return true
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return true
	}
	target, err := canonicalize(abs)
	if err != nil {
		return true
	}
	for _, dir := range BootConfigDirs() {
		d, err := canonicalize(dir)
		if err != nil {
			return true
		}
		if d == target {
			return true
		}
		for _, name := range BootConfigFileNames() {
			f, err := canonicalize(filepath.Join(dir, name))
			if err != nil {
				return true
			}
			if f == target {
				return true
			}
		}
	}
	return false
}

// hasDeviceOrStreamSyntax reports a \\?\ or \\.\ device prefix, or a colon
// after the volume name (alternate data stream such as steward.cfg::$DATA).
func hasDeviceOrStreamSyntax(path string) bool {
	p := strings.ReplaceAll(path, "/", `\`)
	for _, prefix := range []string{`\\?\`, `\\.\`, `\??\`} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return strings.Contains(p[len(filepath.VolumeName(p)):], ":")
}

// canonicalize resolves abs to the identity of its deepest existing ancestor
// plus the normalized remainder. Any error other than "not found" is returned.
func canonicalize(abs string) (canonPath, error) {
	p := filepath.Clean(abs)
	var rest []string
	for {
		id, err := openIdentity(p, true)
		if err == nil {
			return canonPath{id: id, rest: strings.Join(rest, `\`)}, nil
		}
		if !isNotFound(err) {
			return canonPath{}, err
		}
		// A dangling link reaches a file that does not exist yet; its
		// destination is unknown, so refuse rather than guess.
		if _, lerr := openIdentity(p, false); lerr == nil {
			return canonPath{}, err
		}
		parent, leaf := filepath.Split(p)
		parent = filepath.Clean(parent)
		if leaf == "" || parent == p {
			return canonPath{}, err
		}
		rest = append([]string{normalizeLeaf(leaf)}, rest...)
		p = parent
	}
}

// normalizeLeaf case-folds a not-yet-existing name and strips the trailing
// dots and spaces Win32 ignores. Existing names (including 8.3 aliases) are
// compared by file identity, so they never reach this function.
func normalizeLeaf(leaf string) string {
	return strings.ToLower(strings.TrimRight(leaf, ". "))
}

func isNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

// openIdentity returns the file ID of path. With follow=false a reparse point
// is opened itself instead of its target.
func openIdentity(path string, follow bool) (fileID, error) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fileID{}, err
	}
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if !follow {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, err := windows.CreateFile(p16, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return fileID{}, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fileID{}, err
	}
	return fileID{volume: info.VolumeSerialNumber, indexHigh: info.FileIndexHigh, indexLow: info.FileIndexLow}, nil
}
