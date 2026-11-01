// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens path without traversing a reparse point at the final component.
//
// The file is opened with FILE_FLAG_OPEN_REPARSE_POINT, so a symlink or junction at the
// leaf is opened as the link itself rather than followed. The handle's attributes are then
// checked and the open is refused if they show a reparse point. The open and the check act
// on the same object, so a leaf swapped after validation cannot be followed.
//
// O_TRUNC is deliberately not mapped to TRUNCATE_EXISTING / CREATE_ALWAYS: those would act
// before the reparse check. The file is opened with a non-destructive disposition and
// truncated only after the handle has been verified.
func openNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = syscall.GENERIC_READ
	case os.O_WRONLY:
		access = syscall.GENERIC_WRITE
	case os.O_RDWR:
		access = syscall.GENERIC_READ | syscall.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 && flag&os.O_TRUNC == 0 {
		access &^= syscall.GENERIC_WRITE
		access |= syscall.FILE_APPEND_DATA
	}
	if flag&os.O_TRUNC != 0 {
		// truncation after verification needs write access
		access |= syscall.GENERIC_WRITE
	}

	var disposition uint32
	switch {
	case flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		disposition = syscall.CREATE_NEW
	case flag&os.O_CREATE != 0:
		disposition = syscall.OPEN_ALWAYS
	default:
		disposition = syscall.OPEN_EXISTING
	}

	attrs := uint32(syscall.FILE_ATTRIBUTE_NORMAL)
	if flag&os.O_CREATE != 0 && perm&0200 == 0 {
		attrs = syscall.FILE_ATTRIBUTE_READONLY
	}
	attrs |= syscall.FILE_FLAG_OPEN_REPARSE_POINT

	// #nosec G304 - callers pass a path already validated by ValidateAndCleanPath
	h, err := syscall.CreateFile(p, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, disposition, attrs, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		_ = syscall.CloseHandle(h)
		return nil, fmt.Errorf("refusing to open %s: cannot query file attributes: %w", path, err)
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = syscall.CloseHandle(h)
		return nil, fmt.Errorf("refusing to open %s: final component is a symlink or reparse point", path)
	}

	f := os.NewFile(uintptr(h), path)
	if flag&os.O_TRUNC != 0 {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, &os.PathError{Op: "truncate", Path: path, Err: err}
		}
	}
	return f, nil
}
