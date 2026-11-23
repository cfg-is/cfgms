// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package sops

import (
	"time"

	"golang.org/x/sys/windows"
)

// setLockFileModTime sets path's modification time to t. os.Chtimes opens the
// file with FILE_SHARE_WRITE only, so it fails with a sharing violation while the
// lock holder has the file open; this opens a fully shared attribute-only handle.
func setLockFileModTime(path string, t time.Time) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	ft := windows.NsecToFiletime(t.UnixNano())
	return windows.SetFileTime(h, nil, &ft, &ft)
}
