// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package flatfile

import (
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// atomicRename renames src → dst on Windows with semantics that match POSIX
// rename(2): the rename is atomic with respect to concurrent readers, who
// keep reading their handle's view of the pre-rename file until they close
// it.
//
// First choice: a POSIX-semantics rename (posixRename, Issue #4262). The
// writer opens only src and asks the filesystem to swap the name in one
// operation; it never opens dst at all, so a reader opening dst can find the
// old file or the new one but never a handle it has to share with.
//
// ReplaceFileW, the previous first choice, does not have that property. It is
// several steps inside the API -- it opens the replaced file to carry its
// attributes and ACLs across before swapping -- and while it holds that open,
// a reader's CreateFile on dst fails with ERROR_SHARING_VIOLATION even with
// every share flag set. Measured in CI (PR #4250, windows-latest): all three
// readers of TestFlatFile_CrossProcess_OneWriterManyReaders exhausted
// readFile's ~360ms retry budget on "The process cannot access the file
// because it is being used by another process".
//
// Fallback: if posixRename fails for any reason (a filesystem without POSIX
// rename semantics returns ERROR_INVALID_PARAMETER / ERROR_NOT_SUPPORTED), the
// previous behaviour runs unchanged: ReplaceFileW for an existing dst, and
// os.Rename (MoveFileEx) when dst does not exist yet.
func atomicRename(src, dst string) error {
	if err := posixRename(src, dst); err == nil {
		return nil
	}
	if err := replaceFileW(dst, src); err == nil {
		return nil
	} else if !errors.Is(err, syscall.Errno(2 /* ERROR_FILE_NOT_FOUND */)) {
		return err
	}
	// dst does not exist — first write. Plain rename is safe here because
	// there's no destination handle to contend with.
	return os.Rename(src, dst)
}

// FILE_RENAME_INFO flags for the FileRenameInfoEx class (winbase.h). Not
// exported by golang.org/x/sys/windows.
const (
	fileRenameFlagReplaceIfExists = 0x00000001
	fileRenameFlagPOSIXSemantics  = 0x00000002
)

// fileRenameInfo mirrors FILE_RENAME_INFO for the FileRenameInfoEx class,
// whose union member is the Flags DWORD. FileName is variable length; the
// buffer handed to SetFileInformationByHandle is sized to hold the whole
// name plus its terminator.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// posixRename renames src over dst with FILE_RENAME_FLAG_POSIX_SEMANTICS:
// dst's name is replaced in one filesystem operation even while readers hold
// dst open (they need FILE_SHARE_DELETE, which readFile sets), and those
// readers keep reading the old file. Only src is opened here.
func posixRename(src, dst string) error {
	absDst, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	srcW, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(absDst) // NUL-terminated
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(srcW,
		windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	nameOffset := unsafe.Offsetof(fileRenameInfo{}.FileName)
	buf := make([]byte, nameOffset+uintptr(len(name))*2)
	info := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	info.Flags = fileRenameFlagReplaceIfExists | fileRenameFlagPOSIXSemantics
	info.FileNameLength = uint32((len(name) - 1) * 2) // bytes, excluding the NUL
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	return windows.SetFileInformationByHandle(h, windows.FileRenameInfoEx, &buf[0], uint32(len(buf)))
}

// replaceFileW calls the Win32 ReplaceFileW API. dst must exist; src must
// exist; dst is replaced by src atomically. Returns the syscall errno on
// failure so the caller can switch on ERROR_FILE_NOT_FOUND for the
// first-write fallback.
func replaceFileW(dst, src string) error {
	const replaceFlagWriteThrough = 0x00000001
	dstW, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	srcW, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	r1, _, e1 := procReplaceFileW.Call(
		uintptr(unsafe.Pointer(dstW)),
		uintptr(unsafe.Pointer(srcW)),
		0, // no backup
		uintptr(replaceFlagWriteThrough),
		0, 0,
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	procReplaceFileW = kernel32.MustFindProc("ReplaceFileW")
)

// jitter returns d randomised by ±50% so concurrent readers/writers retrying
// against the same target don't fire on aligned millisecond boundaries.
// Used by readFile's retry on ERROR_SHARING_VIOLATION. The writer side does
// not retry. The reader-side retry is defense-in-depth for the fallback rename
// path (ReplaceFileW), which can hold dst open while readers try to open it.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	factor := 0.5 + rand.Float64() //nolint:gosec // jitter, not crypto
	return time.Duration(float64(d) * factor)
}

// isRetryableRenameError reports whether err is the Windows transient
// failure mode that occurs when a concurrent operation has the file open.
// Used by readFile (rename_windows is no longer the only caller after the
// ReplaceFileW switch — the name is kept for continuity with read_windows.go).
func isRetryableRenameError(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// ERROR_ACCESS_DENIED = 5, ERROR_SHARING_VIOLATION = 32
		return errno == syscall.Errno(5) || errno == syscall.Errno(32)
	}
	return false
}

// isSharingViolation reports ERROR_SHARING_VIOLATION (32): another handle's
// share mode refused this open. Lets the cross-process test tell that apart
// from a torn read, which is a different defect (Issue #4262).
func isSharingViolation(err error) bool {
	return errors.Is(err, syscall.Errno(32))
}
