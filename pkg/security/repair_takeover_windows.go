// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// takeoverShare lets other processes read and write the object but not rename
// or delete it, so a directory held open while its children are processed
// cannot be swapped for a junction underneath the walk.
const takeoverShare = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE

// TakeOverForRepair takes ownership of every entry under roots, makes
// BUILTIN\Administrators the owner and sets the protected admin-only DACL. It
// is called only by an accepted repair, never by startup or install checks,
// which keep refusing a tampered tree (EnsureAdminOnlyDir, AdoptAdminOnlyDir
// and the Verify functions are unchanged).
//
// Every entry is opened with FILE_FLAG_OPEN_REPARSE_POINT and inspected on the
// handle, so a reparse point is never followed. A junction, symlink or other
// reparse point is deleted (the link only, never its target) and reported as
// quarantined. A regular file with more than one hard link is refused and left
// untouched: it shares its security descriptor with a path outside the root,
// so changing it would change that path too. A root that is itself a reparse
// point is refused. Paths outside roots are never opened.
func TakeOverForRepair(roots []string) (TakeoverReport, error) {
	var rep TakeoverReport
	if len(roots) == 0 {
		return rep, errors.New("repair takeover needs at least one root")
	}
	abs := make([]string, 0, len(roots))
	for _, r := range roots {
		if r == "" {
			return rep, errors.New("repair takeover root is empty")
		}
		a, err := filepath.Abs(r)
		if err != nil {
			return rep, fmt.Errorf("resolve root %q: %w", r, err)
		}
		abs = append(abs, a)
	}
	sd, err := windows.SecurityDescriptorFromString(adminOwnedSDDL)
	if err != nil {
		return rep, fmt.Errorf("build admin-owned security descriptor: %w", err)
	}
	// Administrators hold these privileges but have them disabled. They let the
	// repair take an entry whose DACL grants the administrator nothing.
	restore := enableTakeoverPrivileges()
	defer restore()

	t := &takeover{sd: sd, rep: &rep}
	for _, root := range abs {
		t.root(root)
	}
	if len(rep.Refused) > 0 {
		return rep, ErrTakeoverIncomplete
	}
	return rep, nil
}

type takeover struct {
	sd  *windows.SECURITY_DESCRIPTOR
	rep *TakeoverReport
}

func (t *takeover) refuse(path, why string) {
	t.rep.Refused = append(t.rep.Refused, path+": "+why)
}

func (t *takeover) root(path string) {
	h, err := openTakeover(path, windows.READ_CONTROL|windows.WRITE_OWNER|windows.WRITE_DAC)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return // nothing to take over
	}
	if err != nil {
		t.refuse(path, fmt.Sprintf("open root: %v", err))
		return
	}
	defer func() { _ = windows.CloseHandle(h) }()
	t.dir(h, path, true)
}

// dir handles the entry behind h and, if it is a plain directory, everything
// below it. h stays open for the whole subtree.
func (t *takeover) dir(h windows.Handle, path string, isRoot bool) {
	info, err := infoOf(h)
	if err != nil {
		t.refuse(path, fmt.Sprintf("stat: %v", err))
		return
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		// Only a root reaches here: children are classified before opening.
		t.refuse(path, "root is a link or reparse point")
		return
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		t.refuse(path, "root is not a directory")
		return
	}
	if !t.secure(h, path) {
		return
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.refuse(path, fmt.Sprintf("list directory: %v", err))
		return
	}
	for _, e := range entries {
		t.entry(filepath.Join(path, e.Name()))
	}
}

func (t *takeover) entry(path string) {
	h, err := openTakeover(path, windows.READ_CONTROL|windows.WRITE_OWNER|windows.WRITE_DAC)
	if err != nil {
		// A link we cannot open for security changes can still be removed.
		h2, err2 := openTakeover(path, windows.READ_CONTROL)
		if err2 != nil {
			t.refuse(path, fmt.Sprintf("open: %v", err))
			return
		}
		defer func() { _ = windows.CloseHandle(h2) }()
		info, ierr := infoOf(h2)
		if ierr == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			t.quarantine(path)
			return
		}
		t.refuse(path, fmt.Sprintf("open: %v", err))
		return
	}
	info, err := infoOf(h)
	if err != nil {
		_ = windows.CloseHandle(h)
		t.refuse(path, fmt.Sprintf("stat: %v", err))
		return
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		_ = windows.CloseHandle(h)
		t.quarantine(path)
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		defer func() { _ = windows.CloseHandle(h) }()
		t.dir(h, path, false)
	default:
		defer func() { _ = windows.CloseHandle(h) }()
		if info.NumberOfLinks > 1 {
			t.refuse(path, "regular file has more than one hard link and shares its security descriptor")
			return
		}
		t.secure(h, path)
	}
}

// secure sets owner and DACL on h and records the entry.
func (t *takeover) secure(h windows.Handle, path string) bool {
	secInfo := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	// NtSetSecurityObject sets exactly this object. SetSecurityInfo would also
	// push the inheritable ACEs down to every child, and through a hard link
	// that rewrites the security descriptor of a file outside the root.
	if err := ntSetSecurityObject(h, secInfo, t.sd); err != nil {
		t.refuse(path, fmt.Sprintf("take ownership: %v", err))
		return false
	}
	t.rep.Secured = append(t.rep.Secured, path)
	return true
}

var procNtSetSecurityObject = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtSetSecurityObject")

// ntSetSecurityObject applies the selected parts of sd to h without
// propagating to children.
func ntSetSecurityObject(h windows.Handle, info windows.SECURITY_INFORMATION, sd *windows.SECURITY_DESCRIPTOR) error {
	status, _, _ := procNtSetSecurityObject.Call(uintptr(h), uintptr(info), uintptr(unsafe.Pointer(sd)))
	if status != 0 {
		return windows.NTStatus(status)
	}
	return nil
}

// fileDispositionInfo is FILE_DISPOSITION_INFO.
type fileDispositionInfo struct{ DeleteFile byte }

// quarantine deletes the reparse point at path through a handle opened on the
// link itself, re-checking on that handle that it still is one.
func (t *takeover) quarantine(path string) {
	h, err := openTakeover(path, windows.DELETE|windows.READ_CONTROL)
	if err != nil {
		t.refuse(path, fmt.Sprintf("open link for removal: %v", err))
		return
	}
	defer func() { _ = windows.CloseHandle(h) }()
	info, err := infoOf(h)
	if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		t.refuse(path, "changed while being removed")
		return
	}
	d := fileDispositionInfo{DeleteFile: 1}
	if err := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&d)), uint32(unsafe.Sizeof(d))); err != nil {
		t.refuse(path, fmt.Sprintf("remove link: %v", err))
		return
	}
	t.rep.Quarantined = append(t.rep.Quarantined, path)
}

// openTakeover opens the object itself, never a reparse target.
func openTakeover(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access, takeoverShare, nil, windows.OPEN_EXISTING, openFlags, 0)
}

func infoOf(h windows.Handle) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(h, &info)
	return info, err
}

// enableTakeoverPrivileges enables SeTakeOwnership, SeRestore and SeBackup on
// the process token when held, and returns a function that disables them. A
// privilege that is not held is skipped; the per-entry open then reports it.
func enableTakeoverPrivileges() (restore func()) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return func() {}
	}
	var enabled []windows.Tokenprivileges
	for _, name := range []string{"SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"} {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		var prev windows.Tokenprivileges
		var prevLen uint32
		err := windows.AdjustTokenPrivileges(token, false, &tp, uint32(unsafe.Sizeof(prev)), &prev, &prevLen)
		// prev lists only privileges whose state changed, so one that was
		// already enabled (or is not held) is left as it was on restore.
		if err == nil && prev.PrivilegeCount == 1 {
			tp.Privileges[0].Attributes = 0
			enabled = append(enabled, tp)
		}
	}
	return func() {
		for i := range enabled {
			_ = windows.AdjustTokenPrivileges(token, false, &enabled[i], 0, nil, nil)
		}
		_ = token.Close()
	}
}
