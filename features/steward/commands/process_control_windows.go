// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package commands

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// systemProcessPIDs are refused on Windows: the Idle process (0) and System (4).
var systemProcessPIDs = []int{0, 4}

const processAccess = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_TERMINATE | windows.PROCESS_SUSPEND_RESUME

var (
	modNtdll           = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProcs = modNtdll.NewProc("NtSuspendProcess")
	procNtResumeProcs  = modNtdll.NewProc("NtResumeProcess")
)

type winProcessController struct{}

// newPlatformProcessController returns the Win32 process controller (no taskkill).
func newPlatformProcessController() ProcessController { return winProcessController{} }

// Control opens one handle, verifies the image name on that handle and acts on the same
// handle, so the PID cannot be reused between the check and the action.
func (winProcessController) Control(_ context.Context, op ProcessOp, pid int, image string) error {
	h, err := windows.OpenProcess(processAccess, false, uint32(pid))
	if err != nil {
		switch {
		case errors.Is(err, windows.ERROR_INVALID_PARAMETER):
			return ErrProcessNotFound
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return ErrProcessPermissionDenied
		default:
			return err
		}
	}
	defer func() { _ = windows.CloseHandle(h) }()

	buf := make([]uint16, windows.MAX_PATH*4)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return err
	}
	live := filepath.Base(strings.ReplaceAll(windows.UTF16ToString(buf[:size]), "\\", "/"))
	if !strings.EqualFold(live, image) {
		return ErrProcessChanged
	}

	switch op {
	case ProcessOpEnd:
		if err := windows.TerminateProcess(h, 1); err != nil {
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				return ErrProcessPermissionDenied
			}
			return err
		}
		return nil
	case ProcessOpSuspend:
		return ntProcessCall(procNtSuspendProcs, h)
	case ProcessOpResume:
		return ntProcessCall(procNtResumeProcs, h)
	default:
		return errors.New("unknown process operation")
	}
}

func ntProcessCall(p *windows.LazyProc, h windows.Handle) error {
	if err := p.Find(); err != nil {
		return ErrProcessUnsupported
	}
	status, _, _ := p.Call(uintptr(h))
	if status != 0 {
		return errors.New("process state change failed: NTSTATUS " + windows.NTStatus(status).Error())
	}
	return nil
}
