// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// attachChildToJobObject assigns the supervised steward child to a Windows
// Job Object configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE so that an
// abnormal launcher exit (SCM TerminateProcess, crash, runtime panic without
// defer) takes the steward with it — closing the launcher's last handle to
// the job triggers the kernel to terminate every assigned process.
//
// This mirrors the POSIX process-group / pdeathsig safety net that the rest
// of the supervisor already relies on. Without it, the abnormal-exit case
// produces the symptom from #1928 — orphaned cfgms-steward.exe with a stale
// ParentProcessId, racing the next launcher's child on the same registration
// token.
//
// The job handle is intentionally NOT closed here. It's owned by the
// launcher process for its lifetime; the kernel closes it automatically
// at process exit, and that close is the trigger that kills the children.
// Closing it earlier would defeat the purpose. A future story may wire
// graceful shutdown that explicitly closes the job, but the current
// auto-rollback flow already relies on the launcher's own exit semantics.
//
// Ordering note: cmd.Start has already created the process by the time
// this runs. There's a microsecond-scale window where the child runs
// outside the job; JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE applies
// retroactively once assigned, so this is acceptable for the kill-on-close
// guarantee. A CREATE_SUSPENDED + ResumeThread pattern would close that
// window entirely but adds Win32 surface; deferred until evidence we need
// it.
func attachChildToJobObject(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("attachChildToJobObject: cmd has no process")
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("CreateJobObject: %w", err)
	}

	// LimitFlags carries ONLY JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. Two
	// flags are intentionally NOT set; a future change MUST NOT add them
	// without a fresh threat-model pass:
	//
	//   - JOB_OBJECT_LIMIT_BREAKAWAY_OK / SILENT_BREAKAWAY_OK: would let
	//     a child process spawned with CREATE_BREAKAWAY_FROM_JOB escape
	//     the kill-on-close net, reproducing the orphan bug #1928 set out
	//     to prevent. Absent => Windows denies breakaway by default.
	//   - JOB_OBJECT_LIMIT_PROCESS_MEMORY / JOB_TIME / etc: out of scope
	//     for this story.
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("SetInformationJobObject: %w", err)
	}

	// cmd.Process.Pid is a numeric PID, not a handle. Open a process
	// handle with PROCESS_SET_QUOTA | PROCESS_TERMINATE so
	// AssignProcessToJobObject is allowed.
	//
	// PID-recycle race note: Go's os/exec internally holds a process
	// handle to the child for the lifetime of *exec.Cmd (created inside
	// Start, released by Wait or Release). Windows guarantees that a
	// process's PID is NOT recycled while any handle to that process
	// remains open, so the PID we read from cmd.Process.Pid here cannot
	// refer to a different process. The OpenProcess call below gets a
	// second handle to the same child.
	processHandle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("OpenProcess(pid=%d): %w", cmd.Process.Pid, err)
	}
	defer func() { _ = windows.CloseHandle(processHandle) }()

	if err := windows.AssignProcessToJobObject(job, processHandle); err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}

	// Intentionally do NOT CloseHandle(job). The launcher's open handle is
	// what keeps the job alive; the kernel terminates assigned children
	// when the last handle closes (process exit).
	_ = job // explicit: handle is retained for launcher lifetime

	return nil
}
