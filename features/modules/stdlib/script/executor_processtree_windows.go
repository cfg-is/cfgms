// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package script

// This file is compiled only on Windows (Go filename convention: _windows.go suffix).

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/cfgis/cfgms/pkg/logging"
	"golang.org/x/sys/windows"
)

// processTree tracks a launched command together with every descendant it
// spawns, so a timeout/cancel can terminate the whole tree at once rather than
// just the top-level process.
//
// Issue #2715: a Windows `.cmd` job (e.g. `cmd.exe /c config.cmd`) can spawn a
// detached grandchild — such as a `--runasservice` registration that backgrounds
// a service-install step. `cmd.Process.Kill()` terminates only the top-level
// `cmd.exe`; the grandchild survives and, if it inherited the stdout/stderr pipe
// handles, keeps the write end open. `cmd.Wait()` then blocks forever waiting for
// the output-copy goroutines to see EOF, wedging the executor goroutine and the
// steward's per-device execution slot indefinitely.
//
// The fix assigns the top-level process to a Job Object. Descendants
// automatically join the job (a plain job does not permit breakaway), so a single
// TerminateJobObject on timeout kills the entire tree — the grandchild dies, its
// pipe handle closes, and cmd.Wait() returns promptly.
//
// The job is intentionally created WITHOUT JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:
// termination happens only via the explicit TerminateJobObject in terminate()
// (the timeout path). This preserves the behavior of a script that completes
// successfully after deliberately backgrounding a detached descendant — that
// descendant is not collaterally killed when close() releases the job handle on
// the success path.
type processTree struct {
	logger logging.Logger
	job    windows.Handle
	// suspended records that prepare started the process with CREATE_SUSPENDED,
	// so track must resume it on every path.
	suspended bool
}

// newProcessTree returns a process-tree tracker. It holds no OS resources until
// prepare is called, so close is always safe.
func newProcessTree(logger logging.Logger) *processTree {
	return &processTree{logger: logger}
}

// prepare creates the Job Object BEFORE the process is started and configures
// cmd to start suspended (CREATE_SUSPENDED). The process therefore cannot run a
// single instruction, let alone spawn a descendant, until track has assigned it
// to the job and resumed it (Issue #5534): a grandchild spawned inside the
// post-Start window would otherwise never join the job and survive
// TerminateJobObject.
//
// Failure is logged, never fatal: with no job, terminate falls back to killing
// the top-level process only — the pre-#2715 behavior — so a missing job never
// makes execution worse than it already was.
func (p *processTree) prepare(cmd *exec.Cmd) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		p.logger.Warn("process-tree: CreateJobObject failed; timeout will kill top-level process only",
			"error", err)
		return
	}
	p.job = job
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	p.suspended = true
}

// track assigns the freshly started (suspended) process to the Job Object created
// by prepare and then resumes it. It must be called immediately after
// cmd.Start(). Because the process is suspended until this returns, it is a job
// member before it executes anything, so every descendant inherits membership
// and a single TerminateJobObject reaches the whole tree. Assignment failure
// downgrades to top-level-only kill; the process is resumed regardless.
func (p *processTree) track(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if p.suspended {
		defer func() {
			if err := resumeProcess(uint32(cmd.Process.Pid)); err != nil { //nolint:gosec // Pid is a valid process id owned by this executor
				p.logger.Warn("process-tree: failed to resume suspended process; killing it",
					"error", err)
				_ = cmd.Process.Kill()
			}
		}()
	}
	if p.job == 0 {
		return
	}

	// AssignProcessToJobObject needs a process handle with PROCESS_SET_QUOTA and
	// PROCESS_TERMINATE rights; os/exec does not expose the handle it opened, so
	// re-open by PID.
	//nolint:gosec // Pid is a valid process id owned by this executor
	hProc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		p.logger.Warn("process-tree: OpenProcess failed; timeout will kill top-level process only",
			"error", err)
		p.releaseJob()
		return
	}
	defer func() { _ = windows.CloseHandle(hProc) }()

	if err := windows.AssignProcessToJobObject(p.job, hProc); err != nil {
		p.logger.Warn("process-tree: AssignProcessToJobObject failed; timeout will kill top-level process only",
			"error", err)
		p.releaseJob()
		return
	}
}

// resumeProcess resumes every thread of a process created with CREATE_SUSPENDED
// (exactly one, the initial thread). os/exec does not expose the thread handle,
// so the thread is located through a toolhelp snapshot.
func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()

	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Thread32First(snap, &entry); err != nil {
		return fmt.Errorf("Thread32First: %w", err)
	}
	resumed := false
	for {
		if entry.OwnerProcessID == pid {
			hThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err != nil {
				return fmt.Errorf("OpenThread: %w", err)
			}
			_, err = windows.ResumeThread(hThread)
			_ = windows.CloseHandle(hThread)
			if err != nil {
				return fmt.Errorf("ResumeThread: %w", err)
			}
			resumed = true
		}
		if err := windows.Thread32Next(snap, &entry); err != nil {
			break // ERROR_NO_MORE_FILES ends the enumeration
		}
	}
	if !resumed {
		return fmt.Errorf("no thread found for pid %d", pid)
	}
	return nil
}

// terminate kills the entire tracked process tree. When the process was assigned
// to a job this is a single TerminateJobObject call that reaches every
// descendant; otherwise it falls back to killing the top-level process only.
func (p *processTree) terminate(cmd *exec.Cmd) {
	if p.job != 0 {
		if err := windows.TerminateJobObject(p.job, 1); err != nil {
			p.logger.Warn("process-tree: TerminateJobObject failed; killing top-level process",
				"error", err)
			p.killTopLevel(cmd)
		}
		return
	}
	p.killTopLevel(cmd)
}

func (p *processTree) killTopLevel(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			p.logger.Warn("process-tree: failed to kill top-level process", "error", err)
		}
	}
}

// releaseJob closes and clears the job handle so terminate/close fall back to the
// top-level path.
func (p *processTree) releaseJob() {
	if p.job != 0 {
		_ = windows.CloseHandle(p.job)
		p.job = 0
	}
}

// close releases the Job Object handle without terminating its members (the job
// carries no kill-on-close limit). On the timeout path terminate has already
// killed the tree; on the success path any deliberately-detached descendant is
// left running. Idempotent.
func (p *processTree) close() {
	p.releaseJob()
}
