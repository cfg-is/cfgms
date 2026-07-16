// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package script

// This file is compiled only on Windows (Go filename convention: _windows.go suffix).

import (
	"os/exec"

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
}

// newProcessTree returns a process-tree tracker. It holds no OS resources until
// prepare is called, so close is always safe.
func newProcessTree(logger logging.Logger) *processTree {
	return &processTree{logger: logger}
}

// prepare creates the Job Object BEFORE the process is started, so that track
// (called immediately after Start) only has to open the process and assign it.
// Creating the job up front minimizes the window between cmd.Start() and job
// assignment in which a descendant could spawn and escape the job.
//
// Failure is logged, never fatal: with no job, terminate falls back to killing
// the top-level process only — the pre-#2715 behavior — so a missing job never
// makes execution worse than it already was.
func (p *processTree) prepare() {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		p.logger.Warn("process-tree: CreateJobObject failed; timeout will kill top-level process only",
			"error", err)
		return
	}
	p.job = job
}

// track assigns the freshly started process to the Job Object created by prepare.
//
// It must be called immediately after cmd.Start(), as the very first post-Start
// action, so the top-level process becomes a job member before it has run the
// script body and spawned any grandchildren; every descendant then inherits job
// membership. The residual window is just this OpenProcess + assignment (two
// in-process syscalls). os/exec offers no CREATE_SUSPENDED + ResumeThread hook
// to make the assignment provably pre-execution, but the launchers here are
// heavyweight interpreters (cmd.exe, powershell.exe, pwsh.exe, python.exe) whose
// own startup far exceeds those two syscalls, so a descendant cannot realistically
// spawn inside the window. Assignment failure downgrades to top-level-only kill.
func (p *processTree) track(cmd *exec.Cmd) {
	if p.job == 0 || cmd == nil || cmd.Process == nil {
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
