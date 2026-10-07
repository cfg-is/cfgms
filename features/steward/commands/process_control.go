// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"context"
	"errors"
	"os"
)

// ProcessOp is one process-control operation of the steward_action allowlist.
type ProcessOp string

const (
	ProcessOpEnd     ProcessOp = "end"
	ProcessOpSuspend ProcessOp = "suspend"
	ProcessOpResume  ProcessOp = "resume"
)

var (
	// ErrProcessUnsupported is returned on platforms with no in-process implementation.
	ErrProcessUnsupported = errors.New("process control unsupported on this platform")

	// ErrProcessNotFound is returned when no process has the PID.
	ErrProcessNotFound = errors.New("process not found")

	// ErrProcessChanged is returned when the PID's current image name differs from the
	// one the operator saw: the PID was reused by another process.
	ErrProcessChanged = errors.New("process image changed")

	// ErrProcessPermissionDenied is returned when the OS refuses the caller.
	ErrProcessPermissionDenied = errors.New("process control permission denied")
)

// ProcessController ends, suspends and resumes processes through in-process OS APIs
// only. Implementations never shell out.
type ProcessController interface {
	// Control verifies that pid's current image name equals image (ErrProcessChanged
	// otherwise) and then applies op.
	Control(ctx context.Context, op ProcessOp, pid int, image string) error
}

// isProtectedPID reports whether pid must never be targeted: the steward itself, its
// parent (service host or supervisor), and the platform's system PIDs.
func isProtectedPID(pid int) bool {
	if pid <= 0 || pid == os.Getpid() || pid == os.Getppid() {
		return true
	}
	for _, p := range systemProcessPIDs {
		if pid == p {
			return true
		}
	}
	return false
}
