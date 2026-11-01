// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import "os/exec"

// attachChildToJobObject is a no-op on POSIX systems. The orphan-child
// failure mode that this addresses on Windows (#1928) doesn't exist on
// Linux or macOS:
//
//   - exec.CommandContext already propagates ctx cancellation as SIGKILL
//     to the child.
//   - Most launcher abnormal-exit paths leave the child in the same
//     process group; a setsid-equivalent is the steward's responsibility
//     if it wants to outlive the launcher (it doesn't).
//   - On Linux, the prctl PR_SET_PDEATHSIG path inside the steward could
//     also be wired if we wanted a kernel-enforced guarantee — but the
//     current launcher relies on cmd.Run's normal lifecycle and that's
//     proven adequate.
//
// Keeping a separate file gated by `!windows` lets us call
// attachChildToJobObject unconditionally from lifecycle.go without a
// runtime.GOOS check at the call site.
func attachChildToJobObject(cmd *exec.Cmd) error {
	_ = cmd
	return nil
}
