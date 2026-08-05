//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"os/exec"
)

// newScriptCommand executes an administrator-configured absolute patch script
// directly. No shell is involved, so the path cannot be reinterpreted as a
// command line.
func newScriptCommand(ctx context.Context, scriptPath string) *exec.Cmd {
	// #nosec G204 -- executing an administrator-configured absolute patch script
	// is this module's explicit capability; the path is cleaned and validated as
	// absolute by the caller.
	return exec.CommandContext(ctx, scriptPath)
}
