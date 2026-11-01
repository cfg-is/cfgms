//go:build darwin

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"os/exec"
	"time"
)

// darwinCmdWaitDelay bounds how long Output()/Run() will wait for a killed
// command's I/O to drain before the pipes are force-closed. On macOS CI runners
// a DNA-collection tool (e.g. dscl, netstat) can get stuck in a kernel call that
// survives the context-driven SIGKILL while a grandchild keeps the stdout pipe
// open; without WaitDelay, Output() blocks on that pipe indefinitely and leaks a
// goroutine per collection cycle. WaitDelay guarantees the call returns.
const darwinCmdWaitDelay = 5 * time.Second

// darwinRunCmd runs an external command with a timeout context and WaitDelay so
// that a child stuck after SIGKILL cannot block collection forever. It is the
// generalization of network_darwin.go's darwinRunNetCmd, shared by every darwin
// DNA collector. Callers keep their existing `err == nil` gating; on timeout or
// a stuck-pipe drain the returned error is non-nil and output should be ignored.
func darwinRunCmd(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, args...)
	cmd.WaitDelay = darwinCmdWaitDelay
	return cmd.Output()
}
