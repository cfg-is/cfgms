// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cutover

import "os"

// On Windows os.Process.Signal does not support SIGTERM. os.Interrupt
// is delivered as Ctrl-Break to console subsystem processes, which is
// what cfgms-controller installs in its signal handler when run via the
// installer. For non-console services, only Kill works — Drain still
// tries Interrupt and falls back to Stop on timeout.
func init() {
	defaultGracefulSignal = os.Interrupt
}
