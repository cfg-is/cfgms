// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import "io"

// maybeRepairServiceRegistration is a no-op on non-Windows platforms. The SCM
// service-registration self-repair (#2465) targets the Windows Service Control
// Manager, which has no equivalent on Linux/macOS (systemd/launchd units are
// managed differently and were not the incident's failure mode). The supervise
// loop calls this unconditionally; keeping the platform split here mirrors the
// attachChildToJobObject pattern (lifecycle_posix.go / lifecycle_windows.go),
// so lifecycle.go needs no runtime.GOOS check at the call site.
func maybeRepairServiceRegistration(w io.Writer) { _ = w }
