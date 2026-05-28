// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

// windowsHypervExecutor implements hypervExecutor using Windows Hyper-V PowerShell APIs.
// VM management, snapshot, and vSwitch verbs are added in Stories 2–4.
type windowsHypervExecutor struct{}

func newExecutor() hypervExecutor {
	return &windowsHypervExecutor{}
}
