// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

// hypervExecutor is the platform-specific backend for Hyper-V operations.
// VM management, snapshot, and vSwitch verbs are added in Stories 2–4.
// Unsupported platforms provide a stub via executor_stub.go (build tag !windows).
type hypervExecutor interface{}

// stubHypervExecutor is the cross-platform fallback executor. It is the value
// returned by newExecutor() on non-Windows platforms and is also referenced by
// unit tests, which must compile on every platform. Methods added in Stories
// 2–4 will return modules.ErrUnsupportedPlatform.
type stubHypervExecutor struct{}
