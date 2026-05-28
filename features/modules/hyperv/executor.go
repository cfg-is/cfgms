// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

// hypervExecutor is the platform-specific backend for Hyper-V operations.
// VM management, snapshot, and vSwitch verbs are added in Stories 2–4.
// Unsupported platforms provide a stub via executor_stub.go (build tag !windows).
type hypervExecutor interface{}
