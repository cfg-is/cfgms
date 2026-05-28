// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"

	"github.com/cfgis/cfgms/features/modules"
)

// hypervExecutor is the platform-specific backend for Hyper-V operations.
// Snapshot and vSwitch verbs are added in Stories 3–4.
// Unsupported platforms provide a stub via executor_stub.go (build tag !windows).
type hypervExecutor interface {
	// CreateVM creates a new Generation-2 VM on the Hyper-V host.
	CreateVM(ctx context.Context, config VMConfig) error
	// GetVM retrieves the current state of a VM by host-side name.
	GetVM(ctx context.Context, hostName string) (*VMConfig, error)
	// RemoveVM forcibly removes a VM by host-side name.
	RemoveVM(ctx context.Context, hostName string) error
}

// stubHypervExecutor is the cross-platform fallback executor. It is the value
// returned by newExecutor() on non-Windows platforms and is also referenced by
// unit tests, which must compile on every platform.
type stubHypervExecutor struct{}

func (s *stubHypervExecutor) CreateVM(_ context.Context, _ VMConfig) error {
	return modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) GetVM(_ context.Context, _ string) (*VMConfig, error) {
	return nil, modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) RemoveVM(_ context.Context, _ string) error {
	return modules.ErrUnsupportedPlatform
}
