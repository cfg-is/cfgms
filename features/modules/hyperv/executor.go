// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"

	"github.com/cfgis/cfgms/features/modules"
)

// hypervExecutor is the platform-specific backend for Hyper-V operations.
// Unsupported platforms provide a stub via executor_stub.go (build tag !windows).
type hypervExecutor interface {
	// CreateVM creates a new Generation-2 VM on the Hyper-V host.
	CreateVM(ctx context.Context, config VMConfig) error
	// GetVM retrieves the current state of a VM by host-side name.
	GetVM(ctx context.Context, hostName string) (*VMConfig, error)
	// RemoveVM forcibly removes a VM by host-side name.
	RemoveVM(ctx context.Context, hostName string) error

	// CreateSnapshot creates a new checkpoint for the named VM on the Hyper-V host.
	CreateSnapshot(ctx context.Context, vmHostName, snapHostName string) error
	// GetSnapshot checks whether a checkpoint exists on the Hyper-V host.
	GetSnapshot(ctx context.Context, vmHostName, snapHostName string) (*SnapshotConfig, error)
	// RemoveSnapshot deletes a checkpoint from the Hyper-V host.
	RemoveSnapshot(ctx context.Context, vmHostName, snapHostName string) error
	// RestoreSnapshot restores the VM to the named checkpoint.
	RestoreSnapshot(ctx context.Context, vmHostName, snapHostName string) error

	// CreateVSwitch creates a virtual switch on the Hyper-V host.
	CreateVSwitch(ctx context.Context, config VSwitchConfig) error
	// GetVSwitch retrieves the current state of a virtual switch by host-side name.
	GetVSwitch(ctx context.Context, hostName string) (*VSwitchConfig, error)
	// RemoveVSwitch forcibly removes a virtual switch by host-side name.
	RemoveVSwitch(ctx context.Context, hostName string) error
	// AttachVMToSwitch adds a network adapter on a VM and connects it to a switch.
	// adapterName may be empty; in that case the -Name parameter is omitted.
	AttachVMToSwitch(ctx context.Context, vmHostName, switchHostName, adapterName string) error
	// DetachVMFromSwitch removes a named network adapter from a VM.
	DetachVMFromSwitch(ctx context.Context, vmHostName, adapterName string) error
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

func (s *stubHypervExecutor) CreateSnapshot(_ context.Context, _, _ string) error {
	return modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) GetSnapshot(_ context.Context, _, _ string) (*SnapshotConfig, error) {
	return nil, modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) RemoveSnapshot(_ context.Context, _, _ string) error {
	return modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) RestoreSnapshot(_ context.Context, _, _ string) error {
	return modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) CreateVSwitch(_ context.Context, _ VSwitchConfig) error {
	return modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) GetVSwitch(_ context.Context, _ string) (*VSwitchConfig, error) {
	return nil, modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) RemoveVSwitch(_ context.Context, _ string) error {
	return modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) AttachVMToSwitch(_ context.Context, _, _, _ string) error {
	return modules.ErrUnsupportedPlatform
}

func (s *stubHypervExecutor) DetachVMFromSwitch(_ context.Context, _, _ string) error {
	return modules.ErrUnsupportedPlatform
}
