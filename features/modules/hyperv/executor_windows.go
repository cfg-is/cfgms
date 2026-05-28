// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"

	"github.com/cfgis/cfgms/features/modules"
)

// windowsHypervExecutor implements hypervExecutor using Windows Hyper-V PowerShell APIs.
// VM management is wired through the WinRM transport on the hypervModule; these
// methods are reserved for future native Windows operations (Stories 3–4).
type windowsHypervExecutor struct{}

func newExecutor() hypervExecutor {
	return &windowsHypervExecutor{}
}

func (w *windowsHypervExecutor) CreateVM(_ context.Context, _ VMConfig) error {
	return modules.ErrUnsupportedPlatform
}

func (w *windowsHypervExecutor) GetVM(_ context.Context, _ string) (*VMConfig, error) {
	return nil, modules.ErrUnsupportedPlatform
}

func (w *windowsHypervExecutor) RemoveVM(_ context.Context, _ string) error {
	return modules.ErrUnsupportedPlatform
}

func (w *windowsHypervExecutor) CreateSnapshot(_ context.Context, _, _ string) error {
	return modules.ErrUnsupportedPlatform
}

func (w *windowsHypervExecutor) GetSnapshot(_ context.Context, _, _ string) (*SnapshotConfig, error) {
	return nil, modules.ErrUnsupportedPlatform
}

func (w *windowsHypervExecutor) RemoveSnapshot(_ context.Context, _, _ string) error {
	return modules.ErrUnsupportedPlatform
}

func (w *windowsHypervExecutor) RestoreSnapshot(_ context.Context, _, _ string) error {
	return modules.ErrUnsupportedPlatform
}
