// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows

package github_runner

import (
	"context"

	"github.com/cfgis/cfgms/features/modules"
)

// stubRunnerService is used on platforms where the runner service is not
// supported (the module's platforms are linux and windows). It keeps the package
// buildable everywhere (cross-compilation gate) by returning
// ErrUnsupportedPlatform for any service operation.
type stubRunnerService struct{}

func newServiceExecutor() runnerServiceExecutor { return &stubRunnerService{} }

func (s *stubRunnerService) status(_ context.Context, _ string) (svcStatus, error) {
	return svcStatus{}, modules.ErrUnsupportedPlatform
}

func (s *stubRunnerService) ensure(_ context.Context, _ string, _, _ bool) error {
	return modules.ErrUnsupportedPlatform
}
