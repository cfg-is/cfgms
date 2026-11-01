// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !linux && !windows

package commands

import "context"

type unsupportedServiceController struct{}

// newPlatformServiceController returns a controller that reports every operation
// as unsupported (macOS and other platforms).
func newPlatformServiceController() ServiceController { return unsupportedServiceController{} }

func (unsupportedServiceController) Control(context.Context, ServiceOp, string) error {
	return ErrServiceUnsupported
}

func (unsupportedServiceController) IsStewardService(context.Context, string) (bool, error) {
	return false, ErrServiceUnsupported
}
