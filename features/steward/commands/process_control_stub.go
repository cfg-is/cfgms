// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !linux && !windows

package commands

import "context"

// systemProcessPIDs are refused on other platforms: init.
var systemProcessPIDs = []int{1}

type unsupportedProcessController struct{}

// newPlatformProcessController returns a controller that reports every operation as
// unsupported (macOS and other platforms).
func newPlatformProcessController() ProcessController { return unsupportedProcessController{} }

func (unsupportedProcessController) Control(context.Context, ProcessOp, int, string) error {
	return ErrProcessUnsupported
}
