// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows && !darwin

package timemodule

import "github.com/cfgis/cfgms/features/modules"

// stubExecutor is used on platforms where time configuration is not supported.
type stubExecutor struct{}

func newExecutor() timeExecutor {
	return &stubExecutor{}
}

func (e *stubExecutor) getState() (timeState, error) {
	return timeState{}, modules.ErrUnsupportedPlatform
}

func (e *stubExecutor) setState(_ timeState) error {
	return modules.ErrUnsupportedPlatform
}
