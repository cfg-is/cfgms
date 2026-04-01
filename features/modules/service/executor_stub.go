// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows && !darwin

package service

import "github.com/cfgis/cfgms/features/modules"

// stubExecutor is used on platforms where service management is not supported.
type stubExecutor struct{}

func newExecutor() serviceExecutor {
	return &stubExecutor{}
}

func (e *stubExecutor) getState(_ string) (serviceState, error) {
	return serviceState{}, modules.ErrUnsupportedPlatform
}

func (e *stubExecutor) setState(_ string, _ bool, _ bool) error {
	return modules.ErrUnsupportedPlatform
}
