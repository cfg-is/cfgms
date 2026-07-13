// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows && !darwin

package user

import "github.com/cfgis/cfgms/features/modules"

// stubExecutor is used on platforms where local user account management is not
// supported. All calls return ErrUnsupportedPlatform.
type stubExecutor struct{}

func newExecutor() userExecutor {
	return &stubExecutor{}
}

func (e *stubExecutor) getState(_ string) (userState, error) {
	return userState{}, modules.ErrUnsupportedPlatform
}

func (e *stubExecutor) setState(_ string, _ userState) error {
	return modules.ErrUnsupportedPlatform
}
