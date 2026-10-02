// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows && !darwin

package hostname

import "github.com/cfgis/cfgms/features/modules"

// stubExecutor is used on platforms where hostname configuration is not supported.
type stubExecutor struct{}

func newExecutor() hostnameExecutor {
	return &stubExecutor{}
}

func (e *stubExecutor) getState() (hostnameState, error) {
	return hostnameState{}, modules.ErrUnsupportedPlatform
}

func (e *stubExecutor) setState(_ hostnameState) error {
	return modules.ErrUnsupportedPlatform
}
