// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows && !darwin

package cert_trust

import "github.com/cfgis/cfgms/features/modules"

// stubExecutor is used on platforms where trust store management is not supported.
type stubExecutor struct{}

func newExecutor() trustStoreExecutor {
	return &stubExecutor{}
}

func (e *stubExecutor) list() ([]certEntry, error) {
	return nil, modules.ErrUnsupportedPlatform
}

func (e *stubExecutor) install(_ []byte) error {
	return modules.ErrUnsupportedPlatform
}

func (e *stubExecutor) remove(_ string) error {
	return modules.ErrUnsupportedPlatform
}
