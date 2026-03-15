// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows && !darwin

package service

import (
	"fmt"
	"runtime"
)

func newManager(binaryPath string) Manager {
	return &stubManager{}
}

type stubManager struct{}

func (m *stubManager) InstallPath() string { return "" }

func (m *stubManager) IsElevated() bool { return false }

func (m *stubManager) Install(token string) error {
	return fmt.Errorf("service install is not supported on %s", runtime.GOOS)
}

func (m *stubManager) Uninstall(purge bool) error {
	return fmt.Errorf("service uninstall is not supported on %s", runtime.GOOS)
}

func (m *stubManager) Status() (*ServiceStatus, error) {
	return &ServiceStatus{}, fmt.Errorf("service status is not supported on %s", runtime.GOOS)
}
