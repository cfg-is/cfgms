// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !linux && !windows && !darwin

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// platformCACertPath returns the CA certificate path, respecting
// CFGMS_INSTALL_PREFIX for test isolation.
func platformCACertPath() string {
	const p = "/etc/cfgms/controller-ca.crt"
	if prefix := os.Getenv("CFGMS_INSTALL_PREFIX"); prefix != "" {
		return filepath.Join(prefix, p)
	}
	return p
}

func newManager(binaryPath string) Manager {
	return &stubManager{}
}

type stubManager struct{}

func (m *stubManager) IsElevated() bool { return false }

func (m *stubManager) Install(token, controllerURL, caCertPEM, expectedFingerprint string) error {
	return fmt.Errorf("service install is not supported on %s", runtime.GOOS)
}

func (m *stubManager) Uninstall(purge bool) error {
	return fmt.Errorf("service uninstall is not supported on %s", runtime.GOOS)
}

func (m *stubManager) Status() (*ServiceStatus, error) {
	return &ServiceStatus{}, fmt.Errorf("service status is not supported on %s", runtime.GOOS)
}

func (m *stubManager) Stop() error {
	return fmt.Errorf("service stop is not supported on %s", runtime.GOOS)
}

func (m *stubManager) RegistrationTokenConfigured() (bool, error) {
	return tokenFileConfigured(platformTokenFilePath())
}
