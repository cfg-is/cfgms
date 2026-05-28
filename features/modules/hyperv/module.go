// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"

	"github.com/cfgis/cfgms/features/modules"
)

var (
	errConfigRequired        = errors.New("hyperv: config must not be nil")
	errSecretStoreRequired   = errors.New("hyperv: secret store must be injected before Configure")
	errHostRequired          = errors.New("hyperv: winrm_host is required")
	errUserSecretKeyRequired = errors.New("hyperv: winrm_user_secret key is required")
	errPassSecretKeyRequired = errors.New("hyperv: winrm_pass_secret key is required")
)

// HypervDetector detects whether Hyper-V is available on the host.
// The concrete implementation is added in Story 5 (host detection).
type HypervDetector interface {
	IsAvailable() (bool, error)
}

// hypervModule implements modules.Module and modules.Configurable for remote
// Hyper-V management via WinRM. Credentials are fetched from SecretStore on
// every operation — no credential values are stored between calls.
type hypervModule struct {
	modules.DefaultLoggingSupport
	modules.DefaultSecretStoreSupport

	host          string
	userSecretKey string
	passSecretKey string

	transport winrmTransport
	executor  hypervExecutor
}

// New creates a new hypervModule. detector is reserved for Story 5 host detection
// and may be nil in Story 1.
func New(detector HypervDetector) modules.Module {
	return &hypervModule{
		executor: newExecutor(),
	}
}

// Configure implements modules.Configurable. It extracts WinRM connection details
// from config and wires the transport. SecretStore must be injected before calling.
//
// Required config keys:
//   - winrm_host: hostname or IP of the Hyper-V host
//   - winrm_user_secret: SecretStore key for the WinRM username
//   - winrm_pass_secret: SecretStore key for the WinRM password
func (m *hypervModule) Configure(config modules.ConfigState) error {
	if config == nil {
		return errConfigRequired
	}

	store, injected := m.GetSecretStore()
	if !injected {
		return errSecretStoreRequired
	}

	configMap := config.AsMap()

	host, _ := configMap["winrm_host"].(string)
	if host == "" {
		return errHostRequired
	}

	userSecretKey, _ := configMap["winrm_user_secret"].(string)
	if userSecretKey == "" {
		return errUserSecretKeyRequired
	}

	passSecretKey, _ := configMap["winrm_pass_secret"].(string)
	if passSecretKey == "" {
		return errPassSecretKeyRequired
	}

	m.host = host
	m.userSecretKey = userSecretKey
	m.passSecretKey = passSecretKey
	m.transport = newWinRMClientWithStore(host, userSecretKey, passSecretKey, store)

	return nil
}

// Get returns the current Hyper-V resource configuration.
// VM retrieval is implemented in Story 2.
func (m *hypervModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	return nil, modules.ErrNotImplemented
}

// Set applies the desired Hyper-V resource configuration.
// VM management is implemented in Stories 2–4.
func (m *hypervModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return modules.ErrNotImplemented
}
