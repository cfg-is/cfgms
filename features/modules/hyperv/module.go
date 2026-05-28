// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"strings"
	"sync"

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
	tenantID      string

	transport winrmTransport
	executor  hypervExecutor

	// vms is the write-through VM cache. Keys are user-visible VM names
	// (without the cfgms-<tenantID>__ prefix). Updated on executor success only.
	vmsMu sync.RWMutex
	vms   map[string]VMConfig
}

// New creates a new hypervModule. detector is reserved for Story 5 host detection
// and may be nil in Story 1.
func New(detector HypervDetector) modules.Module {
	return &hypervModule{
		executor: newExecutor(),
		vms:      make(map[string]VMConfig),
	}
}

// Configure implements modules.Configurable. It extracts WinRM connection details
// from config and wires the transport. SecretStore must be injected before calling.
//
// Required config keys:
//   - winrm_host: hostname or IP of the Hyper-V host
//   - winrm_user_secret: SecretStore key for the WinRM username
//   - winrm_pass_secret: SecretStore key for the WinRM password
//
// Optional config keys:
//   - tenant_id: tenant identifier used to namespace host-side VM names
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
	m.tenantID, _ = configMap["tenant_id"].(string)
	m.transport = newWinRMClientWithStore(host, userSecretKey, passSecretKey, store)

	return nil
}

// Get returns the current Hyper-V resource configuration.
// Supported resource ID prefixes:
//   - "vm:<name>": retrieve VMConfig for the named virtual machine
//   - "snapshot:<vmName>/<snapName>": retrieve SnapshotConfig for the named checkpoint
func (m *hypervModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	prefix, name, ok := splitResourceID(resourceID)
	if !ok {
		return nil, modules.ErrNotImplemented
	}
	switch prefix {
	case "vm":
		return m.getVM(ctx, name)
	case "snapshot":
		vmName, snapName, ok := splitSnapshotName(name)
		if !ok {
			return nil, modules.ErrNotImplemented
		}
		return m.getSnapshot(ctx, vmName, snapName)
	default:
		return nil, modules.ErrNotImplemented
	}
}

// Set applies the desired Hyper-V resource configuration.
// Supported resource ID prefixes:
//   - "vm:<name>": create, update, or delete the named virtual machine
//   - "snapshot:<vmName>/<snapName>": create, restore, or delete the named checkpoint
func (m *hypervModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	prefix, _, ok := splitResourceID(resourceID)
	if !ok {
		return modules.ErrNotImplemented
	}
	switch prefix {
	case "vm":
		if config == nil {
			return modules.ErrNotImplemented
		}
		return m.setVM(ctx, resourceID, config)
	case "snapshot":
		if config == nil {
			return modules.ErrNotImplemented
		}
		return m.setSnapshot(ctx, resourceID, config)
	default:
		return modules.ErrNotImplemented
	}
}

// splitResourceID splits "prefix:name" into its parts. Returns ok=false if
// there is no colon separator.
func splitResourceID(resourceID string) (prefix, name string, ok bool) {
	idx := strings.IndexByte(resourceID, ':')
	if idx < 0 {
		return "", "", false
	}
	return resourceID[:idx], resourceID[idx+1:], true
}
