// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/modules"
)

var (
	errConfigRequired        = errors.New("hyperv: config must not be nil")
	errSecretStoreRequired   = errors.New("hyperv: secret store must be injected before Configure")
	errHostRequired          = errors.New("hyperv: winrm_host is required")
	errUserSecretKeyRequired = errors.New("hyperv: winrm_user_secret key is required")
	errPassSecretKeyRequired = errors.New("hyperv: winrm_pass_secret key is required")
)

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

	// detector gates every Get and Set — the module refuses operations when the
	// host is not a Hyper-V host. detMu protects the 5-minute result cache.
	detector  HypervDetector
	detMu     sync.Mutex
	detResult bool
	detExpiry time.Time

	// vms is the write-through VM cache. Keys are user-visible VM names
	// (without the cfgms-<tenantID>__ prefix). Updated on executor success only.
	vmsMu sync.RWMutex
	vms   map[string]VMConfig

	// vswitches is the write-through vSwitch cache. Keys are user-visible switch names
	// (without the cfgms-<tenantID>__ prefix). Updated on transport success only.
	vswitchesMu sync.RWMutex
	vswitches   map[string]VSwitchConfig
}

// New creates a new hypervModule. Production callers pass newDefaultDetector();
// tests inject a fakeDetector via newModuleWithDetector.
func New(detector HypervDetector) modules.Module {
	return &hypervModule{
		executor:  newExecutor(),
		vms:       make(map[string]VMConfig),
		vswitches: make(map[string]VSwitchConfig),
		detector:  detector,
	}
}

// checkDetection calls the injected HypervDetector and enforces the 5-minute
// result cache. Returns ErrHostNotHyperV when the host is not a Hyper-V host
// or when no detector was provided.
func (m *hypervModule) checkDetection(ctx context.Context) error {
	if m.detector == nil {
		return ErrHostNotHyperV
	}

	m.detMu.Lock()
	defer m.detMu.Unlock()

	if time.Now().Before(m.detExpiry) {
		if !m.detResult {
			return ErrHostNotHyperV
		}
		return nil
	}

	result, err := m.detector.IsHypervHost(ctx)
	if err != nil {
		return err
	}
	if result {
		m.detResult = true
		m.detExpiry = time.Now().Add(5 * time.Minute)
	}
	if !result {
		return ErrHostNotHyperV
	}
	return nil
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
//   - "vswitch:<name>": retrieve VSwitchConfig for the named virtual switch
//   - "vmattach:<vmName>/<switchName>": retrieve VMAttachmentConfig for the named attachment
func (m *hypervModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if err := m.checkDetection(ctx); err != nil {
		return nil, err
	}
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
	case "vswitch":
		return m.getVSwitch(ctx, name)
	case "vmattach":
		return m.getVMAttachment(ctx, name)
	default:
		return nil, modules.ErrNotImplemented
	}
}

// Set applies the desired Hyper-V resource configuration.
// Supported resource ID prefixes:
//   - "vm:<name>": create, update, or delete the named virtual machine
//   - "snapshot:<vmName>/<snapName>": create, restore, or delete the named checkpoint
//   - "vswitch:<name>": create or delete the named virtual switch
//   - "vmattach:<vmName>/<switchName>": attach or detach a VM network adapter
func (m *hypervModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if err := m.checkDetection(ctx); err != nil {
		return err
	}
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
	case "vswitch":
		if config == nil {
			return modules.ErrNotImplemented
		}
		return m.setVSwitch(ctx, resourceID, config)
	case "vmattach":
		if config == nil {
			return modules.ErrNotImplemented
		}
		return m.setVMAttachment(ctx, resourceID, config)
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
