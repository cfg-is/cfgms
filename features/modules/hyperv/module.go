// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
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
	stewardID     string

	auditMgr  *audit.Manager
	transport winrmTransport
	executor  hypervExecutor

	// detector gates every Get and Set — the module refuses operations when the
	// host is not a Hyper-V host. detMu protects the 5-minute result cache.
	detector  HypervDetector
	detMu     sync.Mutex
	detResult bool
	detExpiry time.Time

	// vms is the write-through VM cache. Keys are the exact VM names admins
	// specify (identical to the host-side names). Updated on executor success
	// only. The cache is never used as the source of truth for an apply
	// decision — setVM always reconciles against live host state via getVM.
	vmsMu sync.RWMutex
	vms   map[string]VMConfig

	// vswitches is the write-through vSwitch cache. Keys are the exact switch
	// names admins specify (identical to the host-side names). Updated on
	// transport success only.
	vswitchesMu sync.RWMutex
	vswitches   map[string]VSwitchConfig

	// provisionStore persists per-VM provisioning records for the
	// create-from-source state machine (ADR-009 §2/§3). Defaults to an
	// in-memory store via New(); tests inject an alternative with
	// WithProvisionStore.
	provisionStore ProvisionStore

	// profileStore loads unattended-install profiles referenced as
	// profile://<name> in a VM source (ADR-009 §7). It is wired from the
	// controller's stored-config backend in Configure() when a "config_store"
	// is supplied, or injected directly in tests via WithProfileStore. It may
	// be nil when no config store is available; callers must handle that.
	profileStore ProfileStore
}

// HypervOption configures a hypervModule at construction time.
type HypervOption func(*hypervModule)

// WithProvisionStore overrides the default in-memory ProvisionStore. Tests
// inject an alternative store to inspect or seed provisioning records.
func WithProvisionStore(s ProvisionStore) HypervOption {
	return func(m *hypervModule) {
		if s != nil {
			m.provisionStore = s
		}
	}
}

// WithProfileStore overrides the ProfileStore wired from the config store.
// Tests inject a memProfileStore (or another ProfileStore) to supply profiles
// without a stored-config backend. A nil store is ignored.
func WithProfileStore(s ProfileStore) HypervOption {
	return func(m *hypervModule) {
		if s != nil {
			m.profileStore = s
		}
	}
}

// New creates a new hypervModule. Production callers pass newDefaultDetector();
// tests inject a fakeDetector via newModuleWithDetector. Optional HypervOption
// values override defaults (e.g. WithProvisionStore for the provisioning
// record store, which otherwise defaults to an in-memory store).
func New(detector HypervDetector, opts ...HypervOption) modules.Module {
	m := &hypervModule{
		executor:       newExecutor(),
		vms:            make(map[string]VMConfig),
		vswitches:      make(map[string]VSwitchConfig),
		detector:       detector,
		provisionStore: newMemProvisionStore(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
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

// Configure implements modules.Configurable. It picks the transport — local
// PS host (preferred, replaces #1852's broken WinRM stack) or WinRM (named
// fallback per #1887 AC) — and wires per-resource bookkeeping.
//
// SecretStore must be injected before calling. (WinRM-fallback needs it for
// credential lookup; PS-host doesn't need credentials at all but the check
// stays since the broader module surface assumes it.)
//
// Optional config keys (all default-driven for the post-#1894 in-host
// deployment shape):
//
//   - tenant_id        — tenant identifier recorded on audit events and DNA
//     (default ""). It is NOT used to namespace host-side names: VMs and
//     switches are created with the exact name the admin specifies.
//   - steward_id       — audit-trail subject id (default "<tenant>/hyperv").
//   - audit_manager    — *audit.Manager to record verb invocations.
//   - transport        — "ps-host" (default) or "winrm". "ps-host" runs the
//     persistent powershell.exe subprocess described in
//     pstransport_windows.go. "winrm" preserves the legacy remote
//     execution path with the keys below.
//
// WinRM-fallback config keys (only consulted when transport == "winrm"):
//   - winrm_host        — hostname or IP of the Hyper-V host.
//   - winrm_user_secret — SecretStore key for the WinRM username.
//   - winrm_pass_secret — SecretStore key for the WinRM password.
//
// On Linux/macOS the PS host transport is not available (Hyper-V is a
// Windows-only feature) and Configure falls back to WinRM regardless of the
// explicit `transport` setting.
func (m *hypervModule) Configure(config modules.ConfigState) error {
	if config == nil {
		return errConfigRequired
	}

	store, injected := m.GetSecretStore()
	if !injected {
		return errSecretStoreRequired
	}

	configMap := config.AsMap()

	m.tenantID, _ = configMap["tenant_id"].(string)
	m.auditMgr, _ = configMap["audit_manager"].(*audit.Manager)

	// Wire the stored-config-backed profile store when a config store is
	// supplied (same injection pattern as audit_manager). Operators define
	// unattended-install profiles in the controller's stored-config backend and
	// reference them as profile://<name>; this makes them loadable without code
	// changes (ADR-009 §7). When no config store is provided, profileStore stays
	// as set by WithProfileStore (nil in production without a backend).
	if configStore, ok := configMap["config_store"].(cfgconfig.ConfigStore); ok && configStore != nil {
		m.profileStore = &ConfigBackedProfileStore{store: configStore, tenantID: m.tenantID}
	}

	stewardID, _ := configMap["steward_id"].(string)
	if stewardID == "" {
		stewardID = m.tenantID + "/hyperv"
	}
	m.stewardID = stewardID

	transportChoice, _ := configMap["transport"].(string)
	if transportChoice == "" {
		transportChoice = "ps-host"
	}

	switch transportChoice {
	case "ps-host":
		// Try the persistent PS host. On non-Windows this returns
		// errPSHostUnsupported and we fall through to the WinRM path so
		// non-Windows builds remain usable for cross-platform tests.
		ps, err := newPSHostTransport(context.Background())
		if err == nil {
			m.transport = ps
			return nil
		}
		// PS host unavailable (non-Windows, or powershell.exe missing).
		// Fall through to WinRM if the operator provided enough config.
		fallthrough
	case "winrm":
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
	default:
		return fmt.Errorf("hyperv: unknown transport %q (valid: \"ps-host\", \"winrm\")", transportChoice)
	}
}

// Get returns the current Hyper-V resource configuration.
// Supported resource ID prefixes:
//   - "vm:<name>": retrieve VMConfig for the named virtual machine
//   - "vswitch:<name>": retrieve VSwitchConfig for the named virtual switch
func (m *hypervModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if err := m.checkDetection(ctx); err != nil {
		if errors.Is(err, ErrHostNotHyperV) {
			if logger, ok := m.GetLogger(); ok {
				logger.Warn("hyperv: declining resource — host is not a Hyper-V host",
					"resource_id", logging.SanitizeLogValue(resourceID))
			}
		}
		return nil, err
	}
	prefix, name, ok := splitResourceID(resourceID)
	if !ok {
		return nil, modules.ErrNotImplemented
	}
	switch prefix {
	case "vm":
		return m.getVM(ctx, name)
	case "vswitch":
		return m.getVSwitch(ctx, name)
	default:
		return nil, modules.ErrNotImplemented
	}
}

// Set applies the desired Hyper-V resource configuration.
// Supported resource ID prefixes:
//   - "vm:<name>": create, update, or delete the named virtual machine
//   - "vswitch:<name>": create or delete the named virtual switch
//
// VM network connectivity is declarative on the VM via switch_name (single
// switch — the common case). Multi-NIC reconciliation is tracked in #2021.
func (m *hypervModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if err := m.checkDetection(ctx); err != nil {
		if errors.Is(err, ErrHostNotHyperV) {
			if logger, ok := m.GetLogger(); ok {
				logger.Warn("hyperv: declining resource — host is not a Hyper-V host",
					"resource_id", logging.SanitizeLogValue(resourceID))
			}
		}
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
	case "vswitch":
		if config == nil {
			return modules.ErrNotImplemented
		}
		return m.setVSwitch(ctx, resourceID, config)
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
