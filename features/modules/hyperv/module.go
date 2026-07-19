// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"fmt"
	"os"
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

	// Failover-cluster scope (S1/S5). clusterName is the single cluster this
	// steward is permitted to read; getCluster / clusterOwnershipHelper reject
	// any other cluster name with ErrClusterNotDeclared BEFORE touching the
	// transport (the scope cap). clusterRoleNames bounds the set of clustered VM
	// role names in scope (S5). nodeHostname is the local node identity captured
	// once in Configure (os.Hostname) and used as the audit node identity for
	// ownership decisions — recordHypervOp's host arg is otherwise empty under
	// the ps-host transport.
	clusterName      string
	clusterRoleNames []string
	nodeHostname     string

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

	// Cluster resource-owner read cache (Story #2577). readResourceOwners is a
	// single bulk cluster read that returns EVERY clustered role's owner, but the
	// read-path membership probe (probeClusterRoleMembership) calls it once per HA
	// VM — so N HA VMs cost N identical full cluster reads per converge pass. This
	// caches the bulk result for a short freshness window so a pass issues ONE
	// cluster read and filters per-VM in process, and is invalidated by any
	// cluster-mutating op (invalidateClusterOwnersCache) so work we just performed
	// is reflected on the next read. It backs only the fail-safe read path; the
	// safety-critical write-path owner gate (clusterOwnershipHelper) always reads
	// live.
	clusterOwnersMu  sync.Mutex
	clusterOwners    map[string]string
	clusterOwnersAt  time.Time
	clusterOwnersTTL time.Duration

	// checkpointDesired maps a VM name to the authored `checkpoints` block last
	// seen for it, so getVM's compliance echo is policy-aware (#2627). It is
	// keyed by VM name and mutex-guarded because the factory caches ONE module
	// instance per bundle (factory.LoadModule) — every hyperv resource on a
	// steward shares this instance, and the monitor goroutine's targeted
	// reconciles run concurrently with the convergence loop. It is populated by
	// setVM (which receives the per-resource desired config as an argument, so it
	// is correctly scoped per VM), NOT by Configure (a module-level hook on the
	// shared instance — using it for per-VM state would race/leak across VMs). A
	// VM converges its policy on the first Set (the authored `checkpoints` key
	// drifts until getVM can echo it); an empty entry ⇒ observe-only.
	checkpointDesiredMu sync.RWMutex
	checkpointDesired   map[string]interface{}

	// vhdPathDesired maps a VM name to the authored `vhd_path` last seen for it,
	// so getVM can echo the desired path back on the Get surface WHEN the VM's
	// disk already lives in the desired home directory (#2776 follow-up). The
	// module manages the VHD's home DIRECTORY (#2411 convergeStorageLocation keys
	// on vmHomeDir), never the file's leaf name — a rename (Rename-VM) does not
	// rename the VHD, and the module never renames disk files. Without the echo, a
	// declared vhd_path whose leaf differs from the on-disk file (e.g. after a
	// rename) drifts forever on a difference the module will not reconcile. Keyed
	// by VM name + mutex-guarded for the same shared-instance reason as
	// checkpointDesired; populated by setVM, echoed by getVM only when the home
	// directory already matches (a wrong directory still drifts → storage move).
	vhdPathDesiredMu sync.RWMutex
	vhdPathDesired   map[string]string

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

	// csvProvisionStore, when non-nil, overrides the CSV-backed store that
	// storeFor constructs for an ha_role+CSV VM (ADR-009 A1.4 Option A, #2447).
	// In production it is nil and storeFor builds one rooted at the VM's CSV home
	// per convergence; tests inject a fake here to assert routing and drive the
	// surface-and-wait behavior without a real CSV mount (mirrors the
	// provisionStore/WithProvisionStore seam).
	csvProvisionStore ProvisionStore

	// fallbackMoveStore backs the storage-location move records (#2411) when
	// provisionStore does not implement MoveStore (both in-repo stores do; this
	// exists so a custom ProvisionStore cannot panic the move path). Lazily
	// created by moveStore().
	fallbackMoveStore *memProvisionStore

	// profileStore loads unattended-install profiles referenced as
	// profile://<name> in a VM source (ADR-009 §7). It is wired from the
	// controller's stored-config backend in Configure() when a "config_store"
	// is supplied, or injected directly in tests via WithProfileStore. It may
	// be nil when no config store is available; callers must handle that.
	profileStore ProfileStore

	// enroll* hold the controller-supplied enrollment wiring for the
	// create-from-source path (ADR-010 §2/§4). They arrive via the existing
	// controller→steward config sync (NOT the steward's local SecretStore,
	// which has no operator write path — the #2077 gap). enrollToken is the
	// tenant's low-sensitivity join token baked into the rendered answer file;
	// enrollCAFingerprint is the controller CA's SHA-256 for the guest's
	// install-time TOFU; enrollStewardPath / enrollCAPath are host paths to the
	// steward binary and CA cert staged onto the seed VHDX so the guest can
	// self-install without guest network/installer infra. enrollLauncherPath is
	// the host path to the cfgms-steward-launcher binary, staged alongside the
	// steward so the guest performs a launcher-managed (push-upgradeable) install
	// — Linux `cfgms-steward install` requires the launcher next to it.
	enrollToken         string
	enrollCAFingerprint string
	enrollStewardPath   string
	enrollLauncherPath  string
	enrollCAPath        string

	// debugSSHAuthorizedKey is an optional SSH PUBLIC key added to a provisioned
	// Linux guest's authorized_keys so operators can log in to diagnose a failed
	// enrollment. Empty = disabled (production default). A public key is not a
	// secret. From config key "debug_ssh_authorized_key".
	debugSSHAuthorizedKey string

	// seedDir is a host-local directory for the ephemeral provisioning seed
	// VHDX. It MUST NOT be on a Cluster Shared Volume (C:\ClusterStorage\...):
	// Mount-VHD against a CSV-resident VHDX hangs on a cluster node. When empty
	// the seed lands next to the VM's primary VHD (fine for non-cluster hosts).
	seedDir string

	// Monitor (modules.Monitor, #2114) state. A single host-level Windows Event
	// Log subscription fans out to per-VM ChangeEvents on the one monChanges
	// channel. Fields live here (cross-platform) so module.go owns the struct;
	// the subscription is driven entirely by the build-tagged monitor_*.go files.
	//
	// monSub holds the wevtapi EvtSubscribe handle as a uintptr so this struct
	// stays platform-neutral (monitor_windows.go casts it to windows.Handle).
	// Zero means "no active subscription". monInterest is the set of registered
	// resourceIDs (vm:<name>); the subscription is created on first interest and
	// torn down when the last is removed or on Close.
	monMu       sync.Mutex               //nolint:unused // written and read by monitor_windows.go; invisible to non-Windows builds
	monChanges  chan modules.ChangeEvent //nolint:unused // written and read by monitor_windows.go; invisible to non-Windows builds
	monInterest map[string]struct{}      //nolint:unused // written and read by monitor_windows.go; invisible to non-Windows builds
	monSub      uintptr                  //nolint:unused // written and read by monitor_windows.go; invisible to non-Windows builds
	monClosed   bool                     //nolint:unused // written and read by monitor_windows.go; invisible to non-Windows builds
	// monTeardown stops the reader goroutine and releases the EvtSubscribe and
	// signal handles. It is set by the platform establish routine when the
	// subscription is created and cleared on Close. nil means "no subscription".
	monTeardown func() error //nolint:unused // written and read by monitor_windows.go; invisible to non-Windows builds

	// Cluster DNA Monitor (#2241) state. Unlike the VM monitor (one host-level
	// Event Log subscription), each watched cluster gets its own polling
	// goroutine — there is no FailoverCluster event channel, so ownership /
	// membership is polled on a ticker and emitted as a ChangeEvent with a
	// *ClusterStatus payload (the epic #415 DNA contract). Fields are guarded by
	// monMu; the pollers are owned by the Monitor()/Close() lifecycle.
	monClusterInterest map[string]struct{}      //nolint:unused // written and read by monitor_windows.go / cluster_windows.go
	monClusterStop     map[string]chan struct{} //nolint:unused // per-cluster poller stop channels
	monClusterWG       sync.WaitGroup           //nolint:unused // joins cluster pollers before the changes channel is closed
	// clusterPollInterval overrides the cluster DNA poll cadence (Configure key
	// "cluster_poll_interval", a Go duration string). Zero ⇒ the 30s default.
	clusterPollInterval time.Duration //nolint:unused // read by monitor_windows.go (cluster poller)
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

// WithCSVProvisionStore overrides the CSV-backed ProvisionStore that storeFor
// otherwise constructs per-VM for an ha_role+CSV VM (#2447). Tests inject a fake
// to assert store routing and drive the mid-provision-failover surface-and-wait
// path without a real Cluster Shared Volume. A nil store is ignored.
func WithCSVProvisionStore(s ProvisionStore) HypervOption {
	return func(m *hypervModule) {
		if s != nil {
			m.csvProvisionStore = s
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
		executor:          newExecutor(),
		vms:               make(map[string]VMConfig),
		vswitches:         make(map[string]VSwitchConfig),
		checkpointDesired: make(map[string]interface{}),
		vhdPathDesired:    make(map[string]string),
		detector:          detector,
		provisionStore:    NewMemProvisionStore(),
		// Freshness window for the bulk cluster-owner read cache (Story #2577).
		// Long enough to collapse the per-VM membership probes of a single
		// converge pass into one cluster read, short enough that an external
		// failover is picked up on the read path within a few seconds; any op we
		// perform invalidates it immediately regardless.
		clusterOwnersTTL: 5 * time.Second,
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

	// Controller-supplied enrollment wiring for create-from-source (ADR-010).
	// These ride the existing config sync; absence is non-fatal (a VM source
	// without enrollment still creates/installs, it just won't auto-register).
	m.enrollToken, _ = configMap["enroll_token"].(string)
	m.enrollCAFingerprint, _ = configMap["enroll_ca_fingerprint"].(string)
	m.enrollStewardPath, _ = configMap["enroll_steward_path"].(string)
	m.enrollLauncherPath, _ = configMap["enroll_launcher_path"].(string)
	m.enrollCAPath, _ = configMap["enroll_ca_path"].(string)
	m.debugSSHAuthorizedKey, _ = configMap["debug_ssh_authorized_key"].(string)
	m.seedDir, _ = configMap["seed_dir"].(string)

	// Failover-cluster scope cap (S5). cluster_name bounds which cluster this
	// steward will read; cluster_role_names bounds the clustered VM roles in
	// scope. nodeHostname is the local node identity recorded on ownership audit
	// events (S8) — recordHypervOp's host arg is empty under the ps-host
	// transport, so capture os.Hostname() once here. A failed os.Hostname()
	// leaves it "" (non-fatal); audit then records an empty node identity, which
	// the ownership helper still functions without.
	m.clusterName, _ = configMap["cluster_name"].(string)
	// An ha_role vm resource carries its cluster name only under the nested
	// ha_role block, never as a top-level cluster_name key. Derive the S5 scope
	// cap from there when the top-level key is absent, so the Get path
	// (probeClusterRoleMembership) can report ha_role in current state and the
	// resource round-trips through the executor's verify step. Without this,
	// m.clusterName stays "" for an ha_role vm, the probe is gated off, Get omits
	// ha_role, and every converge cycle re-detects it as unapplied "added" drift
	// — a resource that never reports converged (Story #2577).
	if m.clusterName == "" {
		if hr := parseHARoleMap(configMap["ha_role"]); hr != nil {
			m.clusterName = hr.ClusterName
		}
	}
	m.clusterRoleNames = parseStringList(configMap["cluster_role_names"])
	m.nodeHostname, _ = os.Hostname()
	// Optional cluster DNA poll cadence (#2241). Accept a Go duration string;
	// an unset/invalid value leaves the 30s default in place.
	if pollStr, ok := configMap["cluster_poll_interval"].(string); ok && pollStr != "" {
		if d, derr := time.ParseDuration(pollStr); derr == nil && d > 0 {
			m.clusterPollInterval = d
		}
	}

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
		// Reuse an already-established PS host transport. Configure is called on
		// every convergence/reconcile pass (the executor re-configures before each
		// Get/Set); spawning a fresh powershell.exe each time would orphan the prior
		// subprocess (and its stderr-drain goroutine) and leak a handle per cycle.
		// When a live ps-host transport already exists, keep it.
		if _, ok := m.transport.(*psHostTransport); ok {
			return nil
		}
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
//   - "cluster:<name>": retrieve ClusterStatus (read-only) for the named
//     failover cluster, subject to the cluster_name scope cap (S5)
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
	case "cluster":
		return m.getCluster(ctx, name)
	default:
		return nil, modules.ErrNotImplemented
	}
}

// parseStringList normalises a config-map value into a []string. It accepts a
// native []string (module-decoded YAML) and a []interface{} (executor-supplied
// generic map). Any other shape — including nil — yields a nil slice.
func parseStringList(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		out := make([]string, len(t))
		copy(out, t)
		return out
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Set applies the desired Hyper-V resource configuration.
// Supported resource ID prefixes:
//   - "vm:<name>": create, update, or delete the named virtual machine
//   - "vswitch:<name>": create or delete the named virtual switch
//   - "cluster:<name>": create / remove clustered VM roles on the named
//     failover cluster (S2). Only the CNO-owner node mutates (coordination, not
//     authorization); role removal is gated behind allow_destructive (S6).
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
	case "cluster":
		if config == nil {
			return modules.ErrNotImplemented
		}
		return m.setCluster(ctx, resourceID, config)
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
