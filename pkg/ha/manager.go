// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/version"
)

// clusterLeadershipLeaseName is the pkg/lease lease name used for the cluster
// singleton-leadership claim (ADR-031 Decision 5). One HA cluster shares exactly
// one lease under this name; every ClusterMode Manager that has had a lease store
// wired contends for it under its own node ID as holderID.
const clusterLeadershipLeaseName = "controller-cluster-leadership"

// usesLeaseAuthority reports whether this deployment mode derives HasLeadership()
// and GetTerm() from the cluster leadership lease (ADR-031 Decision 5), and
// therefore also whether it wires the shared controller-node registry (Issue
// #3763) that backs GetClusterNodes()/GetLeader().
//
// Only ClusterMode does. The lease is a mutual-exclusion primitive, and exclusion
// comes from the substrate, not from the algorithm: it is authority only when
// every node contends for the same rows in a shared database, which is the
// storage tier ClusterMode — and only ClusterMode — deploys. SingleServerMode
// needs no lease at all (ADR-029 Decision 4's unconditional-true short-circuit).
// BlueGreenMode runs the node-local storage tier, so a lease acquired there would
// be acquired independently and successfully by *both* the blue and the green
// node against their own database files, each minting its own token sequence from
// 1 — two simultaneous "singleton" holders and two fencing sequences, which is
// precisely the condition the lease exists to make impossible. Blue-green
// therefore has no lease-backed authority: HasLeadership() stays false and
// leader-gated mutating endpoints stay closed, which is where that mode was
// before ADR-031 and is the safe direction to be wrong in. The same reasoning
// governs the node registry: a node-local substrate would let the blue and green
// node each believe they are the entire cluster.
func (m *Manager) usesLeaseAuthority() bool {
	return m.cfg != nil && m.cfg.Mode == ClusterMode
}

// Manager implements the ClusterManager interface and coordinates all HA operations
type Manager struct {
	mu     sync.RWMutex
	cfg    *Config
	logger logging.Logger

	// Core components
	nodeInfo      *NodeInfo
	healthChecker *HealthChecker
	failover      *failoverManager

	// State management
	storageManager *interfaces.StorageManager
	isStarted      bool
	startTime      time.Time
	ctx            context.Context
	cancel         context.CancelFunc

	// Cluster state. Always contains at least the local node; used verbatim by
	// GetClusterNodes() whenever nodeRegistryStore is nil (SingleServerMode,
	// BlueGreenMode, or a ClusterMode deployment without a registry store wired).
	clusterNodes map[string]*NodeInfo

	// Health checks
	healthChecks map[string]HealthCheckFunc
	healthStatus *HealthStatus

	// leaseManager, when non-nil, backs HasLeadership()/GetTerm() with the S3
	// database lease (pkg/lease, ADR-031 Decision 5). nil until wired by
	// NewManager (usesLeaseAuthority gates this to ClusterMode); always nil in
	// SingleServerMode, which never consults it (Decision 4's
	// unconditional-true short-circuit).
	leaseManager *lease.Manager
	// leaseRenewalInterval is the interval Start()'s background acquisition loop
	// ticks at. Set alongside leaseManager by SetLeaseStore so the loop renews
	// often enough relative to the lease TTL to keep leaseManager's derived
	// SafetyMargin() meaningful.
	leaseRenewalInterval time.Duration

	// backgroundLoopLeaseManager, when non-nil, backs SingletonJobs returned by
	// NewBackgroundLoopLease (ADR-031 Decision 4) — a distinct lease population
	// from leaseManager (cluster leadership): background loops (sweeps, expiry
	// jobs, schedulers) contend under their own lease names, sized for typical
	// sweep cadences (backgroundLoopLeaseTTL/backgroundLoopRenewInterval) rather
	// than cfg.Cluster.ElectionTimeout. Wired alongside leaseManager from the
	// same store by setLeaseStoreLocked; nil wherever leaseManager is nil.
	backgroundLoopLeaseManager *lease.Manager

	// nodeRegistryStore, when non-nil, backs GetClusterNodes()/GetLeader() with
	// the shared controller-node registry (Issue #3763, ADR-031 Decision 5's
	// post-Raft membership mechanism) instead of the local-only clusterNodes
	// map. nil until wired by NewManager (usesLeaseAuthority's same ClusterMode
	// gate); nil whenever the running storage provider does not implement
	// business.NodeRegistryStoreCreator.
	nodeRegistryStore business.NodeRegistryStore
}

// backgroundLoopLeaseTTL and backgroundLoopRenewInterval configure every lease
// NewBackgroundLoopLease constructs, and also the node-registry self-registration
// loop (runNodeRegistration): a single fixed configuration keeps the derived
// staleness window uniform and simple to reason about. A dead holder's lease (or
// a departed node's registry record) frees up within backgroundLoopLeaseTTL
// regardless of which loop or node it names, since business.NodeRegistryStaleAfter
// is set to the same 90s value; RegisterNode's per-cycle call refreshes it for a
// live node on every tick that lands within that window.
const (
	backgroundLoopLeaseTTL      = 90 * time.Second
	backgroundLoopRenewInterval = 20 * time.Second
)

// NewManager creates a new HA manager.
func NewManager(cfg *Config, logger logging.Logger, storageManager *interfaces.StorageManager) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid HA configuration: %w", err)
	}

	// Load configuration from environment
	if err := cfg.LoadFromEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to load HA configuration from environment: %w", err)
	}

	// Generate node ID if not provided
	if cfg.Node.ID == "" {
		nodeID, err := generateNodeID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate node ID: %w", err)
		}
		cfg.Node.ID = nodeID
	}

	// Set default node name if not provided
	if cfg.Node.Name == "" {
		cfg.Node.Name = fmt.Sprintf("controller-%s", cfg.Node.ID[:8])
	}

	// Create node info
	nodeInfo := &NodeInfo{
		ID:               cfg.Node.ID,
		Address:          cfg.Node.ExternalAddress,
		State:            NodeStateHealthy,
		Role:             NodeRoleFollower,
		StartedAt:        time.Now(),
		Version:          version.Short(),
		Capabilities:     cfg.Node.Capabilities,
		Region:           cfg.Node.Region,
		AvailabilityZone: cfg.Node.AvailabilityZone,
		Coordinates:      cfg.Node.Coordinates,
		Latency:          make(map[string]time.Duration),
	}

	// For single server mode, this node is always the leader
	if cfg.Mode == SingleServerMode {
		nodeInfo.Role = NodeRoleLeader
	}

	manager := &Manager{
		cfg:            cfg,
		logger:         logger,
		nodeInfo:       nodeInfo,
		storageManager: storageManager,
		clusterNodes:   make(map[string]*NodeInfo),
		healthChecks:   make(map[string]HealthCheckFunc),
		healthStatus: &HealthStatus{
			Overall:   NodeStateHealthy,
			Checks:    make(map[string]NodeState),
			Timestamp: time.Now(),
			Details:   make(map[string]string),
		},
	}

	// Add this node to cluster nodes
	manager.clusterNodes[nodeInfo.ID] = nodeInfo

	// Initialize components based on deployment mode
	if err := manager.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize HA components: %w", err)
	}

	// Wire the leadership lease and the shared node registry from the storage
	// manager this Manager was handed (ADR-031 Decision 5, Issue #3763).
	// Deriving the substrate here rather than leaving it to an opt-in
	// SetLeaseStore call is deliberate: in ClusterMode the lease *is* the
	// authority source, so a construction path that forgets to wire it does not
	// produce a manager with a missing option, it produces a manager whose
	// HasLeadership() is permanently false and whose GetTerm() stamps 0.
	// SetLeaseStore remains available to override this (tests, alternate stores).
	// A provider that supplies no lease store leaves this nil and Start() refuses.
	//
	// Only ClusterMode wires either — see usesLeaseAuthority for why a
	// node-local substrate must never become cluster-wide authority or
	// membership in the other modes.
	if manager.usesLeaseAuthority() && storageManager != nil {
		if leaseStore := storageManager.GetLeaseStore(); leaseStore != nil {
			if err := manager.setLeaseStoreLocked(leaseStore); err != nil {
				return nil, fmt.Errorf("failed to wire leadership lease store: %w", err)
			}
		}
		if nodeRegistryStore := storageManager.GetNodeRegistryStore(); nodeRegistryStore != nil {
			manager.nodeRegistryStore = nodeRegistryStore
		}
	}

	manager.logger.Info("HA Manager initialized",
		"mode", cfg.GetModeString(),
		"node_id", nodeInfo.ID)

	return manager, nil
}

// Start begins the HA operations
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isStarted {
		return fmt.Errorf("HA manager is already started")
	}

	// ADR-031 Decision 5: in ClusterMode, HasLeadership() and GetTerm() are backed
	// exclusively by the database lease. Starting without one is not a degraded
	// mode, it is a disabled security control: HasLeadership() would be false
	// forever (every leader-gated mutating endpoint 503s) and GetTerm() would stamp
	// 0 on every outbound command, which the steward fence ratchet reads as
	// "unstamped" — accepted unconditionally by a fresh steward and rejected
	// unconditionally by a ratcheted one. Refuse to start instead.
	if m.usesLeaseAuthority() && m.leaseManager == nil {
		return fmt.Errorf(
			"HA mode %q requires a lease store for leadership authority: call SetLeaseStore before Start (ADR-031 Decision 5)",
			m.cfg.GetModeString())
	}

	// m.ctx bounds every long-lived background component started below (health
	// checker, node-registry self-registration, failover) — it must live for the
	// Manager's full lifetime, cancelled only by Stop(). It is deliberately NOT
	// derived from the ctx parameter: callers commonly wrap a short
	// startup-timeout context around this call (e.g. server.go's Start() uses a
	// 30s context.WithTimeout solely to bound this synchronous call, via `defer
	// cancel()` on return) — reusing that as the source for m.ctx would cancel
	// every background component within milliseconds of Start() returning.
	// Reproduced live during #3130: the node-info replication goroutine's
	// ctx.Done() fired ~1ms after entering its select, before the cluster could
	// converge, so GET /api/v1/ha/cluster always returned an empty node list
	// despite a genuinely healthy cluster.
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.startTime = time.Now()
	m.nodeInfo.StartedAt = m.startTime
	m.nodeInfo.LastSeen = m.startTime

	m.logger.Info("Starting HA Manager", "mode", m.cfg.GetModeString())

	// Start health checker with a snapshot of currently-registered checks.
	// m.mu is held here so the snapshot is consistent with the map state.
	if m.healthChecker != nil {
		checkSnapshot := make(map[string]HealthCheckFunc, len(m.healthChecks))
		for name, fn := range m.healthChecks {
			checkSnapshot[name] = fn
		}
		if err := m.healthChecker.Start(m.ctx, checkSnapshot); err != nil {
			return fmt.Errorf("failed to start health checker: %w", err)
		}
	}

	switch m.cfg.Mode {
	case ClusterMode:
		if err := m.startClusterMode(); err != nil {
			return fmt.Errorf("failed to start cluster mode: %w", err)
		}
	case BlueGreenMode:
		if err := m.startBlueGreenMode(); err != nil {
			return fmt.Errorf("failed to start blue-green mode: %w", err)
		}
	case SingleServerMode:
		m.logger.Info("Running in single server mode - no additional HA components needed")
	}

	// Start the S3 database-lease acquisition loop (ADR-031 Decision 5) when a
	// lease store has been wired via SetLeaseStore. SingleServerMode never has a
	// leaseManager (SetLeaseStore no-ops there), so this never runs for it.
	if m.leaseManager != nil {
		lm := m.leaseManager
		nodeID := m.nodeInfo.ID
		renewalInterval := m.leaseRenewalInterval
		go m.runLeaseAcquisition(m.ctx, lm, nodeID, renewalInterval)
	}

	// Start the shared node-registry self-registration loop (Issue #3763,
	// ADR-031 Decision 5's post-Raft membership mechanism) when a registry
	// store has been wired. SingleServerMode and BlueGreenMode never wire one
	// (see usesLeaseAuthority), so this never runs for them.
	if m.nodeRegistryStore != nil {
		store := m.nodeRegistryStore
		self := business.NodeRecord{ID: m.nodeInfo.ID, Address: m.nodeInfo.Address}
		go m.runNodeRegistration(m.ctx, store, self)
	}

	m.isStarted = true
	m.logger.Info("HA Manager started successfully")

	return nil
}

// Stop gracefully stops the HA operations
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isStarted {
		return nil
	}

	m.logger.Info("Stopping HA Manager")

	// Cancel the context to stop all background operations
	if m.cancel != nil {
		m.cancel()
	}

	// Stop all components
	var stopErrors []error

	if m.healthChecker != nil {
		if err := m.healthChecker.Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("health checker stop: %w", err))
		}
	}

	if m.failover != nil {
		if err := m.failover.Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failover stop: %w", err))
		}
	}

	m.isStarted = false

	if len(stopErrors) > 0 {
		return fmt.Errorf("errors during HA manager stop: %v", stopErrors)
	}

	m.logger.Info("HA Manager stopped successfully")
	return nil
}

// GetDeploymentMode returns the current deployment mode
func (m *Manager) GetDeploymentMode() DeploymentMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Mode
}

// GetCACertPEM returns the CA certificate PEM bytes for HA peer verification.
// Returns nil when CACertPath is empty or the file cannot be read; logs a warning
// on read failure so operators can detect misconfiguration.
// Safe to call concurrently.
func (m *Manager) GetCACertPEM() []byte {
	m.mu.RLock()
	path := m.cfg.CACertPath
	m.mu.RUnlock()

	if path == "" {
		return nil
	}

	// #nosec G304 -- certificate paths are operator-controlled configuration values
	certPEM, err := os.ReadFile(path)
	if err != nil {
		m.logger.Warn("Failed to read HA CA certificate", "path", path, "error", err)
		return nil
	}
	return certPEM
}

// GetLocalNode returns information about the local node
func (m *Manager) GetLocalNode() *NodeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to prevent modification
	nodeInfo := *m.nodeInfo
	nodeInfo.LastSeen = time.Now()
	return &nodeInfo
}

// GetClusterNodes returns information about all nodes in the cluster.
// Backed by the shared controller-node registry (Issue #3763, ADR-031 Decision
// 5's post-Raft membership mechanism) when one is wired. SingleServerMode,
// BlueGreenMode, and any ClusterMode deployment whose storage provider does not
// implement business.NodeRegistryStoreCreator fall back to reporting only the
// nodes known locally — in practice, just this node.
func (m *Manager) GetClusterNodes() ([]*NodeInfo, error) {
	m.mu.RLock()
	nodeRegistryStore := m.nodeRegistryStore
	m.mu.RUnlock()

	if nodeRegistryStore != nil {
		records, err := nodeRegistryStore.ListNodes(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to list cluster nodes: %w", err)
		}
		nodes := make([]*NodeInfo, 0, len(records))
		for _, r := range records {
			nodes = append(nodes, &NodeInfo{ID: r.ID, Address: r.Address})
		}
		return nodes, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	nodes := make([]*NodeInfo, 0, len(m.clusterNodes))
	for _, node := range m.clusterNodes {
		// Create a copy to prevent modification
		nodeCopy := *node
		nodes = append(nodes, &nodeCopy)
	}

	return nodes, nil
}

// HasLeadership returns true when this node is authorised to perform side-effecting
// operations. In SingleServerMode it is unconditionally true (Decision 4, ADR-029):
// there is no quorum to lose and no peer to overlap with, so no lease is needed.
// In ClusterMode it is backed by the S3 database lease (pkg/lease, ADR-031
// Decision 5): true iff this node's node ID currently holds cached local
// authority for clusterLeadershipLeaseName, per leaseManager.HasLocalAuthority's
// monotonic-clock SafetyMargin bound. Returns false when no lease store is
// wired — this fails closed. That state is not reachable on a running
// ClusterMode node: Start() refuses to run without a lease store, precisely so
// an unwired substrate is a loud startup failure rather than a node that
// silently 503s every mutating endpoint and stamps fencing token 0 on every
// command it publishes.
//
// BlueGreenMode returns false: it deploys a node-local storage tier, and a lease
// on a node-local substrate excludes nothing (see usesLeaseAuthority). False is
// the fail-closed answer — leader-gated mutating endpoints refuse on both the
// blue and the green node rather than both nodes claiming to be the singleton.
func (m *Manager) HasLeadership() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cfg.Mode == SingleServerMode {
		return true
	}

	if m.leaseManager != nil {
		_, ok := m.leaseManager.HasLocalAuthority(clusterLeadershipLeaseName, m.nodeInfo.ID)
		return ok
	}

	return false
}

// GetTerm returns the current fencing token, sourced from the S3 database lease
// (pkg/lease, ADR-031 Decision 5). It returns the token cached by this node's
// most recent successful acquire/renew — the same cache HasLeadership() reads —
// so a caller that calls GetTerm() only after observing HasLeadership() == true
// is guaranteed a non-zero token. Returns 0 in SingleServerMode and
// BlueGreenMode (neither has lease-backed authority — see usesLeaseAuthority),
// when no lease store has been wired, and whenever this node does not currently
// hold cached local authority.
func (m *Manager) GetTerm() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.leaseManager != nil {
		if token, ok := m.leaseManager.HasLocalAuthority(clusterLeadershipLeaseName, m.nodeInfo.ID); ok {
			return token
		}
	}

	return 0
}

// NewBackgroundLoopLease constructs a lease.SingletonJob for the cluster-
// singleton background loop named name (ADR-031 Decision 4: leadership shrinks
// to singleton scheduling). Background loops (sweeps, expiry jobs, schedulers)
// are a distinct lease population from the cluster leadership lease
// (clusterLeadershipLeaseName / HasLeadership()): each loop contends
// independently under its own lease name, using backgroundLoopLeaseTTL/
// backgroundLoopRenewInterval rather than cfg.Cluster.ElectionTimeout.
//
// The returned SingletonJob has a nil lease.Manager — so RunIfLeader always
// executes fn — whenever this deployment has no shared lease substrate to
// arbitrate on: SingleServerMode has one node and nothing to exclude (ADR-029
// Decision 4), and any other non-ClusterMode deployment has no node-shared
// store wired at all (see usesLeaseAuthority). This mirrors HasLeadership()'s
// own fail-to-unconditional SingleServerMode short-circuit, so a background
// loop that gates on this behaves identically to today's ungated loop on every
// deployment that is not a multi-node cluster.
//
// Safe to call on a nil *Manager — many composition roots pass a nil
// *ha.Manager for OSS single-node deployments (the same convention as the
// existing "nil haManager = OSS single-node = always leader" checks), and
// every background loop's call site can therefore use this method
// unconditionally rather than repeating that nil check itself.
func (m *Manager) NewBackgroundLoopLease(name string, logger logging.Logger) (lease.SingletonJob, error) {
	if m == nil {
		return lease.NewSingletonJob(nil, name, "single-node", 0, 0, logger)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.backgroundLoopLeaseManager == nil {
		return lease.NewSingletonJob(nil, name, m.nodeInfo.ID, 0, 0, logger)
	}
	return lease.NewSingletonJob(m.backgroundLoopLeaseManager, name, m.nodeInfo.ID, backgroundLoopLeaseTTL, backgroundLoopRenewInterval, logger)
}

// SetLeaseStore replaces the S3 database-lease store (pkg/lease, ADR-031 Decision 5)
// that backs HasLeadership()/GetTerm() in ClusterMode. It is an override, not the
// primary wiring: NewManager already wires the store supplied by the StorageManager
// it is handed, so the substrate cannot be silently skipped by a construction path
// that forgets to call this. Call it (before Start) only to supply a store the
// StorageManager does not have. In ClusterMode a nil store is an error, not a
// silent unwiring.
//
// A no-op in every mode that does not derive authority from the lease
// (usesLeaseAuthority): SingleServerMode never consults one (Decision 4's
// unconditional-true short-circuit) and BlueGreenMode must not, because its
// node-local substrate would hand both the blue and the green node simultaneous
// leadership. A no-op rather than an error keeps that guarantee independent of
// what any caller passes: no store handed to a non-cluster Manager can ever
// become its authority.
//
// Whether a given store's substrate is genuinely shared by all nodes is not
// decidable here — a store is an object, and "every node contends on it" is a
// property of the deployment that composed it. The composition layer owns that
// check: the controller startup path refuses to build a ClusterMode manager unless
// the wired store reports business.LeaseStoreIsNodeShared (see
// features/controller/server.initializeHAManager). In-process tests legitimately
// share one node-local store between two Managers, which is real exclusion within
// that process and no basis for rejecting the store here.
//
// The constructed pkg/lease.Manager's leaseTTL/renewalInterval/
// maxAllowedRenewalLatency are derived from cfg.Cluster.ElectionTimeout using the
// same 0.8 ratio ADR-029 Decision 1 established (leaseDuration = 0.8 ×
// ElectionTimeout — see ClusterConfig.LeaseDuration): TTL equals ElectionTimeout,
// and renewalInterval/maxAllowedRenewalLatency each take half of the remaining
// 0.2, so the derived SafetyMargin lands on the identical bound already
// validated for this deployment's ElectionTimeout. This method only chooses
// those three inputs — the margin itself is pkg/lease.SafetyMargin's derivation,
// not re-derived here.
func (m *Manager) SetLeaseStore(store business.LeaseStore) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setLeaseStoreLocked(store)
}

// setLeaseStoreLocked is SetLeaseStore's body without the lock, so NewManager can
// reuse it while the Manager is still unpublished. Callers must hold m.mu (or own
// the Manager exclusively, as NewManager does).
func (m *Manager) setLeaseStoreLocked(store business.LeaseStore) error {
	if !m.usesLeaseAuthority() {
		return nil
	}

	// lease.NewManager also rejects a nil store, but naming the caller's mistake
	// here keeps the startup error actionable: a nil here means the running
	// storage provider supplies no LeaseStore, not that pkg/lease misconfigured.
	if store == nil {
		return fmt.Errorf(
			"HA mode %q requires a shared-database lease store but none was supplied; the configured storage provider does not implement interfaces.LeaseStoreCreator (ADR-031 Decision 5)",
			m.cfg.GetModeString())
	}

	electionTimeout := m.cfg.Cluster.ElectionTimeout
	ttl := electionTimeout
	renewalInterval := electionTimeout / 10
	maxAllowedRenewalLatency := electionTimeout / 10

	lm, err := lease.NewManager(store, ttl, renewalInterval, maxAllowedRenewalLatency)
	if err != nil {
		return fmt.Errorf("failed to construct lease manager: %w", err)
	}

	blLM, err := lease.NewManager(store, backgroundLoopLeaseTTL, backgroundLoopRenewInterval, backgroundLoopRenewInterval)
	if err != nil {
		return fmt.Errorf("failed to construct background-loop lease manager: %w", err)
	}

	m.leaseManager = lm
	m.leaseRenewalInterval = renewalInterval
	m.backgroundLoopLeaseManager = blLM
	return nil
}

// runLeaseAcquisition periodically calls TryAcquire so this node keeps contending
// for (or renewing) the S3 database lease that backs HasLeadership()/GetTerm()
// (ADR-031 Decision 5). Every ClusterMode node with a lease store wired contends
// for the same lease name — the database lease alone decides authority. Bounded
// by ctx (m.ctx, cancelled by Stop()) so the goroutine always exits.
func (m *Manager) runLeaseAcquisition(ctx context.Context, lm *lease.Manager, holderID string, renewalInterval time.Duration) {
	ttl := lm.LeaseTTL()
	ticker := time.NewTicker(renewalInterval)
	defer ticker.Stop()

	for {
		if _, _, err := lm.TryAcquire(ctx, clusterLeadershipLeaseName, holderID, ttl); err != nil {
			m.logger.Warn("Failed to acquire/renew cluster leadership lease",
				"error", logging.SanitizeLogValue(err.Error()))
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// runNodeRegistration periodically calls RegisterNode so this node's record in
// the shared controller-node registry (Issue #3763, ADR-031 Decision 5's
// post-Raft membership mechanism) never goes stale while it is live. It runs
// independently of leadership — every ClusterMode node with a registry store
// wired registers itself, regardless of which node currently holds the cluster
// leadership lease. Bounded by ctx (m.ctx, cancelled by Stop()) so the
// goroutine always exits.
func (m *Manager) runNodeRegistration(ctx context.Context, store business.NodeRegistryStore, self business.NodeRecord) {
	ticker := time.NewTicker(backgroundLoopRenewInterval)
	defer ticker.Stop()

	for {
		if err := store.RegisterNode(ctx, self); err != nil {
			m.logger.Warn("Failed to register cluster node",
				"error", logging.SanitizeLogValue(err.Error()))
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// GetLeader returns the current cluster leader node. In SingleServerMode the
// local node is always the leader. In ClusterMode the leader is whichever node
// currently holds the cluster leadership lease (ADR-031 Decision 5), resolved
// to a NodeInfo via the shared node registry (Issue #3763) when the holder is
// a peer, or the local node's own info when this node holds it. Returns an
// error if no lease store is wired or no node currently holds the lease.
func (m *Manager) GetLeader() (*NodeInfo, error) {
	m.mu.RLock()
	mode := m.cfg.Mode
	localNodeID := m.nodeInfo.ID
	localNodeInfo := *m.nodeInfo
	leaseManager := m.leaseManager
	nodeRegistryStore := m.nodeRegistryStore
	m.mu.RUnlock()

	if mode == SingleServerMode {
		return &localNodeInfo, nil
	}

	if leaseManager == nil {
		return nil, fmt.Errorf("no leader elected")
	}

	holderID, _, _, ok, err := leaseManager.CurrentHolder(context.Background(), clusterLeadershipLeaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to query cluster leadership lease: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("no leader elected")
	}

	if holderID == localNodeID {
		return &localNodeInfo, nil
	}

	if nodeRegistryStore != nil {
		if records, err := nodeRegistryStore.ListNodes(context.Background()); err == nil {
			for _, r := range records {
				if r.ID == holderID {
					return &NodeInfo{ID: r.ID, Address: r.Address}, nil
				}
			}
		}
	}

	return &NodeInfo{ID: holderID}, nil
}

// RegisterHealthCheck registers a health check function
func (m *Manager) RegisterHealthCheck(name string, check HealthCheckFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.healthChecks[name] = check
	m.logger.Debug("Health check registered", "name", name)
}

// GetHealth returns the current health status
func (m *Manager) GetHealth() *HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to prevent modification
	status := &HealthStatus{
		Overall:   m.healthStatus.Overall,
		Checks:    make(map[string]NodeState),
		Timestamp: m.healthStatus.Timestamp,
		Details:   make(map[string]string),
	}

	for name, state := range m.healthStatus.Checks {
		status.Checks[name] = state
	}

	for key, value := range m.healthStatus.Details {
		status.Details[key] = value
	}

	return status
}

// initializeComponents initializes HA components based on deployment mode
func (m *Manager) initializeComponents() error {
	// Always initialize health checker
	m.healthChecker = NewHealthChecker(m.cfg.HealthCheck, m.logger, m)

	// Register basic health checks
	m.registerBasicHealthChecks()

	// Initialize mode-specific components
	switch m.cfg.Mode {
	case ClusterMode:
		return m.initializeClusterComponents()
	case BlueGreenMode:
		return m.initializeBlueGreenComponents()
	case SingleServerMode:
		// No additional components needed for single server mode
		return nil
	default:
		return fmt.Errorf("unsupported deployment mode: %s", m.cfg.Mode)
	}
}

// initializeClusterComponents initializes components for cluster mode
func (m *Manager) initializeClusterComponents() error {
	var err error

	m.failover, err = NewFailoverManager(m.cfg.Failover, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize failover manager: %w", err)
	}

	return nil
}

// initializeBlueGreenComponents initializes components for blue-green mode.
// Discovery has been removed; blue-green mode requires no additional components.
func (m *Manager) initializeBlueGreenComponents() error {
	return nil
}

// startClusterMode starts components for cluster mode
func (m *Manager) startClusterMode() error {
	if m.failover != nil {
		if err := m.failover.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start failover manager: %w", err)
		}
	}

	return nil
}

// startBlueGreenMode starts components for blue-green mode.
// Discovery has been removed; blue-green mode starts with no additional components.
func (m *Manager) startBlueGreenMode() error {
	return nil
}

// registerBasicHealthChecks registers basic health checks
func (m *Manager) registerBasicHealthChecks() {
	// Register storage health check
	m.RegisterHealthCheck("storage", func(ctx context.Context) error {
		store := m.storageManager.GetConfigStore()
		if store == nil {
			return fmt.Errorf("config store not available")
		}
		return nil
	})

	// Register memory health check
	m.RegisterHealthCheck("memory", func(ctx context.Context) error {
		// Simple memory health check - could be enhanced with actual memory monitoring
		return nil
	})

	// Register disk health check
	m.RegisterHealthCheck("disk", func(ctx context.Context) error {
		// Simple disk health check - could be enhanced with actual disk space monitoring
		return nil
	})
}

// generateNodeID generates a unique node ID
func generateNodeID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
