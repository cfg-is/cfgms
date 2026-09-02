// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.etcd.io/raft/v3"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cptypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/cfgis/cfgms/pkg/version"
)

// clusterLeadershipLeaseName is the pkg/lease lease name used for the cluster
// singleton-leadership claim (ADR-031 Decision 5). One HA cluster shares exactly
// one lease under this name; every ClusterMode Manager that has had a lease store
// wired contends for it under its own node ID as holderID.
const clusterLeadershipLeaseName = "controller-cluster-leadership"

// usesLeaseAuthority reports whether this deployment mode derives HasLeadership()
// and GetTerm() from the cluster leadership lease (ADR-031 Decision 5).
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
// before ADR-031 and is the safe direction to be wrong in.
func (m *Manager) usesLeaseAuthority() bool {
	return m.cfg != nil && m.cfg.Mode == ClusterMode
}

// Manager implements the ClusterManager interface and coordinates all HA operations
type Manager struct {
	mu         sync.RWMutex
	cfg        *Config
	logger     logging.Logger
	raftLogDir string // directory for the per-node bbolt WAL; empty means in-memory only

	// Core components
	nodeInfo      *NodeInfo
	healthChecker *HealthChecker
	raftConsensus *RaftConsensus
	failover      *failoverManager
	splitBrain    *splitBrainDetector

	// State management
	storageManager *interfaces.StorageManager
	isStarted      bool
	startTime      time.Time
	ctx            context.Context
	cancel         context.CancelFunc

	// certManager supplies the mTLS client certificate for outbound Raft peer
	// transport. Required in ClusterMode; nil is accepted in SingleServerMode and
	// BlueGreenMode where no peer transport is created.
	certManager *cert.Manager

	// Session registry for steward connect/disconnect replication
	registry registry.Registry

	// controlPlaneProvider is used to dispatch reconnect commands to orphaned
	// stewards when this node becomes the Raft leader after a failover.
	controlPlaneProvider cpinterfaces.ControlPlaneProvider

	// signer, if set, signs reconnect commands before dispatch so stewards in
	// secured mode can authenticate them.
	signer signature.Signer

	// Cluster state
	clusterNodes map[string]*NodeInfo

	// Health checks
	healthChecks map[string]HealthCheckFunc
	healthStatus *HealthStatus

	// leaseManager, when non-nil, backs HasLeadership()/GetTerm() with the S3
	// database lease (pkg/lease, ADR-031 Decision 5) instead of RaftConsensus.
	// nil until SetLeaseStore is called; always nil in SingleServerMode, which
	// never consults it (Decision 4's unconditional-true short-circuit).
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
}

// backgroundLoopLeaseTTL and backgroundLoopRenewInterval configure every lease
// NewBackgroundLoopLease constructs. A single fixed configuration (independent
// of any one loop's own check interval) keeps the population's derived
// SafetyMargin uniform and simple to reason about: a dead holder's lease frees
// up within backgroundLoopLeaseTTL regardless of which loop it names, and
// RunIfLeader's per-cycle TryAcquire renews it for a live holder on every tick
// that lands within the TTL, whatever that loop's own cadence.
const (
	backgroundLoopLeaseTTL      = 90 * time.Second
	backgroundLoopRenewInterval = 20 * time.Second
)

// NewManager creates a new HA manager.
// certManager is required in ClusterMode to mint the mTLS client certificate that
// the outbound Raft peer transport presents on POST /raft/message. It may be nil in
// SingleServerMode and BlueGreenMode, which never create a peer transport.
// raftLogDir, when non-empty, is the directory where the per-node Raft WAL
// (raft.db) is stored. Pass an empty string in tests to use in-memory state only.
func NewManager(cfg *Config, logger logging.Logger, storageManager *interfaces.StorageManager, certManager *cert.Manager, raftLogDir string) (*Manager, error) {
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
		certManager:    certManager,
		raftLogDir:     raftLogDir,
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

	// Wire the leadership lease from the storage manager this Manager was handed
	// (ADR-031 Decision 5). Deriving the substrate here rather than leaving it to
	// an opt-in SetLeaseStore call is deliberate: in ClusterMode the lease *is* the
	// authority source, so a construction path that forgets to wire it does not
	// produce a manager with a missing option, it produces a manager whose
	// HasLeadership() is permanently false and whose GetTerm() stamps 0.
	// SetLeaseStore remains available to override this (tests, alternate stores).
	// A provider that supplies no lease store leaves this nil and Start() refuses.
	//
	// Only ClusterMode wires it — see usesLeaseAuthority for why a node-local
	// substrate must never become leadership authority in the other modes.
	if manager.usesLeaseAuthority() && storageManager != nil {
		if leaseStore := storageManager.GetLeaseStore(); leaseStore != nil {
			if err := manager.setLeaseStoreLocked(leaseStore); err != nil {
				return nil, fmt.Errorf("failed to wire leadership lease store: %w", err)
			}
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
	// checker, node-info replication goroutine, failover, split-brain
	// detection) — it must live for the Manager's full lifetime, cancelled only
	// by Stop(). It is deliberately NOT derived from the ctx parameter: callers
	// commonly wrap a short startup-timeout context around this call (e.g.
	// server.go's Start() uses a 30s context.WithTimeout solely to bound this
	// synchronous call, via `defer cancel()` on return) — reusing that as the
	// source for m.ctx cancelled every background component within
	// milliseconds of Start() returning, long before cluster-mode leader
	// election (~10s+) could complete. Reproduced live during #3130: the
	// node-info replication goroutine's ctx.Done() fired ~1ms after entering
	// its select, before leaderElectedC ever had a chance to fire, so
	// GET /api/v1/ha/cluster always returned an empty node list despite a
	// genuinely healthy Raft quorum.
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

	// Register session hooks so steward connect/disconnect events are replicated
	// through the Raft log when running in cluster mode.
	if m.raftConsensus != nil && m.registry != nil {
		rc := m.raftConsensus
		nodeID := m.nodeInfo.ID
		m.registry.OnConnect(func(stewardID string) {
			if err := rc.ProposeSessionUpdate(stewardID, nodeID, true); err != nil {
				m.logger.Warn("Failed to propose session connect",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
			}
		})
		m.registry.OnDisconnect(func(stewardID string) {
			if err := rc.ProposeSessionUpdate(stewardID, nodeID, false); err != nil {
				m.logger.Warn("Failed to propose session disconnect",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
			}
		})
	}

	// Wire the onBecomeLeader callback so the Raft consensus layer notifies the
	// manager when leadership transitions — the manager then dispatches reconnect
	// commands to stewards orphaned by the departed leader.
	if m.raftConsensus != nil {
		rc := m.raftConsensus
		rc.onBecomeLeader = func(ctx context.Context, departedNodeID string) {
			go m.handleBecomeLeader(ctx, departedNodeID)
		}
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

	m.isStarted = true
	m.logger.Info("HA Manager started successfully")

	return nil
}

// Stop gracefully stops the HA operations
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isStarted {
		// runRaft goroutine starts in NewRaftConsensus (called from initializeComponents,
		// before Start) and must be stopped even when Stop is called on a never-started
		// manager — otherwise it leaks. RaftConsensus.Stop is idempotent via sync.Once.
		if m.raftConsensus != nil {
			if err := m.raftConsensus.Stop(); err != nil {
				return fmt.Errorf("raft consensus stop: %w", err)
			}
		}
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

	if m.raftConsensus != nil {
		if err := m.raftConsensus.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("raft consensus stop: %w", err))
		}
	}

	if m.failover != nil {
		if err := m.failover.Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failover stop: %w", err))
		}
	}

	if m.splitBrain != nil {
		if err := m.splitBrain.Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("split-brain detector stop: %w", err))
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

// GetClusterNodes returns information about all nodes in the cluster
func (m *Manager) GetClusterNodes() ([]*NodeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Use Raft consensus as the single source of truth for cluster membership
	if m.raftConsensus != nil {
		return m.raftConsensus.GetClusterNodes(), nil
	}

	// Fallback to local cluster nodes map (for SingleServerMode)
	nodes := make([]*NodeInfo, 0, len(m.clusterNodes))
	for _, node := range m.clusterNodes {
		// Create a copy to prevent modification
		nodeCopy := *node
		nodes = append(nodes, &nodeCopy)
	}

	return nodes, nil
}

// IsLeader returns true if this node is the cluster leader.
// Deprecated: use IsRaftLeader() for protocol state or HasLeadership() for authority.
// Retained for callers not yet migrated to the split API (#3389).
func (m *Manager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Single server mode is always the leader
	if m.cfg.Mode == SingleServerMode {
		return true
	}

	// Raft consensus is the sole authority for leadership
	if m.raftConsensus != nil {
		return m.raftConsensus.IsLeader()
	}

	return false
}

// IsRaftLeader returns the raw Raft replication-protocol state. Returns false in
// SingleServerMode (no Raft node exists; use HasLeadership() for authority there).
// For status and observability only — not an admission primitive.
func (m *Manager) IsRaftLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.raftConsensus != nil {
		return m.raftConsensus.IsRaftLeader()
	}
	return false
}

// HasLeadership returns true when this node is authorised to perform side-effecting
// operations. In SingleServerMode it is unconditionally true (Decision 4, ADR-029):
// there is no quorum to lose and no peer to overlap with, so no lease is needed.
// In ClusterMode it is backed by the S3 database lease (pkg/lease, ADR-031
// Decision 5) rather than RaftConsensus: true iff this node's node ID currently
// holds cached local authority for clusterLeadershipLeaseName, per
// leaseManager.HasLocalAuthority's monotonic-clock SafetyMargin bound. Returns
// false when no lease store is wired — this fails closed rather than falling back
// to Raft. That state is not reachable on a running ClusterMode node: Start()
// refuses to run without a lease store, precisely so an unwired substrate is a
// loud startup failure rather than a node that silently 503s every mutating
// endpoint and stamps fencing token 0 on every command it publishes.
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
// (pkg/lease, ADR-031 Decision 5) rather than RaftConsensus.GetTerm(). It returns
// the token cached by this node's most recent successful acquire/renew — the same
// cache HasLeadership() reads — so a caller that calls GetTerm() only after
// observing HasLeadership() == true is guaranteed a non-zero token. Returns 0 in
// SingleServerMode and BlueGreenMode (neither has lease-backed authority — see
// usesLeaseAuthority), when no lease store has been wired, and whenever this node
// does not currently hold cached local authority.
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
// same 0.8 ratio Raft's own leader lease used (ADR-029 Decision 1:
// leaseDuration = 0.8 × ElectionTimeout — see ClusterConfig.LeaseDuration): TTL
// equals ElectionTimeout, and renewalInterval/maxAllowedRenewalLatency each take
// half of the remaining 0.2, so the derived SafetyMargin lands on the identical
// bound already validated for this deployment's ElectionTimeout. This method only
// chooses those three inputs — the margin itself is pkg/lease.SafetyMargin's
// derivation, not re-derived here.
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
// (ADR-031 Decision 5). It runs independently of Raft — every ClusterMode node
// with a lease store wired contends for the same lease name, regardless of
// whichever node RaftConsensus currently believes is its own leader. This is the
// point of the substrate swap: the database lease, not Raft, decides authority.
// Bounded by ctx (m.ctx, cancelled by Stop()) so the goroutine always exits.
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

// GetLeader returns the current cluster leader node
func (m *Manager) GetLeader() (*NodeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Single server mode: local node is always the leader
	if m.cfg.Mode == SingleServerMode {
		nodeInfo := *m.nodeInfo
		return &nodeInfo, nil
	}

	// Raft consensus is the sole authority for leadership
	if m.raftConsensus != nil {
		return m.raftConsensus.GetLeaderInfo()
	}

	return nil, fmt.Errorf("no leader elected")
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

// GetRaftTransport returns the Raft transport for HTTP endpoint handling
func (m *Manager) GetRaftTransport() RaftTransport {
	m.mu.RLock()
	rc := m.raftConsensus
	m.mu.RUnlock()

	if rc == nil {
		return nil
	}

	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.transport
}

// SetRegistry wires the active-steward connection registry so that connect and
// disconnect events are replicated through the Raft log (Issue #1326).
// Call this after NewManager returns but before Start is called.
func (m *Manager) SetRegistry(r registry.Registry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = r
}

// SetControlPlaneProvider wires the control-plane provider so that reconnect
// commands can be dispatched to orphaned stewards on leadership transition.
// Call this after NewManager returns but before Start is called.
func (m *Manager) SetControlPlaneProvider(p cpinterfaces.ControlPlaneProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.controlPlaneProvider = p
}

// SetSigner wires a command signer so that reconnect commands are cryptographically
// signed before dispatch. Call this after NewManager returns but before Start is called.
// When nil (the default), commands are sent unsigned — only suitable for clusters
// where stewards have not configured a command verifier.
func (m *Manager) SetSigner(s signature.Signer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signer = s
}

// handleBecomeLeader dispatches CommandReconnect to every steward whose session
// was registered to departedNodeID so they re-establish their ControlChannel
// against the new leader. Runs in a goroutine to avoid blocking the Raft loop.
func (m *Manager) handleBecomeLeader(ctx context.Context, departedNodeID string) {
	if departedNodeID == "" {
		return
	}

	m.mu.RLock()
	cp := m.controlPlaneProvider
	rc := m.raftConsensus
	signer := m.signer
	m.mu.RUnlock()

	if cp == nil || rc == nil {
		return
	}

	stewardIDs := rc.GetSessionsForNode(departedNodeID)
	m.logger.Info("Became leader, dispatching reconnect to orphaned stewards",
		"departed_node_id", logging.SanitizeLogValue(departedNodeID),
		"steward_count", len(stewardIDs))

	for _, stewardID := range stewardIDs {
		cmd := &cptypes.SignedCommand{
			Command: cptypes.Command{
				ID:        uuid.New().String(),
				Type:      cptypes.CommandReconnect,
				StewardID: stewardID,
				Timestamp: time.Now(),
			},
		}
		if signer != nil {
			signingBytes, err := cptypes.CommandSigningBytes(&cmd.Command, nil)
			if err != nil {
				m.logger.Warn("Failed to compute signing bytes for reconnect command",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
				continue
			}
			sig, err := signer.Sign(signingBytes)
			if err != nil {
				m.logger.Warn("Failed to sign reconnect command",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
				continue
			}
			cmd.Signature = sig
		}
		if err := cp.SendCommand(ctx, cmd); err != nil {
			m.logger.Warn("Failed to send reconnect command to orphaned steward",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", err)
		} else {
			m.logger.Info("Dispatched reconnect command to orphaned steward",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"command_id", cmd.Command.ID)
		}
	}
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

	// Initialize Raft consensus (sole source of truth for membership and leader election)
	if err := m.initializeRaftConsensus(); err != nil {
		return fmt.Errorf("failed to initialize Raft consensus: %w", err)
	}

	m.failover, err = NewFailoverManager(m.cfg.Failover, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize failover manager: %w", err)
	}

	m.splitBrain, err = NewSplitBrainDetector(m.cfg.SplitBrain, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize split-brain detector: %w", err)
	}

	return nil
}

// initializeRaftConsensus initializes the Raft consensus layer
func (m *Manager) initializeRaftConsensus() error {
	// Parse node ID as uint64 for Raft
	// Use a simple hash of the node ID string
	nodeID := hashStringToUint64(m.nodeInfo.ID)

	m.logger.Debug("Starting Raft consensus initialization",
		"node_id_string", m.nodeInfo.ID, "node_id_uint64", nodeID, "node_address", m.nodeInfo.Address)

	// Build peer list from cluster configuration
	peers := make([]raft.Peer, 0)

	// Parse cluster nodes from config
	m.logger.Debug("Parsing cluster nodes from config", "config_nil", m.cfg.Cluster.Discovery.Config == nil)

	// seenHashes guards against node ID hash collisions before they can silently alias
	// two distinct nodes to the same Raft peer ID.
	seenHashes := make(map[uint64]string) // hash → original string ID

	if clusterNodes := m.cfg.Cluster.Discovery.Config["nodes"]; clusterNodes != nil {
		m.logger.Debug("Found cluster nodes in config", "type", fmt.Sprintf("%T", clusterNodes))
		// Try both []interface{} and []map[string]interface{} type assertions
		if nodes, ok := clusterNodes.([]interface{}); ok {
			m.logger.Debug("Cluster nodes is []interface{}", "count", len(nodes))
			for i, n := range nodes {
				if nodeMap, ok := n.(map[string]interface{}); ok {
					if id, ok := nodeMap["id"].(string); ok {
						peerID := hashStringToUint64(id)
						if existing, dup := seenHashes[peerID]; dup {
							return fmt.Errorf("node ID hash collision: %q and %q both hash to %d", existing, id, peerID)
						}
						seenHashes[peerID] = id
						peers = append(peers, raft.Peer{
							ID:      peerID,
							Context: []byte(id), // Store original string ID
						})
						m.logger.Debug("Added peer to list", "index", i, "peer_id_string", id, "peer_id_uint64", peerID)
					}
				}
			}
		} else if nodes, ok := clusterNodes.([]map[string]interface{}); ok {
			m.logger.Debug("Cluster nodes is []map[string]interface{}", "count", len(nodes))
			for i, nodeMap := range nodes {
				if id, ok := nodeMap["id"].(string); ok {
					peerID := hashStringToUint64(id)
					if existing, dup := seenHashes[peerID]; dup {
						return fmt.Errorf("node ID hash collision: %q and %q both hash to %d", existing, id, peerID)
					}
					seenHashes[peerID] = id
					peers = append(peers, raft.Peer{
						ID:      peerID,
						Context: []byte(id), // Store original string ID
					})
					m.logger.Debug("Added peer to list", "index", i, "peer_id_string", id, "peer_id_uint64", peerID)
				}
			}
		} else {
			m.logger.Debug("Cluster nodes has unexpected type", "type", fmt.Sprintf("%T", clusterNodes))
		}
	} else {
		m.logger.Debug("No cluster nodes found in config")
	}

	// Create Raft consensus
	var err error
	m.raftConsensus, err = NewRaftConsensus(context.Background(), nodeID, m.nodeInfo, peers, &m.cfg.Cluster, m.raftLogDir, m.logger)
	if err != nil {
		return fmt.Errorf("failed to create Raft consensus: %w", err)
	}

	// Load CA certificate for TLS validation between cluster nodes
	var caCertPEM []byte
	if m.cfg.CACertPath != "" {
		var readErr error
		caCertPEM, readErr = os.ReadFile(m.cfg.CACertPath)
		if readErr != nil {
			m.logger.Warn("Failed to read CA cert", "path", m.cfg.CACertPath, "error", readErr)
		}
	}

	// Collect allowed peer CNs for mTLS verification on /raft/message.
	// The local node's own CN is included first so single-node loopback messages
	// are accepted without requiring a second allowlist entry.
	allowedCNs := []string{m.nodeInfo.ID}
	if clusterNodes := m.cfg.Cluster.Discovery.Config["nodes"]; clusterNodes != nil {
		if nodes, ok := clusterNodes.([]interface{}); ok {
			for _, n := range nodes {
				if nodeMap, ok := n.(map[string]interface{}); ok {
					if id, ok := nodeMap["id"].(string); ok && id != m.nodeInfo.ID {
						allowedCNs = append(allowedCNs, id)
					}
				}
			}
		} else if nodes, ok := clusterNodes.([]map[string]interface{}); ok {
			for _, nodeMap := range nodes {
				if id, ok := nodeMap["id"].(string); ok && id != m.nodeInfo.ID {
					allowedCNs = append(allowedCNs, id)
				}
			}
		}
	}

	// Mint a dedicated mTLS client certificate for this node's outbound Raft peer
	// transport. The certificate CN must equal m.nodeInfo.ID so the receiving node's
	// verifyPeerCN check can authenticate the sender against its allowedCNs list.
	// cert.PurposeTransport uses CN "cfgms-internal" (not the node ID), so we generate
	// a dedicated client cert here rather than reusing the transport purpose cert.
	if m.certManager == nil {
		return fmt.Errorf("cluster mode requires a cert manager for mTLS peer authentication: " +
			"pass a non-nil *cert.Manager to NewManager")
	}
	peerCert, err := m.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   m.nodeInfo.ID,
		ValidityDays: 365,
	})
	if err != nil {
		return fmt.Errorf("failed to generate HA peer client certificate: %w", err)
	}

	// Create and attach transport
	transport := newRaftTransport(nodeID, m.nodeInfo.Address, m.raftConsensus, caCertPEM, peerCert.CertificatePEM, peerCert.PrivateKeyPEM, allowedCNs, m.logger)
	// GET /api/v1/raft/status must report is_leader from the same lease-backed
	// HasLeadership() that GET /api/v1/ha/status reports (ADR-029 Decision 7,
	// retained by ADR-031). m.HasLeadership evaluates lazily at call time, so this
	// is safe to wire before SetLeaseStore is ever called.
	transport.setHasLeadershipFn(m.HasLeadership)
	m.raftConsensus.SetTransport(transport)

	// Add peer addresses to transport
	m.logger.Debug("Configuring peer addresses for transport")
	peerCount := 0
	if clusterNodes := m.cfg.Cluster.Discovery.Config["nodes"]; clusterNodes != nil {
		// Try both []interface{} and []map[string]interface{} type assertions
		if nodes, ok := clusterNodes.([]interface{}); ok {
			m.logger.Debug("Processing peer addresses ([]interface{})", "total_nodes", len(nodes))
			for i, n := range nodes {
				if nodeMap, ok := n.(map[string]interface{}); ok {
					if id, ok := nodeMap["id"].(string); ok {
						if addr, ok := nodeMap["address"].(string); ok {
							peerID := hashStringToUint64(id)
							if peerID != nodeID { // Don't add self
								transport.AddPeer(peerID, addr)
								peerCount++
								m.logger.Debug("Added peer address to transport",
									"index", i, "peer_id_string", id, "peer_id_uint64", peerID, "address", addr)
							} else {
								m.logger.Debug("Skipped self in peer list", "node_id", id)
							}
						} else {
							m.logger.Debug("Node missing address", "index", i, "node_id", id)
						}
					}
				}
			}
		} else if nodes, ok := clusterNodes.([]map[string]interface{}); ok {
			m.logger.Debug("Processing peer addresses ([]map)", "total_nodes", len(nodes))
			for i, nodeMap := range nodes {
				if id, ok := nodeMap["id"].(string); ok {
					if addr, ok := nodeMap["address"].(string); ok {
						peerID := hashStringToUint64(id)
						if peerID != nodeID { // Don't add self
							transport.AddPeer(peerID, addr)
							peerCount++
							m.logger.Debug("Added peer address to transport",
								"index", i, "peer_id_string", id, "peer_id_uint64", peerID, "address", addr)
						} else {
							m.logger.Debug("Skipped self in peer list", "node_id", id)
						}
					} else {
						m.logger.Debug("Node missing address", "index", i, "node_id", id)
					}
				}
			}
		}
	}

	m.logger.Debug("Raft consensus initialized",
		"node_id", nodeID, "total_peers", len(peers), "configured_peer_addresses", peerCount)

	return nil
}

// hashStringToUint64 converts a string to a deterministic uint64 using FNV-1a 64-bit.
// FNV-1a has negligible collision probability for the node-count range (3–50 nodes)
// and avoids the aliasing risk of the old polynomial (31-based) hash.
func hashStringToUint64(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// initializeBlueGreenComponents initializes components for blue-green mode.
// Discovery has been removed; blue-green mode requires no additional components.
func (m *Manager) initializeBlueGreenComponents() error {
	return nil
}

// nodeInfoPublishInterval is how long publishNodeInfo waits before re-proposing
// a node_update that has not yet appeared in the applied cluster state.
const nodeInfoPublishInterval = 2 * time.Second

// nodeInfoPublishMaxInterval caps the backoff publishNodeInfo applies while its
// own record has not converged, and nodeInfoPublishWarnAfter is how long it
// stays quiet before saying so.
//
// Convergence is not guaranteed: a node removed from the cluster, or one whose
// node_update never applies, would otherwise re-propose at the base interval for
// the lifetime of the process — steady traffic against a cluster that will never
// accept it, with nothing above Debug to show for it. Backing off bounds the
// cost without abandoning convergence, since a node that becomes able to
// converge later still does.
const (
	nodeInfoPublishMaxInterval = 30 * time.Second
	nodeInfoPublishWarnAfter   = 2 * time.Minute
)

// publishNodeInfo replicates this node's metadata through the Raft log and keeps
// retrying until the entry is observed in the applied state.
//
// ProposeNodeUpdate returning nil means only that the proposal was accepted into
// the raft loop's channel — not that it was committed. etcd/raft drops a
// proposal whenever the leader is unsettled, which is exactly the moment
// leaderElectedC fires, so a single shot lost the only node_update a node ever
// sent. Nothing retried and nothing noticed: ClusterState.Nodes stayed empty for
// the lifetime of the cluster, and because GetLeaderInfo and GetClusterNodes
// both resolve through that map, GET /api/v1/ha/cluster reported no leader and
// no members on a cluster that was electing and replicating perfectly well.
// GET /api/v1/ha/status disagreed, since IsLeader reads the raft state directly.
//
// Membership must converge, so this re-proposes until the node's own record is
// applied, then returns. The interval doubles up to nodeInfoPublishMaxInterval
// so a record that never converges costs a bounded trickle rather than a
// proposal every two seconds forever.
func (m *Manager) publishNodeInfo(rc *RaftConsensus, nodeInfo *NodeInfo) {
	select {
	case <-rc.leaderElectedC:
	case <-m.ctx.Done():
		return
	}

	nodeID := hashStringToUint64(nodeInfo.ID)
	interval := nodeInfoPublishInterval
	started := time.Now()
	warned := false

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		m.logger.Debug("Publishing node metadata to cluster state", "node_id", nodeInfo.ID)
		if err := rc.ProposeNodeUpdate(nodeInfo); err != nil {
			m.logger.Warn("Failed to propose node update; will retry",
				"error", logging.SanitizeLogValue(err.Error()))
		}

		select {
		case <-timer.C:
		case <-m.ctx.Done():
			return
		}

		if rc.HasNode(nodeID) {
			m.logger.Info("Node metadata replicated to cluster state",
				"node_id", nodeInfo.ID, "elapsed", time.Since(started))
			return
		}

		// Surface a stall once. Silence here previously looked identical to
		// success, because only the Debug line above marked an attempt.
		if !warned && time.Since(started) >= nodeInfoPublishWarnAfter {
			m.logger.Error("Node metadata has not reached cluster state; still retrying",
				"node_id", nodeInfo.ID, "elapsed", time.Since(started), "retry_interval", interval)
			warned = true
		}

		if interval < nodeInfoPublishMaxInterval {
			interval *= 2
			if interval > nodeInfoPublishMaxInterval {
				interval = nodeInfoPublishMaxInterval
			}
		}
		timer.Reset(interval)
	}
}

// startClusterMode starts components for cluster mode
func (m *Manager) startClusterMode() error {
	// Start Raft consensus (sole authority for membership and leader election)
	if m.raftConsensus != nil {
		if err := m.raftConsensus.Start(); err != nil {
			return fmt.Errorf("failed to start Raft consensus: %w", err)
		}

		// Replicate local node metadata through the Raft log once a leader exists.
		// Proposals sent before leader election are dropped, so we wait for
		// leaderElectedC (closed by the Raft loop on first leader detection)
		// before calling ProposeNodeUpdate. The goroutine is bounded by m.ctx.
		rc := m.raftConsensus
		nodeInfo := m.nodeInfo
		go m.publishNodeInfo(rc, nodeInfo)

		// Propose add-node ConfChanges for each peer known at startup.
		// These are non-critical (initial membership is bootstrapped via StartNode);
		// failures are logged but do not block cluster startup.
		localNodeID := hashStringToUint64(m.nodeInfo.ID)
		if nodes := m.cfg.Cluster.Discovery.Config["nodes"]; nodes != nil {
			if nodeList, ok := nodes.([]interface{}); ok {
				for _, n := range nodeList {
					nodeMap, ok := n.(map[string]interface{})
					if !ok {
						continue
					}
					id, ok := nodeMap["id"].(string)
					if !ok {
						continue
					}
					peerID := hashStringToUint64(id)
					if peerID == localNodeID {
						continue
					}
					addr, _ := nodeMap["address"].(string)
					peerInfo := &NodeInfo{ID: id, Address: addr}
					if err := m.raftConsensus.ProposeAddNode(peerID, peerInfo); err != nil {
						m.logger.Warn("Failed to propose add-node for peer", "peer_id", peerID, "error", err)
					}
				}
			}
		}
	}

	if m.failover != nil {
		if err := m.failover.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start failover manager: %w", err)
		}
	}

	if m.splitBrain != nil {
		if err := m.splitBrain.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start split-brain detector: %w", err)
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
