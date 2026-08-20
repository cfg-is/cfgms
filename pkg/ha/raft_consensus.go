// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/quorum"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"

	"github.com/cfgis/cfgms/pkg/logging"
)

// RaftConsensus provides Raft-based consensus for HA cluster
type RaftConsensus struct {
	mu       sync.RWMutex
	stopOnce sync.Once
	wg       sync.WaitGroup // tracks the runRaft goroutine; Stop() waits on it

	// Raft core
	node         raft.Node
	storage      *raft.MemoryStorage
	logStore     *RaftLogStore // durable WAL; nil when logDir was empty (tests)
	config       *raft.Config
	tickInterval time.Duration // derived from ClusterConfig.HeartbeatInterval

	// Lease state — monotonic-clock leader authority (ADR-029 Decision 1 & 2).
	// leaseLastAck is the instant at which a quorum of voters had most recently
	// acknowledged this leader. It is derived in refreshLeaseIfQuorum() from
	// peerAcks — real per-peer response timestamps — never from a coarse
	// "recently active" flag. It is written by refreshLeaseIfQuorum() from the
	// single runRaft goroutine and read by HasLeadership() from any goroutine;
	// both paths hold rc.mu (write: Lock, read: RLock).
	// leaseDuration = 0.8 × ClusterConfig.ElectionTimeout (set once at construction).
	leaseLastAck  time.Time
	leaseDuration time.Duration

	// peerAcks records, per peer node ID, the instant this node received that
	// peer's most recent MsgHeartbeatResp/MsgAppResp and the term that response
	// carried. Written by recordPeerAck() from the transport receive path, read
	// by refreshLeaseIfQuorum(); guarded by rc.mu.
	//
	// These are the only evidence of contact the lease accepts. etcd/raft's
	// Progress.RecentActive cannot be used: it is cleared only when
	// MsgCheckQuorum fires, once per ElectionTimeout (raft.go:865-871,
	// 1287-1292), so RecentActive==true means "heard from this peer at some
	// point in the current check-quorum window" — the last real contact may be a
	// full ElectionTimeout in the past. Stamping the lease from it yields an
	// effective authority window of up to 1.8 × ElectionTimeout, which overlaps
	// the successor's election and destroys the ADR-029 Decision 1 bound.
	//
	// Only nodes in the current voter configuration may occupy a slot: see
	// recordPeerAck(), which is fed peer-controlled node IDs off the wire.
	peerAcks map[uint64]peerAck

	// voters is an immutable snapshot of the current Raft voter configuration
	// (Status().Config.Voters.IDs()). It is published by syncVotersLocked() from
	// the runRaft goroutine — on every tick and after every Advance, on every
	// node regardless of role — and read lock-free by recordPeerAck() on the
	// transport receive path.
	//
	// It is atomic rather than rc.mu-guarded so that a message from an unknown
	// node ID is rejected without ever acquiring rc.mu: the receive path runs on
	// peer HTTP requests, and taking the mutex there for traffic that will be
	// discarded hands a peer a lever on the runRaft loop's lock.
	//
	// The pointed-to map is never mutated after Store; each Status() call
	// returns a freshly built map (quorum.JointConfig.IDs).
	voters atomic.Pointer[map[uint64]struct{}]

	// leaseBase is a fixed reference instant, captured once at construction with
	// its monotonic reading intact. Ack instants are expressed as offsets from it
	// so they can be ordered by raft's quorum machinery as uint64 indices and
	// converted back into monotonic time.Time values (base.Add preserves the
	// monotonic reading). No wall-clock arithmetic enters the lease path
	// (ADR-029 Decision 2).
	leaseBase time.Time

	// Node identity
	nodeID   uint64
	nodeInfo *NodeInfo

	// Cluster state (replicated via Raft)
	clusterState *ClusterState
	appliedIndex uint64 // Last applied log index

	// Channels for coordination
	proposeC chan []byte
	// confChangeC carries pointers: raftpb.ConfChange embeds protoimpl.MessageState
	// (sync.Mutex via pragma.DoNotCopy), so the value must never be copied.
	confChangeC chan *raftpb.ConfChange
	errorC      chan error
	stopC       chan struct{}

	// leaderElectedC is closed once the first leader is known; callers that need
	// to propose (which requires a leader) can select on this channel.
	leaderElectedC chan struct{}
	leaderOnce     sync.Once

	// Transport
	transport *raftTransport

	// onBecomeLeader is called (in a goroutine) when this node transitions from
	// non-leader to leader. The second argument is the departed leader's string
	// node ID so the caller can dispatch reconnect commands to orphaned stewards.
	onBecomeLeader func(ctx context.Context, departedNodeID string)

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	logger logging.Logger
}

// ClusterState represents the replicated state machine.
//
// Leader is deliberately not serialized (`json:"-"`). Leadership is local Raft
// protocol state, not replicated state: a snapshot is peer-supplied data, and
// accepting a Leader value out of one would let any node that can produce a
// snapshot name the recipient as leader. Nodes/Sessions are the replicated
// content; leadership is always read from rc.node.Status().
type ClusterState struct {
	mu           sync.RWMutex
	Leader       uint64 `json:"-"`
	Nodes        map[uint64]*NodeInfo
	Sessions     map[string]SessionUpdateCommand
	LastModified time.Time
}

// peerAck is a single observed contact from a peer: the instant its response
// was received (monotonic) and the term that response carried. The term is
// retained so acks from a superseded term are never counted toward the current
// term's lease.
type peerAck struct {
	at   time.Time
	term uint64
}

// RaftCommand represents commands sent through Raft
// Data is deliberately json.RawMessage rather than interface{}.
//
// Decoding into interface{} turns every JSON number into a float64, and
// applyCommand then re-marshalled that value to decode it into the concrete
// command type. Node IDs are uint64 hashes well above 2^53, so the round trip
// silently rounded them: a leader whose Raft ID was 10972337506993669137 was
// stored in ClusterState.Nodes under 10972337506993670000. Every subsequent
// lookup by real node ID missed, so GetLeaderInfo could never resolve the
// leader and HasNode never saw a node it had just applied.
//
// Keeping the payload as raw bytes decodes it exactly once, straight into the
// typed command, with no float64 in the path.
type RaftCommand struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// marshalRaftCommand builds a RaftCommand envelope with its payload encoded
// exactly once.
func marshalRaftCommand(cmdType string, payload interface{}) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s payload: %w", cmdType, err)
	}
	return json.Marshal(RaftCommand{Type: cmdType, Data: data})
}

// NodeUpdateCommand is sent when node info changes
type NodeUpdateCommand struct {
	NodeID   uint64    `json:"node_id"`
	NodeInfo *NodeInfo `json:"node_info"`
}

// SessionUpdateCommand is sent when a steward connects or disconnects
type SessionUpdateCommand struct {
	StewardID string    `json:"steward_id"`
	NodeID    string    `json:"node_id"`
	Connected bool      `json:"connected"`
	Timestamp time.Time `json:"timestamp"`
}

// NewRaftConsensus creates a new Raft consensus instance. clusterCfg provides
// the timing source: tickInterval = HeartbeatInterval, HeartbeatTick = 1, and
// ElectionTick = ElectionTimeout / HeartbeatInterval. ElectionTick must be >= 5.
//
// logDir, when non-empty, is the directory that holds the per-node bbolt WAL
// (raft.db). On first boot the directory is created and StartNode is used.
// On subsequent boots the WAL is replayed into MemoryStorage and RestartNode
// is used so the node rejoins its cluster at the correct log index rather than
// re-bootstrapping. When logDir is empty no WAL is opened (tests only).
func NewRaftConsensus(ctx context.Context, nodeID uint64, nodeInfo *NodeInfo, peers []raft.Peer, clusterCfg *ClusterConfig, logDir string, logger logging.Logger) (*RaftConsensus, error) {
	if clusterCfg == nil {
		return nil, fmt.Errorf("clusterCfg must not be nil")
	}
	if clusterCfg.HeartbeatInterval <= 0 {
		return nil, fmt.Errorf("ClusterConfig.HeartbeatInterval must be positive, got %v", clusterCfg.HeartbeatInterval)
	}
	if clusterCfg.ElectionTimeout <= 0 {
		return nil, fmt.Errorf("ClusterConfig.ElectionTimeout must be positive, got %v", clusterCfg.ElectionTimeout)
	}

	tickInterval := clusterCfg.HeartbeatInterval
	heartbeatTick := 1
	electionTick := int(clusterCfg.ElectionTimeout / clusterCfg.HeartbeatInterval)
	if electionTick < 5*heartbeatTick {
		return nil, fmt.Errorf(
			"ElectionTimeout (%v) must be at least 5× HeartbeatInterval (%v): got ElectionTick=%d, need ≥%d",
			clusterCfg.ElectionTimeout, clusterCfg.HeartbeatInterval, electionTick, 5*heartbeatTick,
		)
	}

	// Open the durable WAL when a log directory is provided.
	var logStore *RaftLogStore
	var recoveredHS *raftpb.HardState
	var recoveredEntries []*raftpb.Entry
	var recoveredSnap *raftpb.Snapshot
	var recoveredApplied uint64

	if logDir != "" {
		var err error
		logStore, err = OpenRaftLogStore(filepath.Join(logDir, "raft.db"))
		if err != nil {
			return nil, fmt.Errorf("open raft log store: %w", err)
		}
		recoveredHS, recoveredEntries, recoveredSnap, recoveredApplied, err = logStore.LoadState()
		if err != nil {
			_ = logStore.Close()
			return nil, fmt.Errorf("load raft log store state: %w", err)
		}
	}

	storage := raft.NewMemoryStorage()

	// Replay persisted state into MemoryStorage before constructing the node.
	// The order matches raft.Storage's contract: snapshot first, then entries.
	// Nil checks are explicit because v3.7.0 changed these from value to pointer
	// types; a nil pointer means "absent" and must not be passed to the helpers.
	if recoveredSnap != nil && !raft.IsEmptySnap(recoveredSnap) {
		if err := storage.ApplySnapshot(recoveredSnap); err != nil {
			_ = logStore.Close()
			return nil, fmt.Errorf("replay snapshot into memory storage: %w", err)
		}
	}
	if len(recoveredEntries) > 0 {
		if err := storage.Append(recoveredEntries); err != nil {
			_ = logStore.Close()
			return nil, fmt.Errorf("replay log entries into memory storage: %w", err)
		}
	}
	if recoveredHS != nil && !raft.IsEmptyHardState(recoveredHS) {
		if err := storage.SetHardState(recoveredHS); err != nil {
			_ = logStore.Close()
			return nil, fmt.Errorf("replay hard state into memory storage: %w", err)
		}
	}

	config := &raft.Config{
		ID:              nodeID,
		ElectionTick:    electionTick,
		HeartbeatTick:   heartbeatTick,
		Storage:         storage,
		MaxSizePerMsg:   4096,
		MaxInflightMsgs: 256,
		CheckQuorum:     true, // Leader steps down if loses quorum
		PreVote:         true, // Prevents election storms
		Logger:          &raftLogger{logger: logger},
		Applied:         recoveredApplied, // avoids re-delivering already-applied entries
	}

	rc := &RaftConsensus{
		nodeID:        nodeID,
		nodeInfo:      nodeInfo,
		storage:       storage,
		logStore:      logStore,
		config:        config,
		tickInterval:  tickInterval,
		leaseDuration: clusterCfg.LeaseDuration(),
		leaseBase:     time.Now(),
		peerAcks:      make(map[uint64]peerAck),
		appliedIndex:  recoveredApplied,
		clusterState: &ClusterState{
			Nodes:    make(map[uint64]*NodeInfo),
			Sessions: make(map[string]SessionUpdateCommand),
		},
		proposeC:       make(chan []byte, 16),
		confChangeC:    make(chan *raftpb.ConfChange, 16),
		errorC:         make(chan error),
		stopC:          make(chan struct{}),
		leaderElectedC: make(chan struct{}),
		logger:         logger,
	}

	rc.ctx, rc.cancel = context.WithCancel(ctx)

	// Restore persisted cluster membership before starting the Raft loop.
	//
	// clusterState.Nodes is built by applyNodeUpdate, which runs only when
	// Raft delivers a committed node_update entry. On restart, config.Applied is
	// set to recoveredApplied to prevent already-applied entries from being
	// redelivered (correct: avoids double-firing side-effecting commands), but
	// this also means historical NodeUpdateCommands for peer nodes are never
	// re-applied — clusterState.Nodes stays empty and GetClusterNodes() returns
	// only the local node until the leader re-replicates every peer's NodeInfo,
	// which never happens automatically. Loading the persisted snapshot here
	// populates clusterState.Nodes immediately on restart so the API endpoints
	// return correct results without waiting for any new log entries.
	if logStore != nil {
		nodesData, err := logStore.LoadClusterNodes()
		if err != nil {
			_ = logStore.Close()
			return nil, fmt.Errorf("load persisted cluster nodes: %w", err)
		}
		if len(nodesData) > 0 {
			var nodes map[uint64]*NodeInfo
			if err := json.Unmarshal(nodesData, &nodes); err != nil {
				// Non-fatal: log and proceed with empty state; membership will
				// reconverge as the leader re-proposes each peer's NodeInfo.
				// The decode error text embeds fragments of the persisted
				// snapshot, which originates from peer NodeInfo replicated
				// through the Raft log — sanitize before logging.
				logger.Warn("Failed to unmarshal persisted cluster nodes; starting with empty membership",
					"error", logging.SanitizeLogValue(err.Error()))
			} else {
				rc.clusterState.Nodes = nodes
				logger.Info("Restored cluster membership from persisted state",
					"node_count", len(nodes))
			}
		}
	}

	// Select StartNode vs RestartNode.
	//
	// The key invariant: StartNode re-bootstraps the log from index 0 by
	// appending one ConfChangeAddNode per peer (3 peers → lastIndex(3)). If
	// the cluster has already advanced (commit(7)), the restarting node panics:
	// "tocommit(7) is out of range [lastIndex(3)]". The fix is to use
	// RestartNode whenever the durable log says we have seen prior state, so
	// we resume at the correct log position regardless of what peers reports.
	//
	// Fallback: when logDir is empty (tests only) we preserve the old
	// len(peers)-based selection so existing tests that pass nil peers do not
	// break — RestartNode is safe for a node with no history to replay.
	hasPersistedState := logStore != nil && logStore.HasData()
	useRestart := hasPersistedState || len(peers) == 0
	if useRestart {
		rc.node = raft.RestartNode(config)
		if hasPersistedState {
			var recoveredTerm, recoveredCommit uint64
			if recoveredHS != nil {
				recoveredTerm = recoveredHS.GetTerm()
				recoveredCommit = recoveredHS.GetCommit()
			}
			logger.Info("Restarted Raft node from persisted log",
				"node_id", nodeID,
				"recovered_term", recoveredTerm,
				"recovered_commit", recoveredCommit,
				"recovered_applied", recoveredApplied,
				"recovered_entries", len(recoveredEntries))
		} else {
			logger.Info("Restarted Raft node", "node_id", nodeID)
		}
	} else {
		rc.node = raft.StartNode(config, peers)
		logger.Info("Started new Raft node", "node_id", nodeID, "peers", peers)
		status := rc.node.Status()
		logger.Debug("Initial status after StartNode",
			"node_id", nodeID, "term", status.Term, "lead", status.Lead, "raft_state", status.RaftState)
	}

	// CRITICAL: Start the Raft processing loop IMMEDIATELY
	// The Ready channel must be consumed or Raft will block
	logger.Debug("Starting Raft processing loop immediately", "node_id", nodeID)
	rc.wg.Add(1)
	go rc.runRaft()

	return rc, nil
}

// SetTransport attaches a transport to the Raft consensus engine.
// Must be called before Start(). Thread-safe.
func (rc *RaftConsensus) SetTransport(t *raftTransport) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.transport = t
}

// Start begins the Raft consensus engine
func (rc *RaftConsensus) Start() error {
	rc.logger.Info("Starting Raft consensus engine", "node_id", rc.nodeID)

	// Note: runRaft() goroutine is already started in NewRaftConsensus()
	// to ensure Ready channel is consumed immediately

	// Start transport layer (read under lock to avoid race with SetTransport)
	rc.mu.RLock()
	transport := rc.transport
	rc.mu.RUnlock()
	if transport != nil {
		if err := transport.Start(rc.ctx); err != nil {
			return fmt.Errorf("failed to start Raft transport: %w", err)
		}
	}

	// Don't propose node update here - it would block since the Raft loop
	// might be waiting for ticker. The node is already added via ConfChange
	// during initialization.

	return nil
}

// Stop gracefully stops the Raft consensus engine. Safe to call multiple times.
// Blocks until the runRaft goroutine has exited so callers can safely inspect
// internal channels (e.g. proposeC) once Stop returns.
func (rc *RaftConsensus) Stop() error {
	rc.stopOnce.Do(func() {
		rc.logger.Info("Stopping Raft consensus engine", "node_id", rc.nodeID)
		close(rc.stopC)
		rc.cancel()
		rc.mu.RLock()
		t := rc.transport
		rc.mu.RUnlock()
		if t != nil {
			t.Stop()
		}
		rc.node.Stop()
	})
	rc.wg.Wait() // all callers block until runRaft has exited
	if rc.logStore != nil {
		if err := rc.logStore.Close(); err != nil {
			rc.logger.Warn("Failed to close raft log store", "node_id", rc.nodeID, "error", err)
		}
	}
	return nil
}

// runRaft is the main Raft processing loop
func (rc *RaftConsensus) runRaft() {
	defer rc.wg.Done()

	ticker := time.NewTicker(rc.tickInterval)
	defer ticker.Stop()

	rc.logger.Debug("Raft loop started", "node_id", rc.nodeID)

	for {
		select {
		case <-ticker.C:
			rc.node.Tick()
			// Re-evaluate the lease on every tick: acks are recorded on the
			// transport receive path, so waiting for a Ready batch would delay
			// both the grant and — for a single-node cluster, which produces no
			// peer traffic at all — every refresh.
			rc.refreshLeaseIfQuorum()

		case rd := <-rc.node.Ready():
			// Process Ready updates from Raft
			rc.logger.Debug("Processing Ready",
				"node_id", rc.nodeID, "entries", len(rd.Entries), "messages", len(rd.Messages), "has_snapshot", rd.Snapshot != nil && !raft.IsEmptySnap(rd.Snapshot))
			rc.processReady(rd)

		case prop := <-rc.proposeC:
			// Spawn a goroutine so the raft event loop continues ticking while
			// the proposal waits for a leader. etcd/raft's n.propc is unbuffered
			// and n.run() nil-gates it when no leader is known, so calling
			// Propose directly here would deadlock the election timer.
			// Track in rc.wg so Stop() does not return until the goroutine exits.
			rc.wg.Add(1)
			go func(p []byte) {
				defer rc.wg.Done()
				rc.logger.Debug("Proposing to Raft", "node_id", rc.nodeID, "bytes", len(p))
				if err := rc.node.Propose(rc.ctx, p); err != nil {
					rc.logger.Error("Failed to propose to Raft", "error", err)
					return
				}
				rc.logger.Debug("Proposal accepted by Raft", "node_id", rc.nodeID)
			}(prop)

		case cc := <-rc.confChangeC:
			// Same reasoning as proposeC: ProposeConfChange blocks on the
			// unbuffered n.propc when no leader exists. Run it off the
			// raft loop so ticks continue to fire.
			// Track in rc.wg so Stop() does not return until the goroutine exits.
			rc.wg.Add(1)
			go func(c *raftpb.ConfChange) {
				defer rc.wg.Done()
				// c satisfies raftpb.ConfChangeI: AsV1 has a pointer receiver in v3.7.0.
				if err := rc.node.ProposeConfChange(rc.ctx, c); err != nil {
					rc.logger.Error("Failed to propose conf change", "error", err)
				}
			}(cc)

		case <-rc.stopC:
			rc.logger.Debug("Raft loop stopping", "node_id", rc.nodeID)
			return

		case <-rc.ctx.Done():
			rc.logger.Debug("Raft loop context cancelled", "node_id", rc.nodeID)
			return
		}
	}
}

// processReady handles a Ready struct from Raft.
//
// Ordering is load-bearing: durable write → send messages → apply → advance.
// The durable write must precede outbound messages so that if the process
// crashes after the send but before the next boot, peers can reconstruct the
// correct log position from the persisted state (Raft's safety requirement).
func (rc *RaftConsensus) processReady(rd raft.Ready) {
	// 1. Update in-memory storage.
	// Nil checks are explicit: v3.7.0 changed Snapshot and HardState from value
	// types to pointer types in raft.Ready; nil means "absent" for this batch.
	if rd.Snapshot != nil && !raft.IsEmptySnap(rd.Snapshot) {
		rc.logger.Debug("Applying snapshot", "node_id", rc.nodeID)
		if err := rc.storage.ApplySnapshot(rd.Snapshot); err != nil {
			rc.logger.Error("Failed to apply snapshot to memory storage", "node_id", rc.nodeID, "error", err)
		}
		rc.publishSnapshot(rd.Snapshot)
	}

	if len(rd.Entries) > 0 {
		rc.logger.Debug("Appending entries to storage", "count", len(rd.Entries), "node_id", rc.nodeID)
		if err := rc.storage.Append(rd.Entries); err != nil {
			rc.logger.Error("Failed to append entries to memory storage", "node_id", rc.nodeID, "error", err)
		}
	}

	// hs is bound locally: raft.Ready embeds *pb.HardState in v3.7.0, so reading
	// through rd.HardState.X would select through the embedded field.
	if hs := rd.HardState; hs != nil && !raft.IsEmptyHardState(hs) {
		rc.logger.Debug("Setting HardState",
			"node_id", rc.nodeID, "term", hs.GetTerm(), "vote", hs.GetVote(), "commit", hs.GetCommit())
		if err := rc.storage.SetHardState(hs); err != nil {
			rc.logger.Error("Failed to set hard state in memory storage", "node_id", rc.nodeID, "error", err)
		}
	}

	// 2. Persist to durable WAL BEFORE sending messages.
	// Raft's durability contract requires entries and HardState to be on stable
	// storage before the associated messages reach any peer. A crash after this
	// point is safe: peers may or may not have seen the messages, but the next
	// boot will replay the persisted state and converge correctly. A crash
	// before this point is also safe: the messages have not been sent yet.
	//
	// Persistence failure violates the safety property — a node that continues
	// after a failed WAL write can silently lose committed entries. Panic so the
	// operator gets an explicit signal rather than a later, harder-to-diagnose
	// inconsistency.
	if rc.logStore != nil {
		rc.mu.RLock()
		applied := rc.appliedIndex
		rc.mu.RUnlock()
		if err := rc.logStore.SaveBatch(rd.HardState, rd.Entries, rd.Snapshot, applied); err != nil {
			panic(fmt.Sprintf("raft log store write failed (node %d): %v — "+
				"continuing would violate Raft's durability contract", rc.nodeID, err))
		}
	}

	// 3. Send messages to peers (after durable write).
	rc.mu.RLock()
	transport := rc.transport
	rc.mu.RUnlock()
	if transport != nil && len(rd.Messages) > 0 {
		rc.logger.Debug("Sending messages to peers", "count", len(rd.Messages), "node_id", rc.nodeID)
		transport.Send(rd.Messages)
	}

	// 4. Apply committed entries to state machine.
	if len(rd.CommittedEntries) > 0 {
		rc.logger.Debug("Applying committed entries", "count", len(rd.CommittedEntries), "node_id", rc.nodeID)
		rc.publishEntries(rc.entriesToApply(rd.CommittedEntries))

		// Persist the updated applied index so restart knows how far the state
		// machine has advanced. The entries are already durable from step 2; this
		// write updates only the applied-index key (monotonic — no-op if unchanged).
		if rc.logStore != nil {
			rc.mu.RLock()
			applied := rc.appliedIndex
			rc.mu.RUnlock()
			if err := rc.logStore.SaveBatch(nil, nil, nil, applied); err != nil {
				panic(fmt.Sprintf("raft log store applied-index write failed (node %d): %v — "+
					"continuing would violate Raft's durability contract", rc.nodeID, err))
			}
			// Persist cluster membership so a restarted node can read back peer
			// NodeInfo without replaying entries that config.Applied blocked.
			rc.persistClusterState()
		}
	}

	// 5. Update leadership.
	if rd.SoftState != nil {
		softState := rd.SoftState
		rc.logger.Debug("Updating leadership",
			"node_id", rc.nodeID, "lead", softState.Lead, "raft_state", softState.RaftState)
		rc.updateLeadership(softState)
	}

	// 6. Advance the Raft state machine.
	rc.node.Advance()

	// 7. Refresh leader lease if this node has quorum acks.
	// Called after Advance() so Status().Progress reflects the latest peer activity.
	rc.refreshLeaseIfQuorum()
}

// entriesToApply filters out entries that have already been applied
func (rc *RaftConsensus) entriesToApply(entries []*raftpb.Entry) []*raftpb.Entry {
	if len(entries) == 0 {
		return nil
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Get the index of the last applied entry from our tracking
	firstIdx := entries[0].GetIndex()
	lastIdx := entries[len(entries)-1].GetIndex()

	rc.logger.Debug("entriesToApply check",
		"node_id", rc.nodeID, "firstIdx", firstIdx, "lastIdx", lastIdx, "appliedIndex", rc.appliedIndex)

	// If we've already applied all these entries, skip them
	if lastIdx <= rc.appliedIndex {
		rc.logger.Debug("All entries already applied", "node_id", rc.nodeID)
		return nil
	}

	// Calculate which entries haven't been applied yet
	offset := uint64(0)
	if firstIdx <= rc.appliedIndex {
		// Some entries at the beginning have already been applied
		offset = rc.appliedIndex + 1 - firstIdx
		rc.logger.Debug("Skipping already-applied entries", "count", offset, "node_id", rc.nodeID)
	}

	if offset >= uint64(len(entries)) {
		// All entries have been applied
		return nil
	}

	return entries[offset:]
}

// publishEntries applies committed entries to the state machine
func (rc *RaftConsensus) publishEntries(entries []*raftpb.Entry) {
	for _, entry := range entries {
		switch entry.GetType() {
		case raftpb.EntryNormal:
			if len(entry.Data) == 0 {
				// Ignore empty entries (leader election)
				break
			}

			// Apply command to state machine
			if err := rc.applyCommand(entry.Data); err != nil {
				rc.logger.Error("Failed to apply command", "error", err)
			}

		case raftpb.EntryConfChange:
			var cc raftpb.ConfChange
			if err := proto.Unmarshal(entry.GetData(), &cc); err != nil {
				rc.logger.Error("Failed to unmarshal conf change", "error", err)
				continue
			}

			// &cc satisfies raftpb.ConfChangeI: AsV1 has a pointer receiver in v3.7.0.
			rc.node.ApplyConfChange(&cc)

			switch cc.GetType() {
			case raftpb.ConfChangeAddNode:
				rc.logger.Info("Added node to cluster", "node_id", cc.GetNodeId())
			case raftpb.ConfChangeRemoveNode:
				rc.logger.Info("Removed node from cluster", "node_id", cc.GetNodeId())
				rc.clusterState.mu.Lock()
				delete(rc.clusterState.Nodes, cc.GetNodeId())
				rc.clusterState.mu.Unlock()
			}
		}

		// Update applied index after processing each entry
		rc.mu.Lock()
		if entry.GetIndex() > rc.appliedIndex {
			rc.appliedIndex = entry.GetIndex()
			rc.logger.Debug("Updated appliedIndex", "applied_index", rc.appliedIndex, "node_id", rc.nodeID)
		}
		rc.mu.Unlock()
	}
}

// applyCommand applies a command to the cluster state machine
func (rc *RaftConsensus) applyCommand(data []byte) error {
	var cmd RaftCommand
	if err := json.Unmarshal(data, &cmd); err != nil {
		return fmt.Errorf("failed to unmarshal command: %w", err)
	}

	switch cmd.Type {
	case "node_update":
		return rc.applyNodeUpdate(cmd.Data)
	case "session_update":
		return rc.applySessionUpdate(cmd.Data)
	default:
		return fmt.Errorf("unknown command type: %s", cmd.Type)
	}
}

// applyNodeUpdate updates node information in cluster state
func (rc *RaftConsensus) applyNodeUpdate(data json.RawMessage) error {
	var update NodeUpdateCommand
	if err := json.Unmarshal(data, &update); err != nil {
		return err
	}

	rc.clusterState.mu.Lock()
	rc.clusterState.Nodes[update.NodeID] = update.NodeInfo
	rc.clusterState.LastModified = time.Now()
	rc.clusterState.mu.Unlock()

	rc.logger.Debug("Applied node update", "node_id", update.NodeID, "node_info", update.NodeInfo)

	return nil
}

// applySessionUpdate updates session state in the cluster state machine
func (rc *RaftConsensus) applySessionUpdate(data json.RawMessage) error {
	var update SessionUpdateCommand
	if err := json.Unmarshal(data, &update); err != nil {
		return err
	}

	rc.clusterState.mu.Lock()
	if update.Connected {
		rc.clusterState.Sessions[update.StewardID] = update
	} else {
		delete(rc.clusterState.Sessions, update.StewardID)
	}
	rc.clusterState.LastModified = time.Now()
	rc.clusterState.mu.Unlock()

	rc.logger.Debug("Applied session update",
		"steward_id", logging.SanitizeLogValue(update.StewardID),
		"node_id", logging.SanitizeLogValue(update.NodeID),
		"connected", update.Connected)

	return nil
}

// ProposeSessionUpdate replicates a steward connect/disconnect event through the Raft log.
// It is non-blocking: if proposeC is at capacity it returns an error immediately.
func (rc *RaftConsensus) ProposeSessionUpdate(stewardID, nodeID string, connected bool) error {
	data, err := marshalRaftCommand("session_update", SessionUpdateCommand{
		StewardID: stewardID,
		NodeID:    nodeID,
		Connected: connected,
		Timestamp: time.Now(),
	})
	if err != nil {
		return err
	}
	select {
	case rc.proposeC <- data:
		return nil
	default:
		return fmt.Errorf("propose channel full, cannot enqueue session update")
	}
}

// persistClusterState saves the current cluster membership to the durable store
// so a restarting node can restore peer NodeInfo without replaying log entries.
// Errors are logged but not propagated — a failed write means the next restart
// will have stale state and must re-converge via normal Raft replication.
func (rc *RaftConsensus) persistClusterState() {
	if rc.logStore == nil {
		return
	}
	rc.clusterState.mu.RLock()
	nodes := make(map[uint64]*NodeInfo, len(rc.clusterState.Nodes))
	for k, v := range rc.clusterState.Nodes {
		nodes[k] = v
	}
	rc.clusterState.mu.RUnlock()

	data, err := json.Marshal(nodes)
	if err != nil {
		rc.logger.Error("Failed to marshal cluster nodes for persistence",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if err := rc.logStore.SaveClusterNodes(data); err != nil {
		// The store error carries the raft.db filesystem path and any
		// underlying decode/encode text — sanitize before logging.
		rc.logger.Error("Failed to persist cluster nodes",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// publishSnapshot applies a snapshot to the state machine
func (rc *RaftConsensus) publishSnapshot(snapshot *raftpb.Snapshot) {
	if snapshot == nil || raft.IsEmptySnap(snapshot) {
		return
	}

	rc.logger.Debug("Publishing snapshot", "index", snapshot.Metadata.Index)

	var state ClusterState
	if err := json.Unmarshal(snapshot.Data, &state); err != nil {
		// The decode error text embeds fragments of peer-supplied snapshot bytes.
		rc.logger.Error("Failed to unmarshal snapshot",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}

	// Copy the replicated fields into the existing ClusterState rather than
	// swapping the pointer. Two reasons:
	//
	//  1. Leadership must not come from a snapshot. Snapshot bytes arrive from a
	//     peer; installing them wholesale set clusterState.Leader from that data,
	//     so a follower that applied a snapshot naming it leader reported itself
	//     leader. Leader is `json:"-"` and is left untouched here — it is owned by
	//     updateLeadership() and, for every authority decision, read from
	//     rc.node.Status() instead.
	//  2. Swapping the pointer also swapped the embedded mutex: the old state's
	//     lock was taken and the new state's (never-locked) mutex was unlocked.
	if state.Nodes == nil {
		state.Nodes = make(map[uint64]*NodeInfo)
	}
	if state.Sessions == nil {
		state.Sessions = make(map[string]SessionUpdateCommand)
	}
	rc.clusterState.mu.Lock()
	rc.clusterState.Nodes = state.Nodes
	rc.clusterState.Sessions = state.Sessions
	rc.clusterState.LastModified = state.LastModified
	rc.clusterState.mu.Unlock()
}

// updateLeadership handles leadership changes
func (rc *RaftConsensus) updateLeadership(ss *raft.SoftState) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	wasLeader := rc.clusterState.Leader == rc.nodeID
	isLeader := ss.Lead == rc.nodeID && ss.RaftState == raft.StateLeader

	if !wasLeader && isLeader {
		rc.logger.Info("Node became LEADER", "node_id", rc.nodeID, "term", rc.node.Status().Term)

		// Capture departed leader's string ID before overwriting clusterState.Leader.
		departedUint := rc.clusterState.Leader
		var departedNodeID string
		rc.clusterState.mu.RLock()
		if nodeInfo, ok := rc.clusterState.Nodes[departedUint]; ok {
			departedNodeID = nodeInfo.ID
		}
		rc.clusterState.mu.RUnlock()

		rc.clusterState.Leader = rc.nodeID

		if rc.onBecomeLeader != nil {
			cb := rc.onBecomeLeader
			ctx := rc.ctx
			go cb(ctx, departedNodeID)
		}
	} else if wasLeader && !isLeader {
		rc.logger.Info("Node lost LEADER status", "node_id", rc.nodeID, "new_leader", ss.Lead)
		rc.clusterState.Leader = ss.Lead
	}

	if ss.Lead != raft.None {
		rc.clusterState.Leader = ss.Lead
		rc.leaderOnce.Do(func() { close(rc.leaderElectedC) })
	}
}

// GetSessionsForNode returns steward IDs from ClusterState.Sessions whose
// NodeID matches the given node ID string. Used by the HA leader to identify
// stewards orphaned by a departed controller node.
func (rc *RaftConsensus) GetSessionsForNode(nodeID string) []string {
	rc.clusterState.mu.RLock()
	defer rc.clusterState.mu.RUnlock()

	var stewardIDs []string
	for stewardID, session := range rc.clusterState.Sessions {
		if session.NodeID == nodeID && session.Connected {
			stewardIDs = append(stewardIDs, stewardID)
		}
	}
	return stewardIDs
}

// IsLeader returns true if this node is the leader.
// Deprecated: use IsRaftLeader() for protocol state or HasLeadership() for authority.
// Retained for callers not yet migrated to the split API (#3389).
func (rc *RaftConsensus) IsLeader() bool {
	return rc.IsRaftLeader()
}

// IsRaftLeader returns the raw Raft replication-protocol leader state, read from
// the Raft state machine itself (Status().RaftState), not from the replicated
// ClusterState.Leader field. ClusterState is state-machine content that arrives
// from peers via snapshots; only rc.node knows whether this node is the leader.
//
// Even so, this value can lag reality during a network partition — the local
// Raft node has not yet noticed it was deposed (see ADR-029). Use
// HasLeadership() when deciding whether to act on authority.
func (rc *RaftConsensus) IsRaftLeader() bool {
	return rc.node.Status().RaftState == raft.StateLeader
}

// HasLeadership returns true only when this node is the Raft leader AND its
// leader lease has not expired. The lease duration is 0.8 × ElectionTimeout
// (ADR-029 Decision 1), measured on a monotonic clock — no wall-clock arithmetic.
//
// A zero leaseLastAck (no quorum ack yet observed) is treated as expired.
// This is the admission primitive for every side-effecting path.
//
// Leadership is read from rc.node.Status(), the authoritative Raft state, and is
// re-checked here rather than trusted from whatever set the lease: the lease
// alone would keep returning true for up to leaseDuration after a step-down.
func (rc *RaftConsensus) HasLeadership() bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	if rc.node.Status().RaftState != raft.StateLeader {
		return false
	}
	if rc.leaseLastAck.IsZero() {
		return false
	}
	return time.Since(rc.leaseLastAck) < rc.leaseDuration
}

// GetTerm returns the current Raft term. Mirrors GetLeader() — a thin read of
// rc.node.Status().GetTerm() under the same locking convention. The term is the
// fencing-token source required by ADR-029 Decision 5 (#3390 wires it).
//
// GetTerm() calls the generated nil-safe accessor (not .Term directly): raft
// v3.7.0 migrated HardState to protobuf-v2 which made Term a *uint64; calling
// .Term where uint64 is expected does not compile. See raft_transport.go:294.
func (rc *RaftConsensus) GetTerm() uint64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.node.Status().GetTerm()
}

// recordPeerAck timestamps a follower response as evidence of contact with that
// peer. Only MsgHeartbeatResp and MsgAppResp qualify: both are sent by a
// follower that has accepted this node as leader for the term they carry, so
// their arrival instant is a real, instantaneous ack — unlike
// Progress.RecentActive, which is a coarse per-ElectionTimeout flag.
//
// The message is recorded before it is stepped into raft; a message that raft
// then discards as stale is filtered at lease time by its term, which must
// equal the leader's current term.
//
// m.GetFrom() is peer-controlled input read straight off the wire, and Process()
// records the ack *before* node.Step gets a chance to reject the message, so the
// node ID is checked against the published voter set before it is allowed to
// occupy a map slot. Without that check an authenticated peer could flood
// synthetic From IDs and grow peerAcks without bound (CWE-770). Only voters are
// ever consulted by voterAckIndex, so a non-voter's ack has no use to drop.
//
// Fails closed: until the runRaft goroutine has published a voter set, no ack is
// recorded. That window is bounded by one tick, and a node whose configuration
// raft has not yet loaded cannot be a leader holding a lease anyway.
func (rc *RaftConsensus) recordPeerAck(m *raftpb.Message) {
	switch m.GetType() {
	case raftpb.MsgHeartbeatResp, raftpb.MsgAppResp:
	default:
		return
	}
	from := m.GetFrom()
	if from == raft.None || from == rc.nodeID {
		return
	}
	voters := rc.voters.Load()
	if voters == nil {
		return
	}
	if _, ok := (*voters)[from]; !ok {
		return
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.peerAcks[from] = peerAck{at: time.Now(), term: m.GetTerm()}
}

// syncVotersLocked publishes the current voter configuration for the receive
// path and drops any recorded ack from a node that is no longer a voter, so
// peerAcks is bounded by the size of the voter set at all times.
//
// It runs on every node regardless of role. Pruning used to sit behind
// refreshLeaseIfQuorum's StateLeader early return, which meant a follower — the
// state a node spends most of its life in — never pruned at all.
//
// voters must be a map the caller does not retain or mutate (Status() returns a
// fresh one per call); it is published by pointer and read without a lock.
// Caller must hold rc.mu.
func (rc *RaftConsensus) syncVotersLocked(voters map[uint64]struct{}) {
	rc.voters.Store(&voters)
	for id := range rc.peerAcks {
		if _, ok := voters[id]; !ok {
			delete(rc.peerAcks, id)
		}
	}
}

// voterAckIndex adapts recorded ack instants to raft's quorum machinery.
//
// Each voter's "index" is its last ack expressed as nanoseconds since base,
// plus one — the +1 reserves 0 for "never acked", which is also the value
// MajorityConfig.CommittedIndex assigns to voters that have not reported in.
// Feeding these into Config.Voters.CommittedIndex therefore returns the newest
// instant that a quorum of voters has acked at or after (the k-th newest ack,
// k = quorum size), computed by raft's own tested quorum code so that joint
// configurations mid-conf-change are handled correctly rather than re-derived.
type voterAckIndex struct {
	self   uint64
	selfAt time.Time
	base   time.Time
	acks   map[uint64]peerAck
	term   uint64
}

// AckedIndex implements quorum.AckedIndexer.
func (v *voterAckIndex) AckedIndex(voterID uint64) (quorum.Index, bool) {
	if voterID == v.self {
		// A leader is trivially in contact with itself, right now.
		return v.index(v.selfAt), true
	}
	a, ok := v.acks[voterID]
	if !ok || a.term != v.term {
		// Never heard from, or last heard from in a superseded term: not
		// evidence of contact under the current term. Fail closed.
		return 0, false
	}
	return v.index(a.at), true
}

func (v *voterAckIndex) index(t time.Time) quorum.Index {
	d := t.Sub(v.base)
	if d < 0 {
		d = 0
	}
	return quorum.Index(d) + 1
}

// refreshLeaseIfQuorum advances leaseLastAck to the instant at which a quorum of
// voters had most recently acknowledged this leader (ADR-029 Decision 1).
//
// Leadership is taken from rc.node.Status() — the Raft state machine itself —
// and never from clusterState.Leader, which is state-machine content a peer
// snapshot can set. Three conditions must all hold, and each fails closed:
//
//   - Status().RaftState == StateLeader.
//   - Self present in Status().Progress. Progress is populated only on the
//     leader and a leader always has its own entry (raft.go:949-951); a node
//     whose self-Progress is absent is not promotable (raft.go:1946-1949) and
//     cannot legitimately be leader. An empty Progress map is therefore never a
//     single-node leader — it is a node that is not leading — so it yields no
//     lease.
//   - Self present in the current voter configuration. A leader removed from the
//     configuration is in no quorum.
//
// The lease instant itself is the k-th newest real ack across voters (k = quorum
// size), not time.Now(): stamping "now" whenever a coarse RecentActive flag was
// set stretched the effective authority window to ~1.8 × ElectionTimeout,
// because RecentActive is only cleared once per check-quorum window. Deriving it
// from the acks themselves keeps the window at leaseDuration measured from real
// contact, preserving the 0.2 × ElectionTimeout margin (config.go LeaseDuration).
//
// leaseLastAck only ever moves forward: a quorum contact that happened does not
// stop having happened, and a voter set that grows (conf change) must not
// retroactively invalidate authority already granted.
//
// Before any of that it publishes the voter set and prunes acks from nodes that
// are no longer voters (syncVotersLocked). That housekeeping is role
// independent and deliberately sits ahead of the StateLeader return: it is what
// bounds peerAcks, and a follower never reaches the leader path.
//
// Called from the runRaft goroutine on every tick and after every Advance().
func (rc *RaftConsensus) refreshLeaseIfQuorum() {
	// One critical section for the leadership determination and the write.
	// Splitting them let a node that lost leadership in between still refresh
	// its lease. rc.node.Status() is a channel round-trip into raft's own run
	// loop, which never calls back into RaftConsensus, so holding rc.mu across
	// it cannot deadlock.
	rc.mu.Lock()
	defer rc.mu.Unlock()

	status := rc.node.Status()

	// Publish the voter set and prune non-voter acks first, unconditionally:
	// this is the only bound on peerAcks, and a follower must apply it too.
	voters := status.Config.Voters.IDs()
	rc.syncVotersLocked(voters)

	if status.RaftState != raft.StateLeader {
		return
	}
	if _, ok := status.Progress[rc.nodeID]; !ok {
		return
	}
	if _, ok := voters[rc.nodeID]; !ok {
		return
	}

	idx := status.Config.Voters.CommittedIndex(&voterAckIndex{
		self:   rc.nodeID,
		selfAt: time.Now(),
		base:   rc.leaseBase,
		acks:   rc.peerAcks,
		term:   status.GetTerm(),
	})
	if idx == 0 {
		// Fewer than a quorum of voters have acked in the current term. Leave
		// leaseLastAck where it is: the existing lease ages out on its own.
		return
	}

	// Decode the quorum index back into a monotonic instant. offset is the
	// nanosecond distance from leaseBase that voterAckIndex encoded, so it is
	// bounded by the process uptime; the check makes that explicit and fails
	// closed rather than wrapping into a negative duration if it ever were not.
	offset := uint64(idx) - 1
	if offset > math.MaxInt64 {
		return
	}
	ackAt := rc.leaseBase.Add(time.Duration(offset)) // #nosec G115 -- bounded by the check above
	if ackAt.After(rc.leaseLastAck) {
		rc.leaseLastAck = ackAt
	}
}

// GetLeader returns the current leader node ID
func (rc *RaftConsensus) GetLeader() uint64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.clusterState.Leader
}

// GetLeaderInfo returns the leader's NodeInfo
func (rc *RaftConsensus) GetLeaderInfo() (*NodeInfo, error) {
	rc.mu.RLock()
	leaderID := rc.clusterState.Leader
	rc.mu.RUnlock()

	if leaderID == raft.None {
		return nil, fmt.Errorf("no leader elected")
	}

	rc.clusterState.mu.RLock()
	defer rc.clusterState.mu.RUnlock()

	info, ok := rc.clusterState.Nodes[leaderID]
	if !ok {
		return nil, fmt.Errorf("leader node info not found")
	}

	return info, nil
}

// HasNode reports whether the applied cluster state contains the given node.
// Used to confirm a node_update proposal actually committed, since a successful
// ProposeNodeUpdate only means the proposal was accepted for delivery.
func (rc *RaftConsensus) HasNode(nodeID uint64) bool {
	rc.clusterState.mu.RLock()
	defer rc.clusterState.mu.RUnlock()
	_, ok := rc.clusterState.Nodes[nodeID]
	return ok
}

// GetClusterNodes returns all nodes in the cluster
func (rc *RaftConsensus) GetClusterNodes() []*NodeInfo {
	rc.clusterState.mu.RLock()
	defer rc.clusterState.mu.RUnlock()

	nodes := make([]*NodeInfo, 0, len(rc.clusterState.Nodes))
	for _, node := range rc.clusterState.Nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

// ProposeNodeUpdate replicates updated NodeInfo for this node through the Raft log.
// It is non-blocking: if proposeC is at capacity it returns an error immediately.
func (rc *RaftConsensus) ProposeNodeUpdate(nodeInfo *NodeInfo) error {
	data, err := marshalRaftCommand("node_update", NodeUpdateCommand{
		NodeID:   rc.nodeID,
		NodeInfo: nodeInfo,
	})
	if err != nil {
		return err
	}
	select {
	case rc.proposeC <- data:
		return nil
	default:
		return fmt.Errorf("propose channel full, cannot enqueue node update")
	}
}

// ProposeAddNode proposes a ConfChangeAddNode for the given node.
// It is non-blocking: if confChangeC is at capacity it returns an error immediately.
func (rc *RaftConsensus) ProposeAddNode(nodeID uint64, nodeInfo *NodeInfo) error {
	contextData, err := json.Marshal(nodeInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal node info for add-node conf change: %w", err)
	}
	// v3.7.0: Type is *ConfChangeType (use .Enum()), NodeId is *uint64 (use new()).
	cc := &raftpb.ConfChange{
		Type:    raftpb.ConfChangeAddNode.Enum(),
		NodeId:  new(nodeID),
		Context: contextData,
	}
	select {
	case rc.confChangeC <- cc:
		return nil
	default:
		return fmt.Errorf("conf change channel full, cannot enqueue add-node for %d", nodeID)
	}
}

// ProposeRemoveNode proposes a ConfChangeRemoveNode for the given node.
// It is non-blocking: if confChangeC is at capacity it returns an error immediately.
func (rc *RaftConsensus) ProposeRemoveNode(nodeID uint64) error {
	// v3.7.0: Type is *ConfChangeType (use .Enum()), NodeId is *uint64 (use new()).
	cc := &raftpb.ConfChange{
		Type:   raftpb.ConfChangeRemoveNode.Enum(),
		NodeId: new(nodeID),
	}
	select {
	case rc.confChangeC <- cc:
		return nil
	default:
		return fmt.Errorf("conf change channel full, cannot enqueue remove-node for %d", nodeID)
	}
}

// Process receives and processes Raft messages from peers.
// m is a pointer: raftpb.Message embeds protoimpl.MessageState (sync.Mutex via
// pragma.DoNotCopy) in v3.7.0, so copying the value is unsound, and node.Step
// takes *raftpb.Message anyway.
func (rc *RaftConsensus) Process(ctx context.Context, m *raftpb.Message) error {
	if m == nil {
		return fmt.Errorf("cannot process nil raft message")
	}
	// Timestamp follower responses before stepping: this is the only place a
	// peer's liveness is observed, and it is what the leader lease is built from.
	rc.recordPeerAck(m)
	return rc.node.Step(ctx, m)
}

// raftLogger adapts our logger to Raft's logger interface
type raftLogger struct {
	logger logging.Logger
}

func (l *raftLogger) Debug(v ...interface{}) {
	l.logger.Debug(fmt.Sprint(v...))
}

func (l *raftLogger) Debugf(format string, v ...interface{}) {
	l.logger.Debug(fmt.Sprintf(format, v...))
}

func (l *raftLogger) Error(v ...interface{}) {
	l.logger.Error(fmt.Sprint(v...))
}

func (l *raftLogger) Errorf(format string, v ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, v...))
}

func (l *raftLogger) Info(v ...interface{}) {
	l.logger.Info(fmt.Sprint(v...))
}

func (l *raftLogger) Infof(format string, v ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, v...))
}

func (l *raftLogger) Warning(v ...interface{}) {
	l.logger.Warn(fmt.Sprint(v...))
}

func (l *raftLogger) Warningf(format string, v ...interface{}) {
	l.logger.Warn(fmt.Sprintf(format, v...))
}

func (l *raftLogger) Fatal(v ...interface{}) {
	l.logger.Error(fmt.Sprint(v...))
	panic(fmt.Sprint(v...))
}

func (l *raftLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, v...))
	panic(fmt.Sprintf(format, v...))
}

func (l *raftLogger) Panic(v ...interface{}) {
	l.logger.Error(fmt.Sprint(v...))
	panic(fmt.Sprint(v...))
}

func (l *raftLogger) Panicf(format string, v ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, v...))
	panic(fmt.Sprintf(format, v...))
}
