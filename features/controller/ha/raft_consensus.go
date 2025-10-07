package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"

	"github.com/cfgis/cfgms/pkg/logging"
)

// RaftConsensus provides Raft-based consensus for HA cluster
type RaftConsensus struct {
	mu sync.RWMutex

	// Raft core
	node    raft.Node
	storage *raft.MemoryStorage
	config  *raft.Config

	// Node identity
	nodeID   uint64
	nodeInfo *NodeInfo

	// Cluster state (replicated via Raft)
	clusterState *ClusterState
	appliedIndex uint64 // Last applied log index

	// Channels for coordination
	proposeC    chan []byte
	confChangeC chan raftpb.ConfChange
	commitC     chan *commit
	errorC      chan error
	stopC       chan struct{}

	// Transport
	transport *raftTransport

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	logger logging.Logger
}

// ClusterState represents the replicated state machine
type ClusterState struct {
	mu           sync.RWMutex
	Leader       uint64
	Nodes        map[uint64]*NodeInfo
	LastModified time.Time
}

// commit represents a committed log entry
type commit struct {
	data  [][]byte //nolint:unused // Reserved for future use
	index uint64   //nolint:unused // Reserved for future use
	term  uint64   //nolint:unused // Reserved for future use
}

// RaftCommand represents commands sent through Raft
type RaftCommand struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// NodeUpdateCommand is sent when node info changes
type NodeUpdateCommand struct {
	NodeID   uint64    `json:"node_id"`
	NodeInfo *NodeInfo `json:"node_info"`
}

// NewRaftConsensus creates a new Raft consensus instance
func NewRaftConsensus(ctx context.Context, nodeID uint64, nodeInfo *NodeInfo, peers []raft.Peer, logger logging.Logger) (*RaftConsensus, error) {
	storage := raft.NewMemoryStorage()

	config := &raft.Config{
		ID:              nodeID,
		ElectionTick:    10, // 1 second (with 100ms tick)
		HeartbeatTick:   1,  // 100ms heartbeat
		Storage:         storage,
		MaxSizePerMsg:   4096,
		MaxInflightMsgs: 256,
		CheckQuorum:     true, // Leader steps down if loses quorum
		PreVote:         true, // Prevents election storms
		Logger:          &raftLogger{logger: logger},
	}

	rc := &RaftConsensus{
		nodeID:   nodeID,
		nodeInfo: nodeInfo,
		storage:  storage,
		config:   config,
		clusterState: &ClusterState{
			Nodes: make(map[uint64]*NodeInfo),
		},
		proposeC:    make(chan []byte),
		confChangeC: make(chan raftpb.ConfChange),
		commitC:     make(chan *commit, 128),
		errorC:      make(chan error),
		stopC:       make(chan struct{}),
		logger:      logger,
	}

	rc.ctx, rc.cancel = context.WithCancel(ctx)

	// Initialize cluster state with local node
	rc.clusterState.Nodes[nodeID] = nodeInfo

	// Start Raft node
	if len(peers) > 0 {
		// Starting a new cluster
		rc.node = raft.StartNode(config, peers)
		log.Printf("RAFT: Started new Raft node, node_id=%d, peers=%v", nodeID, peers)

		// Log Raft status immediately after start
		status := rc.node.Status()
		log.Printf("RAFT: Initial status after StartNode, node_id=%d, term=%d, lead=%d, raft_state=%s",
			nodeID, status.Term, status.Lead, status.RaftState)
	} else {
		// Joining existing cluster (will be added via ConfChange)
		rc.node = raft.RestartNode(config)
		log.Printf("RAFT: Restarted Raft node, node_id=%d", nodeID)
	}

	// CRITICAL: Start the Raft processing loop IMMEDIATELY
	// The Ready channel must be consumed or Raft will block
	log.Printf("RAFT: Starting Raft processing loop immediately, node_id=%d", nodeID)
	go rc.runRaft()

	return rc, nil
}

// Start begins the Raft consensus engine
func (rc *RaftConsensus) Start() error {
	log.Printf("RAFT: Starting Raft consensus engine, node_id=%d", rc.nodeID)

	// Note: runRaft() goroutine is already started in NewRaftConsensus()
	// to ensure Ready channel is consumed immediately

	// Start transport layer
	if rc.transport != nil {
		if err := rc.transport.Start(rc.ctx); err != nil {
			return fmt.Errorf("failed to start Raft transport: %w", err)
		}
	}

	// Don't propose node update here - it would block since the Raft loop
	// might be waiting for ticker. The node is already added via ConfChange
	// during initialization.

	return nil
}

// Stop gracefully stops the Raft consensus engine
func (rc *RaftConsensus) Stop() error {
	log.Printf("RAFT: Stopping Raft consensus engine, node_id=%d", rc.nodeID)

	close(rc.stopC)
	rc.cancel()

	if rc.transport != nil {
		rc.transport.Stop()
	}

	rc.node.Stop()

	return nil
}

// runRaft is the main Raft processing loop
func (rc *RaftConsensus) runRaft() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	log.Printf("RAFT: Main Raft loop started, node_id=%d, ticker=%p", rc.nodeID, ticker)
	tickCount := 0
	loopCount := 0

	// Debug timer to see if select is blocking
	debugTicker := time.NewTicker(5 * time.Second)
	defer debugTicker.Stop()

	for {
		loopCount++
		if loopCount%100 == 0 {
			log.Printf("RAFT: Loop iteration %d, node_id=%d", loopCount, rc.nodeID)
		}

		select {
		case <-ticker.C:
			tickCount++
			log.Printf("RAFT: Tick %d START, node_id=%d", tickCount, rc.nodeID)
			rc.node.Tick()
			log.Printf("RAFT: Tick %d COMPLETE, node_id=%d", tickCount, rc.nodeID)

		case <-debugTicker.C:
			// Periodic health check

		case rd := <-rc.node.Ready():
			// Process Ready updates from Raft
			log.Printf("RAFT: Processing Ready, node_id=%d, has_entries=%d, has_messages=%d, has_snapshot=%t",
				rc.nodeID, len(rd.Entries), len(rd.Messages), !raft.IsEmptySnap(rd.Snapshot))
			rc.processReady(rd)

		case prop := <-rc.proposeC:
			// Propose new entry to Raft log
			log.Printf("RAFT: Received proposal, node_id=%d", rc.nodeID)
			if err := rc.node.Propose(rc.ctx, prop); err != nil {
				rc.logger.Error("Failed to propose to Raft", "error", err)
			}

		case cc := <-rc.confChangeC:
			// Propose configuration change
			log.Printf("RAFT: Received conf change, node_id=%d", rc.nodeID)
			if err := rc.node.ProposeConfChange(rc.ctx, cc); err != nil {
				rc.logger.Error("Failed to propose conf change", "error", err)
			}

		case <-rc.stopC:
			log.Printf("RAFT: Raft loop stopping, node_id=%d", rc.nodeID)
			return

		case <-rc.ctx.Done():
			log.Printf("RAFT: Raft loop context cancelled, node_id=%d", rc.nodeID)
			return
		}
	}
}

// processReady handles Ready struct from Raft
func (rc *RaftConsensus) processReady(rd raft.Ready) {
	log.Printf("RAFT: processReady START, node_id=%d", rc.nodeID)

	// Save to storage before sending messages
	if !raft.IsEmptySnap(rd.Snapshot) {
		log.Printf("RAFT: Applying snapshot, node_id=%d", rc.nodeID)
		if err := rc.storage.ApplySnapshot(rd.Snapshot); err != nil {
			log.Printf("RAFT: Failed to apply snapshot, node_id=%d, error=%v", rc.nodeID, err)
		}
		rc.publishSnapshot(rd.Snapshot)
	}

	if len(rd.Entries) > 0 {
		log.Printf("RAFT: Appending %d entries to storage, node_id=%d", len(rd.Entries), rc.nodeID)
		if err := rc.storage.Append(rd.Entries); err != nil {
			log.Printf("RAFT: Failed to append entries, node_id=%d, error=%v", rc.nodeID, err)
		}
	}

	if !raft.IsEmptyHardState(rd.HardState) {
		hardState := rd.HardState
		log.Printf("RAFT: Setting HardState, node_id=%d, term=%d, vote=%d, commit=%d",
			rc.nodeID, hardState.Term, hardState.Vote, hardState.Commit)
		if err := rc.storage.SetHardState(hardState); err != nil {
			log.Printf("RAFT: Failed to set hard state, node_id=%d, error=%v", rc.nodeID, err)
		}
	}

	// Send messages to peers
	if rc.transport != nil && len(rd.Messages) > 0 {
		log.Printf("RAFT: Sending %d messages to peers, node_id=%d", len(rd.Messages), rc.nodeID)
		rc.transport.Send(rd.Messages)
	}

	// Apply committed entries to state machine
	if len(rd.CommittedEntries) > 0 {
		log.Printf("RAFT: Applying %d committed entries, node_id=%d", len(rd.CommittedEntries), rc.nodeID)
		rc.publishEntries(rc.entriesToApply(rd.CommittedEntries))
	}

	// Update leadership
	if rd.SoftState != nil {
		softState := rd.SoftState
		log.Printf("RAFT: Updating leadership, node_id=%d, lead=%d, raft_state=%s",
			rc.nodeID, softState.Lead, softState.RaftState)
		rc.updateLeadership(softState)
	}

	// Advance the Raft state machine
	log.Printf("RAFT: Calling Advance(), node_id=%d", rc.nodeID)
	rc.node.Advance()
	log.Printf("RAFT: processReady COMPLETE, node_id=%d", rc.nodeID)
}

// entriesToApply filters out entries that have already been applied
func (rc *RaftConsensus) entriesToApply(entries []raftpb.Entry) []raftpb.Entry {
	if len(entries) == 0 {
		return nil
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Get the index of the last applied entry from our tracking
	firstIdx := entries[0].Index
	lastIdx := entries[len(entries)-1].Index

	log.Printf("RAFT: entriesToApply check, node_id=%d, firstIdx=%d, lastIdx=%d, appliedIndex=%d",
		rc.nodeID, firstIdx, lastIdx, rc.appliedIndex)

	// If we've already applied all these entries, skip them
	if lastIdx <= rc.appliedIndex {
		log.Printf("RAFT: All entries already applied, node_id=%d", rc.nodeID)
		return nil
	}

	// Calculate which entries haven't been applied yet
	offset := uint64(0)
	if firstIdx <= rc.appliedIndex {
		// Some entries at the beginning have already been applied
		offset = rc.appliedIndex + 1 - firstIdx
		log.Printf("RAFT: Skipping %d already-applied entries, node_id=%d", offset, rc.nodeID)
	}

	if offset >= uint64(len(entries)) {
		// All entries have been applied
		return nil
	}

	return entries[offset:]
}

// publishEntries applies committed entries to the state machine
func (rc *RaftConsensus) publishEntries(entries []raftpb.Entry) {
	for _, entry := range entries {
		switch entry.Type {
		case raftpb.EntryNormal:
			if len(entry.Data) == 0 {
				// Ignore empty entries (leader election)
				break
			}

			// Apply command to state machine
			if err := rc.applyCommand(entry.Data); err != nil {
				log.Printf("RAFT: Failed to apply command: %v", err)
			}

		case raftpb.EntryConfChange:
			var cc raftpb.ConfChange
			if err := cc.Unmarshal(entry.Data); err != nil {
				log.Printf("RAFT: Failed to unmarshal conf change: %v", err)
				continue
			}

			rc.node.ApplyConfChange(cc)

			switch cc.Type {
			case raftpb.ConfChangeAddNode:
				log.Printf("RAFT: Added node to cluster, node_id=%d", cc.NodeID)
			case raftpb.ConfChangeRemoveNode:
				log.Printf("RAFT: Removed node from cluster, node_id=%d", cc.NodeID)
				rc.clusterState.mu.Lock()
				delete(rc.clusterState.Nodes, cc.NodeID)
				rc.clusterState.mu.Unlock()
			}
		}

		// Update applied index after processing each entry
		rc.mu.Lock()
		if entry.Index > rc.appliedIndex {
			rc.appliedIndex = entry.Index
			log.Printf("RAFT: Updated appliedIndex=%d, node_id=%d", rc.appliedIndex, rc.nodeID)
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
	default:
		return fmt.Errorf("unknown command type: %s", cmd.Type)
	}
}

// applyNodeUpdate updates node information in cluster state
func (rc *RaftConsensus) applyNodeUpdate(data interface{}) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	var update NodeUpdateCommand
	if err := json.Unmarshal(dataBytes, &update); err != nil {
		return err
	}

	rc.clusterState.mu.Lock()
	rc.clusterState.Nodes[update.NodeID] = update.NodeInfo
	rc.clusterState.LastModified = time.Now()
	rc.clusterState.mu.Unlock()

	log.Printf("RAFT: Applied node update, node_id=%d, node_info=%+v", update.NodeID, update.NodeInfo)

	return nil
}

// publishSnapshot applies a snapshot to the state machine
func (rc *RaftConsensus) publishSnapshot(snapshot raftpb.Snapshot) {
	if raft.IsEmptySnap(snapshot) {
		return
	}

	log.Printf("RAFT: Publishing snapshot at index %d", snapshot.Metadata.Index)

	var state ClusterState
	if err := json.Unmarshal(snapshot.Data, &state); err != nil {
		log.Printf("RAFT: Failed to unmarshal snapshot: %v", err)
		return
	}

	rc.clusterState.mu.Lock()
	rc.clusterState = &state
	rc.clusterState.mu.Unlock()
}

// updateLeadership handles leadership changes
func (rc *RaftConsensus) updateLeadership(ss *raft.SoftState) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	wasLeader := rc.clusterState.Leader == rc.nodeID
	isLeader := ss.Lead == rc.nodeID && ss.RaftState == raft.StateLeader

	if !wasLeader && isLeader {
		log.Printf("RAFT: Node became LEADER, node_id=%d, term=%d", rc.nodeID, rc.node.Status().Term)
		rc.clusterState.Leader = rc.nodeID
	} else if wasLeader && !isLeader {
		log.Printf("RAFT: Node lost LEADER status, node_id=%d, new_leader=%d", rc.nodeID, ss.Lead)
		rc.clusterState.Leader = ss.Lead
	}

	if ss.Lead != raft.None {
		rc.clusterState.Leader = ss.Lead
	}
}

// IsLeader returns true if this node is the leader
func (rc *RaftConsensus) IsLeader() bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.clusterState.Leader == rc.nodeID
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

// Process receives and processes Raft messages from peers
func (rc *RaftConsensus) Process(ctx context.Context, m raftpb.Message) error {
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
