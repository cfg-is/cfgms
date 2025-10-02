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
	data  [][]byte
	index uint64
	term  uint64
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
	} else {
		// Joining existing cluster (will be added via ConfChange)
		rc.node = raft.RestartNode(config)
		log.Printf("RAFT: Restarted Raft node, node_id=%d", nodeID)
	}

	return rc, nil
}

// Start begins the Raft consensus engine
func (rc *RaftConsensus) Start() error {
	log.Printf("RAFT: Starting Raft consensus engine, node_id=%d", rc.nodeID)

	// Start the main Raft loop
	go rc.runRaft()

	// Start transport layer
	if rc.transport != nil {
		if err := rc.transport.Start(rc.ctx); err != nil {
			return fmt.Errorf("failed to start Raft transport: %w", err)
		}
	}

	// Register local node in cluster state
	if err := rc.proposeNodeUpdate(rc.nodeID, rc.nodeInfo); err != nil {
		rc.logger.Warn("Failed to propose initial node update", "error", err)
	}

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

	log.Printf("RAFT: Main Raft loop started, node_id=%d", rc.nodeID)

	for {
		select {
		case <-ticker.C:
			rc.node.Tick()

		case rd := <-rc.node.Ready():
			// Process Ready updates from Raft
			rc.processReady(rd)

		case prop := <-rc.proposeC:
			// Propose new entry to Raft log
			if err := rc.node.Propose(rc.ctx, prop); err != nil {
				rc.logger.Error("Failed to propose to Raft", "error", err)
			}

		case cc := <-rc.confChangeC:
			// Propose configuration change
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
	// Save to storage before sending messages
	if !raft.IsEmptySnap(rd.Snapshot) {
		rc.storage.ApplySnapshot(rd.Snapshot)
		rc.publishSnapshot(rd.Snapshot)
	}

	if len(rd.Entries) > 0 {
		rc.storage.Append(rd.Entries)
	}

	if !raft.IsEmptyHardState(rd.HardState) {
		rc.storage.SetHardState(rd.HardState)
	}

	// Send messages to peers
	if rc.transport != nil {
		rc.transport.Send(rd.Messages)
	}

	// Apply committed entries to state machine
	if len(rd.CommittedEntries) > 0 {
		rc.publishEntries(rc.entriesToApply(rd.CommittedEntries))
	}

	// Update leadership
	if rd.SoftState != nil {
		rc.updateLeadership(rd.SoftState)
	}

	// Advance the Raft state machine
	rc.node.Advance()
}

// entriesToApply filters out entries that have already been applied
func (rc *RaftConsensus) entriesToApply(entries []raftpb.Entry) []raftpb.Entry {
	if len(entries) == 0 {
		return nil
	}

	// Get the index of the last applied entry
	firstIdx := entries[0].Index
	snapshot, err := rc.storage.Snapshot()
	if err != nil {
		log.Printf("RAFT: Failed to get snapshot: %v", err)
		return nil
	}
	lastApplied := snapshot.Metadata.Index

	if firstIdx > lastApplied+1 {
		log.Fatalf("RAFT: First index %d should <= last applied %d + 1", firstIdx, lastApplied)
	}

	// Trim already-applied entries
	offset := lastApplied + 1 - firstIdx
	if offset < uint64(len(entries)) {
		return entries[offset:]
	}

	return nil
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

// proposeNodeUpdate proposes a node update to the cluster
func (rc *RaftConsensus) proposeNodeUpdate(nodeID uint64, nodeInfo *NodeInfo) error {
	cmd := RaftCommand{
		Type: "node_update",
		Data: NodeUpdateCommand{
			NodeID:   nodeID,
			NodeInfo: nodeInfo,
		},
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	select {
	case rc.proposeC <- data:
		return nil
	case <-rc.ctx.Done():
		return rc.ctx.Err()
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
