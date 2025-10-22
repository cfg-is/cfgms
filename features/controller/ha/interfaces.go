package ha

import (
	"context"
	"net/http"
	"time"
)

// DeploymentMode represents the controller deployment configuration
type DeploymentMode int

const (
	// SingleServerMode - Traditional single instance deployment
	SingleServerMode DeploymentMode = iota

	// BlueGreenMode - Dual instance deployment for zero-downtime updates
	BlueGreenMode

	// ClusterMode - Multi-instance cluster with leader election
	ClusterMode
)

func (d DeploymentMode) String() string {
	switch d {
	case SingleServerMode:
		return "single"
	case BlueGreenMode:
		return "blue-green"
	case ClusterMode:
		return "cluster"
	default:
		return "unknown"
	}
}

// NodeState represents the state of a controller node
type NodeState int

const (
	NodeStateUnknown NodeState = iota
	NodeStateHealthy
	NodeStateDegraded
	NodeStateFailed
	NodeStateOffline
)

func (n NodeState) String() string {
	switch n {
	case NodeStateHealthy:
		return "healthy"
	case NodeStateDegraded:
		return "degraded"
	case NodeStateFailed:
		return "failed"
	case NodeStateOffline:
		return "offline"
	default:
		return "unknown"
	}
}

// NodeRole represents the role of a controller node in cluster mode
type NodeRole int

const (
	NodeRoleFollower NodeRole = iota
	NodeRoleCandidate
	NodeRoleLeader
)

func (r NodeRole) String() string {
	switch r {
	case NodeRoleFollower:
		return "follower"
	case NodeRoleCandidate:
		return "candidate"
	case NodeRoleLeader:
		return "leader"
	default:
		return "unknown"
	}
}

// NodeInfo represents information about a controller node
type NodeInfo struct {
	ID               string                   `json:"id"`
	Address          string                   `json:"address"`
	State            NodeState                `json:"state"`
	Role             NodeRole                 `json:"role"`
	LastSeen         time.Time                `json:"last_seen"`
	Version          string                   `json:"version"`
	StartedAt        time.Time                `json:"started_at"`
	Capabilities     []string                 `json:"capabilities"`
	Region           string                   `json:"region,omitempty"`
	AvailabilityZone string                   `json:"availability_zone,omitempty"`
	Coordinates      *GeographicCoordinates   `json:"coordinates,omitempty"`
	Latency          map[string]time.Duration `json:"latency,omitempty"` // Latency to other nodes
}

// ClusterManager handles high availability operations
type ClusterManager interface {
	// Start begins the cluster operations
	Start(ctx context.Context) error

	// Stop gracefully stops cluster operations
	Stop(ctx context.Context) error

	// GetDeploymentMode returns the current deployment mode
	GetDeploymentMode() DeploymentMode

	// GetLocalNode returns information about the local node
	GetLocalNode() *NodeInfo

	// GetClusterNodes returns information about all nodes in the cluster
	GetClusterNodes() ([]*NodeInfo, error)

	// IsLeader returns true if this node is the cluster leader
	IsLeader() bool

	// GetLeader returns the current cluster leader node
	GetLeader() (*NodeInfo, error)

	// RegisterHealthCheck registers a health check function
	RegisterHealthCheck(name string, check HealthCheckFunc)

	// GetHealth returns the current health status
	GetHealth() *HealthStatus

	// GetRaftTransport returns the Raft HTTP transport (commercial only, returns nil in OSS)
	GetRaftTransport() RaftTransport
}

// HealthCheckFunc is a function that checks the health of a component
type HealthCheckFunc func(ctx context.Context) error

// HealthStatus represents the overall health of the node
type HealthStatus struct {
	Overall   NodeState            `json:"overall"`
	Checks    map[string]NodeState `json:"checks"`
	Timestamp time.Time            `json:"timestamp"`
	Details   map[string]string    `json:"details,omitempty"`
}

// SessionSynchronizer handles session state synchronization across cluster nodes
type SessionSynchronizer interface {
	// SyncSessionState synchronizes session state to other cluster nodes
	SyncSessionState(ctx context.Context, sessionID string, state interface{}) error

	// GetSessionState retrieves session state from the cluster
	GetSessionState(ctx context.Context, sessionID string) (interface{}, error)

	// RemoveSessionState removes session state from the cluster
	RemoveSessionState(ctx context.Context, sessionID string) error

	// Subscribe to session state changes
	Subscribe(ctx context.Context, handler SessionStateHandler) error
}

// SessionStateHandler handles session state change notifications
type SessionStateHandler interface {
	OnSessionStateChanged(sessionID string, state interface{}) error
	OnSessionRemoved(sessionID string) error
}

// LoadBalancer handles request distribution across cluster nodes
type LoadBalancer interface {
	// GetNextNode returns the next node for load balancing
	GetNextNode() (*NodeInfo, error)

	// UpdateNodeHealth updates the health status of a node
	UpdateNodeHealth(nodeID string, health *HealthStatus) error

	// RemoveNode removes a node from load balancing
	RemoveNode(nodeID string) error

	// GetLoadBalancingStrategy returns the current strategy
	GetLoadBalancingStrategy() LoadBalancingStrategy
}

// LoadBalancingStrategy represents different load balancing strategies
type LoadBalancingStrategy int

const (
	RoundRobinStrategy LoadBalancingStrategy = iota
	LeastConnectionsStrategy
	HealthBasedStrategy
	GeographicStrategy
)

func (s LoadBalancingStrategy) String() string {
	switch s {
	case RoundRobinStrategy:
		return "round-robin"
	case LeastConnectionsStrategy:
		return "least-connections"
	case HealthBasedStrategy:
		return "health-based"
	case GeographicStrategy:
		return "geographic"
	default:
		return "unknown"
	}
}

// FailoverManager handles automatic failover operations
type FailoverManager interface {
	// Start begins failover monitoring
	Start(ctx context.Context) error

	// Stop stops failover monitoring
	Stop(ctx context.Context) error

	// RegisterFailoverHandler registers a handler for failover events
	RegisterFailoverHandler(handler FailoverHandler)

	// TriggerFailover manually triggers a failover
	TriggerFailover(ctx context.Context, reason string) error

	// GetFailoverHistory returns recent failover events
	GetFailoverHistory() ([]*FailoverEvent, error)
}

// FailoverHandler handles failover events
type FailoverHandler interface {
	OnFailoverStarted(event *FailoverEvent) error
	OnFailoverCompleted(event *FailoverEvent) error
	OnFailoverFailed(event *FailoverEvent, err error) error
}

// FailoverEvent represents a failover event
type FailoverEvent struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	Reason           string                 `json:"reason"`
	PreviousLeader   string                 `json:"previous_leader,omitempty"`
	NewLeader        string                 `json:"new_leader,omitempty"`
	Duration         time.Duration          `json:"duration"`
	SessionsMigrated int                    `json:"sessions_migrated"`
	Status           string                 `json:"status"`
	Details          map[string]interface{} `json:"details,omitempty"`
}

// SplitBrainDetector detects and prevents split-brain scenarios
type SplitBrainDetector interface {
	// Start begins split-brain detection
	Start(ctx context.Context) error

	// Stop stops split-brain detection
	Stop(ctx context.Context) error

	// CheckSplitBrain checks for split-brain conditions
	CheckSplitBrain(ctx context.Context) (*SplitBrainStatus, error)

	// RegisterSplitBrainHandler registers a handler for split-brain events
	RegisterSplitBrainHandler(handler SplitBrainHandler)
}

// SplitBrainHandler handles split-brain detection events
type SplitBrainHandler interface {
	OnSplitBrainDetected(status *SplitBrainStatus) error
	OnSplitBrainResolved(status *SplitBrainStatus) error
}

// SplitBrainStatus represents the status of split-brain detection
type SplitBrainStatus struct {
	Detected     bool                   `json:"detected"`
	Timestamp    time.Time              `json:"timestamp"`
	PartitionIDs []string               `json:"partition_ids,omitempty"`
	Resolution   string                 `json:"resolution,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// RaftTransport handles HTTP transport for Raft messages
// This is only used in commercial builds with clustering
type RaftTransport interface {
	// HandleMessage handles incoming Raft messages
	HandleMessage(w http.ResponseWriter, r *http.Request)

	// HandleStatus returns Raft cluster status
	HandleStatus(w http.ResponseWriter, r *http.Request)
}
