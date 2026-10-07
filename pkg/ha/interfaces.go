// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ha

import (
	"context"
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

	// HasLeadership returns true when this node holds lease-backed authority to
	// perform side-effecting operations (ADR-029 Decision 3, ADR-031 Decision 5).
	// In SingleServerMode this is unconditionally true; in ClusterMode it is
	// backed by the shared database lease (pkg/lease). This is the admission
	// primitive for every side-effecting path.
	HasLeadership() bool

	// GetLeader returns the current cluster leader node
	GetLeader() (*NodeInfo, error)

	// RegisterHealthCheck registers a health check function
	RegisterHealthCheck(name string, check HealthCheckFunc)

	// GetHealth returns the current health status
	GetHealth() *HealthStatus

	// GetCACertPEM returns the CA certificate PEM bytes used to verify HA peer TLS.
	// Returns nil when CACertPath is unconfigured or the file cannot be read.
	// Safe to call concurrently.
	GetCACertPEM() []byte
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
