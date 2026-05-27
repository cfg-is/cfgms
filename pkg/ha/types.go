// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ha

import "time"

// Config represents the high-availability configuration
// This is available in both OSS and commercial builds
type Config struct {
	// Deployment mode (single, blue-green, cluster)
	Mode DeploymentMode `yaml:"mode" json:"mode"`

	// Node configuration
	Node NodeConfig `yaml:"node" json:"node"`

	// CACertPath is the path to the CA certificate for TLS verification between HA nodes
	CACertPath string `yaml:"ca_cert_path,omitempty" json:"ca_cert_path,omitempty"`

	// Cluster configuration (only used in commercial builds)
	Cluster ClusterConfig `yaml:"cluster" json:"cluster"`

	// Failover configuration (only used in commercial builds)
	Failover *FailoverConfig `yaml:"failover,omitempty" json:"failover,omitempty"`

	// Split-brain detection configuration (only used in commercial builds)
	SplitBrain *SplitBrainConfig `yaml:"split_brain,omitempty" json:"split_brain,omitempty"`

	// Health check configuration
	HealthCheck *HealthCheckConfig `yaml:"health_check,omitempty" json:"health_check,omitempty"`
}

// NodeConfig contains configuration for this controller node
type NodeConfig struct {
	// Node ID (auto-generated if not provided)
	ID string `yaml:"id" json:"id"`

	// Node name (human-readable, defaults to controller-{short-id})
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	// External address (how other nodes reach this node)
	ExternalAddress string `yaml:"external_address" json:"external_address"`

	// Region identifier for geographic routing
	Region string `yaml:"region,omitempty" json:"region,omitempty"`

	// Availability zone within region
	AvailabilityZone string `yaml:"availability_zone,omitempty" json:"availability_zone,omitempty"`

	// Geographic coordinates for distance calculations
	Coordinates *GeographicCoordinates `yaml:"coordinates,omitempty" json:"coordinates,omitempty"`

	// Node capabilities (for feature-based routing)
	Capabilities []string `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

// GeographicCoordinates represents lat/long for distance calculations
type GeographicCoordinates struct {
	Latitude  float64 `yaml:"latitude" json:"latitude"`
	Longitude float64 `yaml:"longitude" json:"longitude"`
}

// ClusterConfig contains cluster-wide configuration (commercial only)
type ClusterConfig struct {
	ExpectedSize      int              `yaml:"expected_size" json:"expected_size"`
	MinQuorum         int              `yaml:"min_quorum" json:"min_quorum"`
	ElectionTimeout   time.Duration    `yaml:"election_timeout" json:"election_timeout"`
	HeartbeatInterval time.Duration    `yaml:"heartbeat_interval" json:"heartbeat_interval"`
	Discovery         *DiscoveryConfig `yaml:"discovery" json:"discovery"`
}

// DiscoveryConfig contains node discovery configuration (commercial only)
type DiscoveryConfig struct {
	Config map[string]interface{} `yaml:"config" json:"config"`
}

// FailoverConfig contains automatic failover configuration (commercial only)
type FailoverConfig struct {
	Enabled             bool          `yaml:"enabled" json:"enabled"`
	DetectionInterval   time.Duration `yaml:"detection_interval" json:"detection_interval"`
	FailureThreshold    int           `yaml:"failure_threshold" json:"failure_threshold"`
	RecoveryThreshold   int           `yaml:"recovery_threshold" json:"recovery_threshold"`
	MaxFailoversPerHour int           `yaml:"max_failovers_per_hour" json:"max_failovers_per_hour"`
	Timeout             time.Duration `yaml:"timeout" json:"timeout"`                             // Failover operation timeout
	MaxDuration         time.Duration `yaml:"max_duration" json:"max_duration"`                   // Maximum time for failover
	GracePeriod         time.Duration `yaml:"grace_period" json:"grace_period"`                   // Grace period before failover
	MaxSessionMigration int           `yaml:"max_session_migration" json:"max_session_migration"` // Max sessions to migrate
}

// SplitBrainConfig contains split-brain detection configuration (commercial only)
type SplitBrainConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	DetectionInterval  time.Duration `yaml:"detection_interval" json:"detection_interval"`
	QuorumCheck        bool          `yaml:"quorum_check" json:"quorum_check"`
	AutoResolve        bool          `yaml:"auto_resolve" json:"auto_resolve"`
	QuorumInterval     time.Duration `yaml:"quorum_interval" json:"quorum_interval"`         // Quorum validation interval
	ResolutionStrategy string        `yaml:"resolution_strategy" json:"resolution_strategy"` // Split-brain resolution strategy
}

// HealthCheckConfig contains health check configuration
type HealthCheckConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	Interval         time.Duration `yaml:"interval" json:"interval"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	FailureThreshold int           `yaml:"failure_threshold" json:"failure_threshold"` // Consecutive failures before unhealthy
	SuccessThreshold int           `yaml:"success_threshold" json:"success_threshold"` // Consecutive successes before healthy
	EnableInternal   bool          `yaml:"enable_internal" json:"enable_internal"`     // Enable internal health checks
	EnableExternal   bool          `yaml:"enable_external" json:"enable_external"`     // Enable external health checks
}
