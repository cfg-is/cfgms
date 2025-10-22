package ha

import "time"

// Config represents the high-availability configuration
// This is available in both OSS and commercial builds
type Config struct {
	// Deployment mode (single, blue-green, cluster)
	Mode DeploymentMode `yaml:"mode" json:"mode"`

	// Node configuration
	Node NodeConfig `yaml:"node" json:"node"`

	// Cluster configuration (only used in commercial builds)
	Cluster ClusterConfig `yaml:"cluster" json:"cluster"`

	// Load balancing configuration (only used in commercial builds)
	LoadBalancing *LoadBalancingConfig `yaml:"load_balancing,omitempty" json:"load_balancing,omitempty"`

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
	ExpectedSize        int                `yaml:"expected_size" json:"expected_size"`
	MinQuorum           int                `yaml:"min_quorum" json:"min_quorum"`
	ElectionTimeout     time.Duration      `yaml:"election_timeout" json:"election_timeout"`
	HeartbeatInterval   time.Duration      `yaml:"heartbeat_interval" json:"heartbeat_interval"`
	LeaderLeaseDuration time.Duration      `yaml:"leader_lease_duration" json:"leader_lease_duration"`
	CandidateTimeout    time.Duration      `yaml:"candidate_timeout" json:"candidate_timeout"`
	ApplyTimeout        time.Duration      `yaml:"apply_timeout" json:"apply_timeout"`
	Discovery           *DiscoveryConfig   `yaml:"discovery" json:"discovery"`
	SessionSync         *SessionSyncConfig `yaml:"session_sync" json:"session_sync"`
}

// DiscoveryConfig contains node discovery configuration (commercial only)
type DiscoveryConfig struct {
	Method      string                     `yaml:"method" json:"method"`
	Config      map[string]interface{}     `yaml:"config" json:"config"`
	Interval    time.Duration              `yaml:"interval" json:"interval"`
	NodeTimeout time.Duration              `yaml:"node_timeout" json:"node_timeout"`
	Geographic  *GeographicDiscoveryConfig `yaml:"geographic,omitempty" json:"geographic,omitempty"`
}

// GeographicDiscoveryConfig contains geographic-aware discovery settings (commercial only)
type GeographicDiscoveryConfig struct {
	EnableRegionAffinity         bool               `yaml:"enable_region_affinity" json:"enable_region_affinity"`
	CrossRegionTimeoutMultiplier float64            `yaml:"cross_region_timeout_multiplier" json:"cross_region_timeout_multiplier"`
	MaxCrossRegionLatency        time.Duration      `yaml:"max_cross_region_latency" json:"max_cross_region_latency"`
	LatencyCheckInterval         time.Duration      `yaml:"latency_check_interval" json:"latency_check_interval"`
	RegionalWeights              map[string]float64 `yaml:"regional_weights,omitempty" json:"regional_weights,omitempty"`
}

// SessionSyncConfig contains session synchronization configuration (commercial only)
type SessionSyncConfig struct {
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	SyncInterval      time.Duration `yaml:"sync_interval" json:"sync_interval"`
	StateTimeout      time.Duration `yaml:"state_timeout" json:"state_timeout"`
	ReplicationFactor int           `yaml:"replication_factor" json:"replication_factor"`
	MaxStateSize      int           `yaml:"max_state_size" json:"max_state_size"` // Maximum session state size
}

// LoadBalancingConfig contains load balancing configuration (commercial only)
type LoadBalancingConfig struct {
	Strategy           LoadBalancingStrategy          `yaml:"strategy" json:"strategy"`
	HealthCheckEnabled bool                           `yaml:"health_check_enabled" json:"health_check_enabled"`
	SessionAffinity    bool                           `yaml:"session_affinity" json:"session_affinity"`
	HealthBased        *HealthBasedConfig             `yaml:"health_based,omitempty" json:"health_based,omitempty"`
	ConnectionBased    *ConnectionBasedConfig         `yaml:"connection_based,omitempty" json:"connection_based,omitempty"`
	Geographic         *GeographicLoadBalancingConfig `yaml:"geographic,omitempty" json:"geographic,omitempty"`
}

// HealthBasedConfig contains health-based load balancing configuration
type HealthBasedConfig struct {
	MinHealthScore     float64 `yaml:"min_health_score" json:"min_health_score"`
	HealthWeightFactor float64 `yaml:"health_weight_factor" json:"health_weight_factor"`
}

// ConnectionBasedConfig contains connection-based load balancing configuration
type ConnectionBasedConfig struct {
	MaxConnectionsPerNode int     `yaml:"max_connections_per_node" json:"max_connections_per_node"`
	ConnectionThreshold   float64 `yaml:"connection_threshold" json:"connection_threshold"`
}

// GeographicLoadBalancingConfig contains geographic load balancing settings
type GeographicLoadBalancingConfig struct {
	EnableRegionAffinity    bool               `yaml:"enable_region_affinity" json:"enable_region_affinity"`
	RegionAffinityWeight    float64            `yaml:"region_affinity_weight" json:"region_affinity_weight"`
	LatencyWeightFactor     float64            `yaml:"latency_weight_factor" json:"latency_weight_factor"`
	MaxLatencyThreshold     time.Duration      `yaml:"max_latency_threshold" json:"max_latency_threshold"`
	CrossRegionFallback     bool               `yaml:"cross_region_fallback" json:"cross_region_fallback"`
	RegionalCapacityWeights map[string]float64 `yaml:"regional_capacity_weights,omitempty" json:"regional_capacity_weights,omitempty"`
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
