//go:build commercial
// +build commercial

package ha

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Config contains high availability configuration
type Config struct {
	// Deployment mode configuration
	Mode DeploymentMode `yaml:"mode" json:"mode"`

	// Node configuration
	Node *NodeConfig `yaml:"node" json:"node"`

	// Cluster configuration (used in cluster mode)
	Cluster *ClusterConfig `yaml:"cluster" json:"cluster"`

	// Health check configuration
	HealthCheck *HealthCheckConfig `yaml:"health_check" json:"health_check"`

	// Failover configuration
	Failover *FailoverConfig `yaml:"failover" json:"failover"`

	// Load balancing configuration
	LoadBalancing *LoadBalancingConfig `yaml:"load_balancing" json:"load_balancing"`

	// Split-brain prevention configuration
	SplitBrain *SplitBrainConfig `yaml:"split_brain" json:"split_brain"`
}

// NodeConfig contains node-specific configuration
type NodeConfig struct {
	// Unique node identifier (auto-generated if empty)
	ID string `yaml:"id" json:"id"`

	// Node name for display purposes
	Name string `yaml:"name" json:"name"`

	// External address for inter-node communication
	ExternalAddress string `yaml:"external_address" json:"external_address"`

	// Internal address for cluster communication
	InternalAddress string `yaml:"internal_address" json:"internal_address"`

	// Geographic region (e.g., "us-east", "us-central", "us-west")
	Region string `yaml:"region" json:"region"`

	// Availability zone within region (e.g., "us-east-1a")
	AvailabilityZone string `yaml:"availability_zone" json:"availability_zone"`

	// Geographic coordinates for latency calculations
	Coordinates *GeographicCoordinates `yaml:"coordinates,omitempty" json:"coordinates,omitempty"`

	// Node capabilities
	Capabilities []string `yaml:"capabilities" json:"capabilities"`

	// Metadata for node identification
	Metadata map[string]string `yaml:"metadata" json:"metadata"`
}

// GeographicCoordinates represents lat/long for distance calculations
type GeographicCoordinates struct {
	Latitude  float64 `yaml:"latitude" json:"latitude"`
	Longitude float64 `yaml:"longitude" json:"longitude"`
}

// ClusterConfig contains cluster-wide configuration
type ClusterConfig struct {
	// Expected cluster size (for quorum calculations)
	ExpectedSize int `yaml:"expected_size" json:"expected_size"`

	// Minimum quorum size
	MinQuorum int `yaml:"min_quorum" json:"min_quorum"`

	// Leader election timeout
	ElectionTimeout time.Duration `yaml:"election_timeout" json:"election_timeout"`

	// Heartbeat interval
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval" json:"heartbeat_interval"`

	// Leader lease duration (how long a leader holds its lease)
	LeaderLeaseDuration time.Duration `yaml:"leader_lease_duration" json:"leader_lease_duration"`

	// Candidate timeout (how long to wait before becoming candidate)
	CandidateTimeout time.Duration `yaml:"candidate_timeout" json:"candidate_timeout"`

	// Apply timeout (how long to wait for command application)
	ApplyTimeout time.Duration `yaml:"apply_timeout" json:"apply_timeout"`

	// Node discovery configuration
	Discovery *DiscoveryConfig `yaml:"discovery" json:"discovery"`

	// Session synchronization configuration
	SessionSync *SessionSyncConfig `yaml:"session_sync" json:"session_sync"`
}

// DiscoveryConfig contains node discovery configuration
type DiscoveryConfig struct {
	// Discovery method (static, dns, consul, kubernetes, geographic)
	Method string `yaml:"method" json:"method"`

	// Configuration specific to discovery method
	Config map[string]interface{} `yaml:"config" json:"config"`

	// Discovery interval
	Interval time.Duration `yaml:"interval" json:"interval"`

	// Node timeout before marking as offline
	NodeTimeout time.Duration `yaml:"node_timeout" json:"node_timeout"`

	// Geographic discovery configuration
	Geographic *GeographicDiscoveryConfig `yaml:"geographic,omitempty" json:"geographic,omitempty"`
}

// GeographicDiscoveryConfig contains geographic-aware discovery settings
type GeographicDiscoveryConfig struct {
	// Enable geographic routing preferences
	EnableRegionAffinity bool `yaml:"enable_region_affinity" json:"enable_region_affinity"`

	// Cross-region timeout multiplier (e.g., 2.0 = double timeout for cross-region)
	CrossRegionTimeoutMultiplier float64 `yaml:"cross_region_timeout_multiplier" json:"cross_region_timeout_multiplier"`

	// Maximum acceptable latency for cross-region communication (milliseconds)
	MaxCrossRegionLatency time.Duration `yaml:"max_cross_region_latency" json:"max_cross_region_latency"`

	// Latency check interval
	LatencyCheckInterval time.Duration `yaml:"latency_check_interval" json:"latency_check_interval"`

	// Regional node priority weights
	RegionalWeights map[string]float64 `yaml:"regional_weights,omitempty" json:"regional_weights,omitempty"`
}

// SessionSyncConfig contains session synchronization configuration
type SessionSyncConfig struct {
	// Enable session synchronization
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Synchronization interval
	SyncInterval time.Duration `yaml:"sync_interval" json:"sync_interval"`

	// Session state timeout
	StateTimeout time.Duration `yaml:"state_timeout" json:"state_timeout"`

	// Maximum session state size
	MaxStateSize int `yaml:"max_state_size" json:"max_state_size"`
}

// HealthCheckConfig contains health check configuration
type HealthCheckConfig struct {
	// Health check interval
	Interval time.Duration `yaml:"interval" json:"interval"`

	// Health check timeout
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Number of consecutive failures before marking unhealthy
	FailureThreshold int `yaml:"failure_threshold" json:"failure_threshold"`

	// Number of consecutive successes before marking healthy
	SuccessThreshold int `yaml:"success_threshold" json:"success_threshold"`

	// Enable internal health checks
	EnableInternal bool `yaml:"enable_internal" json:"enable_internal"`

	// Enable external health checks
	EnableExternal bool `yaml:"enable_external" json:"enable_external"`
}

// FailoverConfig contains failover configuration
type FailoverConfig struct {
	// Enable automatic failover
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Failover timeout
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Maximum failover duration
	MaxDuration time.Duration `yaml:"max_duration" json:"max_duration"`

	// Grace period before initiating failover
	GracePeriod time.Duration `yaml:"grace_period" json:"grace_period"`

	// Maximum sessions to migrate during failover
	MaxSessionMigration int `yaml:"max_session_migration" json:"max_session_migration"`
}

// LoadBalancingConfig contains load balancing configuration
type LoadBalancingConfig struct {
	// Load balancing strategy
	Strategy LoadBalancingStrategy `yaml:"strategy" json:"strategy"`

	// Health-based routing configuration
	HealthBased *HealthBasedConfig `yaml:"health_based" json:"health_based"`

	// Connection-based routing configuration
	ConnectionBased *ConnectionBasedConfig `yaml:"connection_based" json:"connection_based"`

	// Geographic routing configuration
	Geographic *GeographicLoadBalancingConfig `yaml:"geographic,omitempty" json:"geographic,omitempty"`
}

// GeographicLoadBalancingConfig contains geographic load balancing settings
type GeographicLoadBalancingConfig struct {
	// Enable region affinity (prefer same region)
	EnableRegionAffinity bool `yaml:"enable_region_affinity" json:"enable_region_affinity"`

	// Region affinity weight (0.0-1.0, higher means stronger preference)
	RegionAffinityWeight float64 `yaml:"region_affinity_weight" json:"region_affinity_weight"`

	// Latency weight factor (how much latency affects routing decisions)
	LatencyWeightFactor float64 `yaml:"latency_weight_factor" json:"latency_weight_factor"`

	// Maximum acceptable latency difference before rejecting node (milliseconds)
	MaxLatencyThreshold time.Duration `yaml:"max_latency_threshold" json:"max_latency_threshold"`

	// Cross-region fallback enabled (allow cross-region routing when local region unhealthy)
	CrossRegionFallback bool `yaml:"cross_region_fallback" json:"cross_region_fallback"`

	// Regional capacity weights (for proportional distribution across regions)
	RegionalCapacityWeights map[string]float64 `yaml:"regional_capacity_weights,omitempty" json:"regional_capacity_weights,omitempty"`
}

// HealthBasedConfig contains health-based load balancing configuration
type HealthBasedConfig struct {
	// Minimum health score for routing
	MinHealthScore float64 `yaml:"min_health_score" json:"min_health_score"`

	// Weight adjustment based on health
	HealthWeightFactor float64 `yaml:"health_weight_factor" json:"health_weight_factor"`
}

// ConnectionBasedConfig contains connection-based load balancing configuration
type ConnectionBasedConfig struct {
	// Maximum connections per node
	MaxConnectionsPerNode int `yaml:"max_connections_per_node" json:"max_connections_per_node"`

	// Connection threshold for load balancing
	ConnectionThreshold float64 `yaml:"connection_threshold" json:"connection_threshold"`
}

// SplitBrainConfig contains split-brain prevention configuration
type SplitBrainConfig struct {
	// Enable split-brain detection
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Detection interval
	DetectionInterval time.Duration `yaml:"detection_interval" json:"detection_interval"`

	// Quorum validation interval
	QuorumInterval time.Duration `yaml:"quorum_interval" json:"quorum_interval"`

	// Split-brain resolution strategy
	ResolutionStrategy string `yaml:"resolution_strategy" json:"resolution_strategy"`
}

// DefaultConfig returns a Config with reasonable defaults
func DefaultConfig() *Config {
	return &Config{
		Mode: SingleServerMode,
		Node: &NodeConfig{
			Capabilities: []string{"config", "rbac", "monitoring", "workflow"},
			Metadata:     make(map[string]string),
		},
		Cluster: &ClusterConfig{
			ExpectedSize:        3,
			MinQuorum:           2,
			ElectionTimeout:     10 * time.Second,
			HeartbeatInterval:   2 * time.Second,
			LeaderLeaseDuration: 15 * time.Second,
			CandidateTimeout:    5 * time.Second,
			ApplyTimeout:        2 * time.Second,
			Discovery: &DiscoveryConfig{
				Method:      "static",
				Config:      make(map[string]interface{}),
				Interval:    30 * time.Second,
				NodeTimeout: 60 * time.Second,
				Geographic: &GeographicDiscoveryConfig{
					EnableRegionAffinity:         true,
					CrossRegionTimeoutMultiplier: 2.0,
					MaxCrossRegionLatency:        500 * time.Millisecond,
					LatencyCheckInterval:         60 * time.Second,
					RegionalWeights:              make(map[string]float64),
				},
			},
			SessionSync: &SessionSyncConfig{
				Enabled:      true,
				SyncInterval: 5 * time.Second,
				StateTimeout: 300 * time.Second, // 5 minutes
				MaxStateSize: 1024 * 1024,       // 1MB
			},
		},
		HealthCheck: &HealthCheckConfig{
			Interval:         10 * time.Second,
			Timeout:          5 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 2,
			EnableInternal:   true,
			EnableExternal:   true,
		},
		Failover: &FailoverConfig{
			Enabled:             true,
			Timeout:             30 * time.Second,
			MaxDuration:         5 * time.Minute,
			GracePeriod:         10 * time.Second,
			MaxSessionMigration: 1000,
		},
		LoadBalancing: &LoadBalancingConfig{
			Strategy: HealthBasedStrategy,
			HealthBased: &HealthBasedConfig{
				MinHealthScore:     0.7,
				HealthWeightFactor: 1.0,
			},
			ConnectionBased: &ConnectionBasedConfig{
				MaxConnectionsPerNode: 1000,
				ConnectionThreshold:   0.8,
			},
			Geographic: &GeographicLoadBalancingConfig{
				EnableRegionAffinity:        true,
				RegionAffinityWeight:        0.8,
				LatencyWeightFactor:         0.5,
				MaxLatencyThreshold:         250 * time.Millisecond,
				CrossRegionFallback:         true,
				RegionalCapacityWeights:     make(map[string]float64),
			},
		},
		SplitBrain: &SplitBrainConfig{
			Enabled:            true,
			DetectionInterval:  15 * time.Second,
			QuorumInterval:     30 * time.Second,
			ResolutionStrategy: "quorum-based",
		},
	}
}

// LoadFromEnvironment loads HA configuration from environment variables
func (c *Config) LoadFromEnvironment() error {
	logger := logging.NewLogger("debug")
	logger.Info("HA Config Loading - Starting LoadFromEnvironment")

	// Load deployment mode
	if mode := os.Getenv("CFGMS_HA_MODE"); mode != "" {
		switch strings.ToLower(mode) {
		case "single":
			c.Mode = SingleServerMode
		case "blue-green":
			c.Mode = BlueGreenMode
		case "cluster":
			c.Mode = ClusterMode
		default:
			return fmt.Errorf("invalid HA mode: %s", mode)
		}
	}

	// Load node configuration
	nodeID := os.Getenv("CFGMS_NODE_ID")
	if nodeID != "" {
		c.Node.ID = nodeID
	}

	if nodeName := os.Getenv("CFGMS_HA_NODE_NAME"); nodeName != "" {
		c.Node.Name = nodeName
	}

	if externalAddr := os.Getenv("CFGMS_HA_EXTERNAL_ADDRESS"); externalAddr != "" {
		c.Node.ExternalAddress = externalAddr
	}

	if internalAddr := os.Getenv("CFGMS_HA_INTERNAL_ADDRESS"); internalAddr != "" {
		c.Node.InternalAddress = internalAddr
	}

	// Load geographic configuration
	if region := os.Getenv("CFGMS_NODE_REGION"); region != "" {
		c.Node.Region = region
	}

	if az := os.Getenv("CFGMS_HA_AVAILABILITY_ZONE"); az != "" {
		c.Node.AvailabilityZone = az
	}

	// Load cluster configuration
	if expectedSize := os.Getenv("CFGMS_HA_CLUSTER_SIZE"); expectedSize != "" {
		if size, err := strconv.Atoi(expectedSize); err == nil {
			c.Cluster.ExpectedSize = size
		}
	}

	if minQuorum := os.Getenv("CFGMS_HA_MIN_QUORUM"); minQuorum != "" {
		if quorum, err := strconv.Atoi(minQuorum); err == nil {
			c.Cluster.MinQuorum = quorum
		}
	}

	if electionTimeout := os.Getenv("CFGMS_HA_ELECTION_TIMEOUT"); electionTimeout != "" {
		if timeout, err := time.ParseDuration(electionTimeout); err == nil {
			c.Cluster.ElectionTimeout = timeout
		}
	}

	if heartbeatInterval := os.Getenv("CFGMS_HA_HEARTBEAT_INTERVAL"); heartbeatInterval != "" {
		if interval, err := time.ParseDuration(heartbeatInterval); err == nil {
			c.Cluster.HeartbeatInterval = interval
		}
	}

	if nodeTimeout := os.Getenv("CFGMS_HA_NODE_TIMEOUT"); nodeTimeout != "" {
		if timeout, err := time.ParseDuration(nodeTimeout); err == nil {
			c.Cluster.Discovery.NodeTimeout = timeout
		}
	}

	if discoveryInterval := os.Getenv("CFGMS_HA_DISCOVERY_INTERVAL"); discoveryInterval != "" {
		if interval, err := time.ParseDuration(discoveryInterval); err == nil {
			c.Cluster.Discovery.Interval = interval
		}
	}

	if leaderLease := os.Getenv("CFGMS_HA_LEADER_LEASE_DURATION"); leaderLease != "" {
		if duration, err := time.ParseDuration(leaderLease); err == nil {
			c.Cluster.LeaderLeaseDuration = duration
		}
	}

	if candidateTimeout := os.Getenv("CFGMS_HA_CANDIDATE_TIMEOUT"); candidateTimeout != "" {
		if timeout, err := time.ParseDuration(candidateTimeout); err == nil {
			c.Cluster.CandidateTimeout = timeout
		}
	}

	if applyTimeout := os.Getenv("CFGMS_HA_APPLY_TIMEOUT"); applyTimeout != "" {
		if timeout, err := time.ParseDuration(applyTimeout); err == nil {
			c.Cluster.ApplyTimeout = timeout
		}
	}

	if healthInterval := os.Getenv("CFGMS_HA_HEALTH_CHECK_INTERVAL"); healthInterval != "" {
		if interval, err := time.ParseDuration(healthInterval); err == nil {
			c.HealthCheck.Interval = interval
		}
	}

	// Load discovery configuration
	if discoveryMethod := os.Getenv("CFGMS_HA_DISCOVERY_METHOD"); discoveryMethod != "" {
		c.Cluster.Discovery.Method = discoveryMethod
	}

	// Load cluster nodes for static discovery
	if clusterNodes := os.Getenv("CFGMS_HA_CLUSTER_NODES"); clusterNodes != "" {
		nodes := strings.Split(clusterNodes, ",")
		nodeConfigs := make([]map[string]interface{}, 0, len(nodes))

		for _, nodeStr := range nodes {
			nodeStr = strings.TrimSpace(nodeStr)
			if nodeStr == "" {
				continue
			}

			// Parse node format: "node-id:port" or "node-id"
			parts := strings.Split(nodeStr, ":")
			nodeID := strings.TrimSpace(parts[0])
			if nodeID == "" {
				continue
			}

			nodeConfig := map[string]interface{}{
				"id":     nodeID,
				"name":   nodeID,
				"region": "", // Will be set from individual node's region config
			}

			// If port is specified, construct address
			if len(parts) > 1 {
				port := strings.TrimSpace(parts[1])
				nodeConfig["address"] = fmt.Sprintf("%s:%s", nodeID, port)
			}

			nodeConfigs = append(nodeConfigs, nodeConfig)
		}

		if len(nodeConfigs) > 0 {
			if c.Cluster.Discovery.Config == nil {
				c.Cluster.Discovery.Config = make(map[string]interface{})
			}
			c.Cluster.Discovery.Config["nodes"] = nodeConfigs
		}
	}

	// Load failover configuration
	if failoverEnabled := os.Getenv("CFGMS_HA_FAILOVER_ENABLED"); failoverEnabled != "" {
		if enabled, err := strconv.ParseBool(failoverEnabled); err == nil {
			c.Failover.Enabled = enabled
		}
	}

	if failoverTimeout := os.Getenv("CFGMS_HA_FAILOVER_TIMEOUT"); failoverTimeout != "" {
		if timeout, err := time.ParseDuration(failoverTimeout); err == nil {
			c.Failover.Timeout = timeout
		}
	}

	// Load split-brain configuration
	if splitBrainEnabled := os.Getenv("CFGMS_HA_SPLIT_BRAIN_ENABLED"); splitBrainEnabled != "" {
		if enabled, err := strconv.ParseBool(splitBrainEnabled); err == nil {
			c.SplitBrain.Enabled = enabled
		}
	}

	logger.Info("HA Config Loading - Completed LoadFromEnvironment",
		"node_id", c.Node.ID,
		"node_region", c.Node.Region,
		"node_name", c.Node.Name,
		"mode", c.GetModeString(),
		"node_id_empty", c.Node.ID == "")

	return nil
}

// Validate validates the HA configuration
func (c *Config) Validate() error {
	if c.Node == nil {
		return fmt.Errorf("node configuration is required")
	}

	// Validate cluster configuration for cluster mode
	if c.Mode == ClusterMode {
		if c.Cluster == nil {
			return fmt.Errorf("cluster configuration is required for cluster mode")
		}

		if c.Cluster.ExpectedSize < 1 {
			return fmt.Errorf("cluster expected size must be at least 1")
		}

		if c.Cluster.MinQuorum < 1 || c.Cluster.MinQuorum > c.Cluster.ExpectedSize {
			return fmt.Errorf("min quorum must be between 1 and expected size")
		}

		if c.Cluster.ElectionTimeout <= 0 {
			return fmt.Errorf("election timeout must be positive")
		}

		if c.Cluster.HeartbeatInterval <= 0 {
			return fmt.Errorf("heartbeat interval must be positive")
		}

		if c.Cluster.LeaderLeaseDuration <= 0 {
			return fmt.Errorf("leader lease duration must be positive")
		}

		if c.Cluster.CandidateTimeout <= 0 {
			return fmt.Errorf("candidate timeout must be positive")
		}

		if c.Cluster.ApplyTimeout <= 0 {
			return fmt.Errorf("apply timeout must be positive")
		}

		if c.Cluster.Discovery == nil {
			return fmt.Errorf("discovery configuration is required for cluster mode")
		}
	}

	// Validate health check configuration
	if c.HealthCheck != nil {
		if c.HealthCheck.Interval <= 0 {
			return fmt.Errorf("health check interval must be positive")
		}

		if c.HealthCheck.Timeout <= 0 {
			return fmt.Errorf("health check timeout must be positive")
		}

		if c.HealthCheck.FailureThreshold < 1 {
			return fmt.Errorf("failure threshold must be at least 1")
		}

		if c.HealthCheck.SuccessThreshold < 1 {
			return fmt.Errorf("success threshold must be at least 1")
		}
	}

	// Validate failover configuration
	if c.Failover != nil && c.Failover.Enabled {
		if c.Failover.Timeout <= 0 {
			return fmt.Errorf("failover timeout must be positive")
		}

		if c.Failover.MaxDuration <= 0 {
			return fmt.Errorf("max failover duration must be positive")
		}

		if c.Failover.GracePeriod < 0 {
			return fmt.Errorf("grace period cannot be negative")
		}
	}

	return nil
}

// GetModeString returns the deployment mode as a string
func (c *Config) GetModeString() string {
	return c.Mode.String()
}

// IsClusterMode returns true if the deployment mode is cluster
func (c *Config) IsClusterMode() bool {
	return c.Mode == ClusterMode
}

// IsBlueGreenMode returns true if the deployment mode is blue-green
func (c *Config) IsBlueGreenMode() bool {
	return c.Mode == BlueGreenMode
}

// IsSingleServerMode returns true if the deployment mode is single server
func (c *Config) IsSingleServerMode() bool {
	return c.Mode == SingleServerMode
}