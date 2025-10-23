//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2025 CFGMS Contributors
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

// NOTE: All type definitions (Config, NodeConfig, ClusterConfig, etc.) are now in types.go
// This file contains only the commercial-specific implementation methods.

// DefaultConfig returns a Config with reasonable defaults
// This function must match the type definitions in types.go
func DefaultConfig() *Config {
	return &Config{
		Mode: SingleServerMode,
		Node: NodeConfig{
			Capabilities: []string{"config", "rbac", "monitoring", "workflow"},
		},
		Cluster: ClusterConfig{
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
				Enabled:           true,
				SyncInterval:      5 * time.Second,
				StateTimeout:      300 * time.Second, // 5 minutes
				ReplicationFactor: 3,
				MaxStateSize:      1024 * 1024, // 1MB
			},
		},
		HealthCheck: &HealthCheckConfig{
			Enabled:          true,
			Interval:         10 * time.Second,
			Timeout:          5 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 2,
			EnableInternal:   true,
			EnableExternal:   true,
		},
		Failover: &FailoverConfig{
			Enabled:             true,
			DetectionInterval:   30 * time.Second,
			FailureThreshold:    3,
			RecoveryThreshold:   2,
			MaxFailoversPerHour: 10,
			Timeout:             30 * time.Second,
			MaxDuration:         5 * time.Minute,
			GracePeriod:         10 * time.Second,
			MaxSessionMigration: 1000,
		},
		LoadBalancing: &LoadBalancingConfig{
			Strategy:           HealthBasedStrategy,
			HealthCheckEnabled: true,
			SessionAffinity:    true,
			HealthBased: &HealthBasedConfig{
				MinHealthScore:     0.7,
				HealthWeightFactor: 1.0,
			},
			ConnectionBased: &ConnectionBasedConfig{
				MaxConnectionsPerNode: 1000,
				ConnectionThreshold:   0.8,
			},
			Geographic: &GeographicLoadBalancingConfig{
				EnableRegionAffinity:    true,
				RegionAffinityWeight:    0.8,
				LatencyWeightFactor:     0.5,
				MaxLatencyThreshold:     250 * time.Millisecond,
				CrossRegionFallback:     true,
				RegionalCapacityWeights: make(map[string]float64),
			},
		},
		SplitBrain: &SplitBrainConfig{
			Enabled:            true,
			DetectionInterval:  15 * time.Second,
			QuorumCheck:        true,
			AutoResolve:        true,
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

	// NOTE: InternalAddress field removed from types.go (OSS simplification)

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

	if failoverDetectionInterval := os.Getenv("CFGMS_HA_FAILOVER_DETECTION_INTERVAL"); failoverDetectionInterval != "" {
		if interval, err := time.ParseDuration(failoverDetectionInterval); err == nil {
			c.Failover.DetectionInterval = interval
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
// Updated to match types.go structure (value types, not pointers)
func (c *Config) Validate() error {
	// Node is a value type, always exists - just validate ID
	if c.Node.ID == "" && c.Mode != SingleServerMode {
		return fmt.Errorf("node ID is required for cluster/blue-green modes")
	}

	// Validate cluster configuration for cluster mode
	if c.Mode == ClusterMode {
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

	// Validate health check configuration (HealthCheck is now a pointer)
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

	// Validate failover configuration (Failover is now a pointer)
	if c.Failover != nil && c.Failover.Enabled {
		if c.Failover.DetectionInterval <= 0 {
			return fmt.Errorf("failover detection interval must be positive")
		}

		if c.Failover.FailureThreshold < 1 {
			return fmt.Errorf("failover failure threshold must be at least 1")
		}

		if c.Failover.RecoveryThreshold < 1 {
			return fmt.Errorf("failover recovery threshold must be at least 1")
		}

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
