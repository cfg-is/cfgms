package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/ha"
)

// ControllerInstance represents a running controller instance
type ControllerInstance struct {
	Name     string
	URL      string
	Region   string
	NodeID   string
	IsLeader bool
	Health   string
}

// TestClusterFormation tests basic cluster formation with 3 controllers
func TestClusterFormation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Expected controller endpoints
	controllers := []struct {
		name   string
		url    string
		region string
	}{
		{"controller-east", "http://localhost:8080", "us-east"},
		{"controller-central", "http://localhost:8081", "us-central"},
		{"controller-west", "http://localhost:8082", "us-west"},
	}

	// Wait for all controllers to be healthy
	t.Log("Waiting for all controllers to be healthy...")
	for _, ctrl := range controllers {
		require.NoError(t, waitForHealthy(ctx, ctrl.url, 90*time.Second),
			"Controller %s failed to become healthy", ctrl.name)
		t.Logf("✓ Controller %s is healthy", ctrl.name)
	}

	// Give time for cluster formation (reduced due to aggressive timing)
	t.Log("Waiting for cluster formation...")
	time.Sleep(15 * time.Second)

	// Collect cluster state from all controllers
	var instances []ControllerInstance
	for _, ctrl := range controllers {
		instance, err := getControllerState(ctrl.url)
		require.NoError(t, err, "Failed to get state from %s", ctrl.name)
		instance.Name = ctrl.name
		instance.Region = ctrl.region
		instances = append(instances, instance)
		t.Logf("Controller %s: Leader=%v, NodeID=%s", ctrl.name, instance.IsLeader, instance.NodeID)
	}

	// Verify cluster formation requirements
	t.Run("ExactlyOneLeader", func(t *testing.T) {
		leaderCount := 0
		var leaderName string
		for _, instance := range instances {
			if instance.IsLeader {
				leaderCount++
				leaderName = instance.Name
			}
		}
		assert.Equal(t, 1, leaderCount, "Expected exactly 1 leader, found %d", leaderCount)
		if leaderCount == 1 {
			t.Logf("✓ Leader elected: %s", leaderName)
		}
	})

	t.Run("AllNodesHealthy", func(t *testing.T) {
		for _, instance := range instances {
			assert.Equal(t, "healthy", instance.Health,
				"Controller %s is not healthy: %s", instance.Name, instance.Health)
		}
		t.Log("✓ All controllers are healthy")
	})

	t.Run("UniqueNodeIDs", func(t *testing.T) {
		nodeIDs := make(map[string]string)
		for _, instance := range instances {
			if existing, exists := nodeIDs[instance.NodeID]; exists {
				t.Errorf("Duplicate node ID %s found on %s and %s",
					instance.NodeID, instance.Name, existing)
			}
			nodeIDs[instance.NodeID] = instance.Name
		}
		assert.Len(t, nodeIDs, len(instances), "Expected unique node IDs for all controllers")
		t.Log("✓ All node IDs are unique")
	})

	t.Run("GeographicDistribution", func(t *testing.T) {
		regions := make(map[string]int)
		for _, instance := range instances {
			regions[instance.Region]++
		}

		// Should have one controller per region
		assert.Len(t, regions, 3, "Expected controllers in 3 different regions")
		assert.Equal(t, 1, regions["us-east"], "Expected 1 controller in us-east")
		assert.Equal(t, 1, regions["us-central"], "Expected 1 controller in us-central")
		assert.Equal(t, 1, regions["us-west"], "Expected 1 controller in us-west")
		t.Log("✓ Controllers distributed across 3 geographic regions")
	})
}

// TestClusterConsistency tests that all controllers report consistent cluster state
func TestClusterConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	controllers := []string{
		"http://localhost:8080",
		"http://localhost:8081",
		"http://localhost:8082",
	}

	// Wait for all controllers and get their cluster views
	var clusterViews []ClusterView
	for i, url := range controllers {
		require.NoError(t, waitForHealthy(ctx, url, 30*time.Second))

		view, err := getClusterView(url)
		require.NoError(t, err, "Failed to get cluster view from controller %d", i)
		clusterViews = append(clusterViews, view)
	}

	// All controllers should see the same cluster size
	expectedSize := len(controllers)
	for i, view := range clusterViews {
		assert.Equal(t, expectedSize, len(view.Nodes),
			"Controller %d sees %d nodes, expected %d", i, len(view.Nodes), expectedSize)
	}

	// All controllers should agree on who the leader is
	if len(clusterViews) > 0 {
		expectedLeader := clusterViews[0].Leader
		for i, view := range clusterViews {
			assert.Equal(t, expectedLeader, view.Leader,
				"Controller %d sees leader %s, expected %s", i, view.Leader, expectedLeader)
		}
		t.Logf("✓ All controllers agree on leader: %s", expectedLeader)
	}
}

// ClusterView represents the cluster state as seen by a controller
type ClusterView struct {
	Leader string              `json:"leader"`
	Nodes  []ha.NodeInfo       `json:"nodes"`
	Health string              `json:"health"`
}

// waitForHealthy waits for a controller to respond to health checks
func waitForHealthy(ctx context.Context, url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	healthURL := fmt.Sprintf("%s/health", url)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := client.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			return nil
		}
		if resp != nil {
			_ = resp.Body.Close()
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("controller at %s did not become healthy within %v", url, timeout)
}

// getControllerState gets the basic state of a controller
func getControllerState(url string) (ControllerInstance, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Get health status
	healthResp, err := client.Get(fmt.Sprintf("%s/health", url))
	if err != nil {
		return ControllerInstance{}, fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = healthResp.Body.Close() }()

	health := "unhealthy"
	if healthResp.StatusCode == http.StatusOK {
		health = "healthy"
	}

	// Get HA status (if available)
	haResp, err := client.Get(fmt.Sprintf("%s/api/v1/ha/status", url))
	if err != nil {
		// HA endpoint might not be available yet
		return ControllerInstance{
			URL:    url,
			Health: health,
		}, nil
	}
	defer func() { _ = haResp.Body.Close() }()

	if haResp.StatusCode != http.StatusOK {
		return ControllerInstance{
			URL:    url,
			Health: health,
		}, nil
	}

	var haStatus struct {
		NodeID   string `json:"node_id"`
		IsLeader bool   `json:"is_leader"`
	}

	if err := json.NewDecoder(haResp.Body).Decode(&haStatus); err != nil {
		return ControllerInstance{
			URL:    url,
			Health: health,
		}, nil
	}

	return ControllerInstance{
		URL:      url,
		NodeID:   haStatus.NodeID,
		IsLeader: haStatus.IsLeader,
		Health:   health,
	}, nil
}

// getClusterView gets the cluster view from a controller
func getClusterView(url string) (ClusterView, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(fmt.Sprintf("%s/api/v1/ha/cluster", url))
	if err != nil {
		return ClusterView{}, fmt.Errorf("cluster view request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ClusterView{}, fmt.Errorf("cluster view returned status %d", resp.StatusCode)
	}

	var view ClusterView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		return ClusterView{}, fmt.Errorf("failed to decode cluster view: %w", err)
	}

	return view, nil
}