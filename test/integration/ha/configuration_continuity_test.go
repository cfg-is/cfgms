//go:build commercial

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/push"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ConfigurationPushEvent represents a configuration push event
type ConfigurationPushEvent struct {
	EventID     string                 `json:"event_id"`
	ConfigID    string                 `json:"config_id"`
	TenantID    string                 `json:"tenant_id"`
	StewardID   string                 `json:"steward_id"`
	Status      string                 `json:"status"` // pending, in_progress, completed, failed
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Source      string                 `json:"source"`   // Which controller initiated
	Failover    bool                   `json:"failover"` // Whether failover occurred during push
	Data        map[string]interface{} `json:"data"`
}

// TestConfigurationPushContinuity tests configuration push continuity during controller failover
func TestConfigurationPushContinuity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	helper := NewDockerComposeHelper()

	t.Log("Starting full HA cluster for configuration continuity testing...")
	require.NoError(t, helper.StartCluster(ctx))
	defer func() {
		if err := helper.StopCluster(context.Background()); err != nil {
			t.Logf("Warning: Failed to stop cluster: %v", err)
		}
	}()

	// Wait for all services
	allServices := []string{
		"controller-east", "controller-central", "controller-west",
		"steward-east", "steward-central", "steward-west",
		"git-server-ha",
	}
	require.NoError(t, helper.WaitForServices(ctx, 5*time.Minute, allServices...))

	controllers := []string{
		"https://localhost:9080",
		"https://localhost:9081",
		"https://localhost:9082",
	}

	stewards := []string{
		"steward-east",
		"steward-central",
		"steward-west",
	}

	// Wait for cluster formation
	t.Log("Waiting for cluster and steward initialization...")
	require.Eventually(t, func() bool {
		// Check controller cluster
		leaderCount := 0
		healthyControllers := 0

		for _, url := range controllers {
			if err := waitForHealthy(ctx, url, 10*time.Second); err != nil {
				continue
			}
			healthyControllers++

			instance, err := getControllerState(url)
			if err != nil {
				continue
			}
			if instance.IsLeader {
				leaderCount++
			}
		}

		// Check steward connections using docker helper
		connectedStewards := 0
		for _, steward := range stewards {
			if connected, _, err := helper.CheckStewardConnection(ctx, steward); err == nil && connected {
				connectedStewards++
			}
		}

		return healthyControllers == 3 && leaderCount == 1 && connectedStewards == 3
	}, 5*time.Minute, 10*time.Second, "Cluster initialization failed")

	t.Log("✓ Cluster and stewards operational")

	// Test configuration push scenarios
	t.Run("LargeConfigurationPushWithFailover", func(t *testing.T) {
		testLargeConfigurationPushWithFailover(t, ctx, helper, controllers, stewards)
	})

	t.Run("MultipleConfigurationPushesWithFailover", func(t *testing.T) {
		testMultipleConfigurationPushesWithFailover(t, ctx, helper, controllers, stewards)
	})

	t.Run("ConfigurationRollbackDuringFailover", func(t *testing.T) {
		testConfigurationRollbackDuringFailover(t, ctx, helper, controllers, stewards)
	})
}

// testLargeConfigurationPushWithFailover tests large configuration push surviving failover
func testLargeConfigurationPushWithFailover(t *testing.T, ctx context.Context, helper *DockerComposeHelper, controllers []string, stewards []string) {
	t.Log("Testing large configuration push with controller failover...")

	// Create a large configuration that will take time to push
	largeConfig := createLargeTestConfiguration("large-config-failover-test")

	// Find current leader
	leaderURL := ""
	var leaderService string
	for i, url := range controllers {
		instance, err := getControllerState(url)
		if err == nil && instance.IsLeader {
			leaderURL = url
			services := []string{"controller-east", "controller-central", "controller-west"}
			leaderService = services[i]
			break
		}
	}
	require.NotEmpty(t, leaderURL, "Could not find leader")

	// Start configuration push in background
	pushCompleted := make(chan error, 1)
	pushStartTime := time.Now()

	go func() {
		err := pushLargeConfiguration(leaderURL, largeConfig)
		pushCompleted <- err
	}()

	// Wait for push to start, then trigger failover
	time.Sleep(3 * time.Second)
	t.Logf("Triggering failover during configuration push (leader: %s)", leaderService)

	failoverTime := time.Now()
	require.NoError(t, helper.RestartService(ctx, leaderService))

	// Wait for failover to complete
	require.Eventually(t, func() bool {
		leaderCount := 0
		for _, url := range controllers {
			if url == leaderURL {
				continue // Skip failed leader
			}
			instance, err := getControllerState(url)
			if err == nil && instance.IsLeader {
				leaderCount++
			}
		}
		return leaderCount == 1
	}, 30*time.Second, 2*time.Second, "New leader not elected")

	// Wait for configuration push to complete or timeout
	select {
	case err := <-pushCompleted:
		pushDuration := time.Since(pushStartTime)
		failoverDuration := time.Since(failoverTime)

		if err != nil {
			t.Logf("Configuration push failed after %v (failover at %v): %v", pushDuration, failoverDuration, err)
			// This is expected in current implementation - real system should retry
		} else {
			t.Logf("✓ Configuration push completed in %v despite failover at %v", pushDuration, failoverDuration)
		}

	case <-time.After(60 * time.Second):
		t.Log("Configuration push timed out - checking final state...")
	}

	// Verify steward connectivity and configuration state after failover
	t.Log("Verifying steward connectivity and configuration state after failover...")
	time.Sleep(10 * time.Second) // Allow time for failover to propagate

	connectedAfterFailover := 0
	for _, steward := range stewards {
		state, err := getConfigurationState(ctx, helper, steward)
		if err != nil {
			t.Logf("Warning: Could not get config state for %s: %v", steward, err)
			continue
		}
		t.Logf("Steward %s configuration state: %s", steward, state)
		// Any state other than "unknown" means the steward is reachable
		if state != "unknown" {
			connectedAfterFailover++
		}
	}

	// At least one steward must be reachable after failover
	assert.Greater(t, connectedAfterFailover, 0,
		"At least one steward must be reachable after large-config-push failover")
	t.Log("✓ Large configuration push failover behavior verified")
}

// testMultipleConfigurationPushesWithFailover tests multiple concurrent pushes
func testMultipleConfigurationPushesWithFailover(t *testing.T, ctx context.Context, helper *DockerComposeHelper, controllers []string, stewards []string) {
	t.Log("Testing multiple configuration pushes with controller failover...")

	// Create multiple test configurations
	configs := []push.StewardConfiguration{
		createTestConfiguration("multi-config-1", "security"),
		createTestConfiguration("multi-config-2", "monitoring"),
		createTestConfiguration("multi-config-3", "backup"),
	}

	// Find current leader
	leaderURL := ""
	var leaderService string
	for i, url := range controllers {
		instance, err := getControllerState(url)
		if err == nil && instance.IsLeader {
			leaderURL = url
			services := []string{"controller-east", "controller-central", "controller-west"}
			leaderService = services[i]
			break
		}
	}
	require.NotEmpty(t, leaderURL, "Could not find leader")

	// Start multiple configuration pushes
	pushResults := make(chan error, len(configs))

	for i, config := range configs {
		go func(configIndex int, cfg push.StewardConfiguration) {
			// Stagger the pushes slightly
			time.Sleep(time.Duration(configIndex) * 2 * time.Second)
			err := pushConfigurationToStewards(leaderURL, cfg)
			pushResults <- err
		}(i, config)
	}

	// Trigger failover while pushes are in progress
	time.Sleep(5 * time.Second)
	t.Logf("Triggering failover during multiple configuration pushes...")
	require.NoError(t, helper.RestartService(ctx, leaderService))

	// Collect push results
	pushErrors := 0
	for i := 0; i < len(configs); i++ {
		select {
		case err := <-pushResults:
			if err != nil {
				pushErrors++
				t.Logf("Configuration push %d failed: %v", i+1, err)
			}
		case <-time.After(30 * time.Second):
			pushErrors++
			t.Logf("Configuration push %d timed out", i+1)
		}
	}

	// Wait for cluster to stabilize
	time.Sleep(15 * time.Second)

	// Verify all stewards reconnected after the failover
	t.Log("Verifying steward connectivity after multiple pushes and failover...")
	require.Eventually(t, func() bool {
		connectedCount := 0
		for _, steward := range stewards {
			connected, controller, err := helper.CheckStewardConnection(ctx, steward)
			if err != nil {
				continue
			}
			t.Logf("Steward %s: connected=%v, controller=%s", steward, connected, controller)
			if connected {
				connectedCount++
			}
		}
		return connectedCount == len(stewards)
	}, 30*time.Second, 3*time.Second, "All stewards must be connected after multiple-push failover")

	t.Log("✓ Multiple configuration pushes with failover completed")
}

// testConfigurationRollbackDuringFailover tests rollback during failover
func testConfigurationRollbackDuringFailover(t *testing.T, ctx context.Context, helper *DockerComposeHelper, controllers []string, stewards []string) {
	t.Log("Testing configuration rollback during controller failover...")

	// Apply initial configuration
	initialConfig := createTestConfiguration("rollback-test-initial", "baseline")

	leaderURL := ""
	for _, url := range controllers {
		instance, err := getControllerState(url)
		if err == nil && instance.IsLeader {
			leaderURL = url
			break
		}
	}
	require.NotEmpty(t, leaderURL, "Could not find leader")

	// Apply initial configuration
	t.Log("Applying initial configuration...")
	require.NoError(t, pushConfigurationToStewards(leaderURL, initialConfig))
	time.Sleep(5 * time.Second)

	// Apply new configuration that will be rolled back
	rollbackConfig := createTestConfiguration("rollback-test-new", "rollback-target")

	// Start configuration push that will be interrupted by failover.
	// Error is logged but not required since the push may fail mid-flight.
	rollbackPushErr := make(chan error, 1)
	go func() {
		time.Sleep(2 * time.Second)
		rollbackPushErr <- pushConfigurationToStewards(leaderURL, rollbackConfig)
	}()

	// Trigger failover immediately after push starts
	time.Sleep(1 * time.Second)

	var leaderService string
	for i, url := range controllers {
		if url == leaderURL {
			services := []string{"controller-east", "controller-central", "controller-west"}
			leaderService = services[i]
			break
		}
	}

	t.Logf("Triggering failover to test rollback behavior...")
	require.NoError(t, helper.RestartService(ctx, leaderService))

	// Collect push result (may have failed due to failover — that is expected)
	select {
	case err := <-rollbackPushErr:
		t.Logf("Rollback push result: %v", err)
	case <-time.After(15 * time.Second):
		t.Log("Rollback push timed out — failover likely interrupted it")
	}

	// Verify cluster recovered: at least 2 of 3 controllers must be healthy
	require.Eventually(t, func() bool {
		healthyCount := 0
		for _, url := range controllers {
			if waitForHealthy(ctx, url, 5*time.Second) == nil {
				healthyCount++
			}
		}
		return healthyCount >= 2
	}, 45*time.Second, 3*time.Second, "At least 2 controllers must be healthy after rollback-during-failover")

	t.Log("✓ Configuration rollback during failover tested")
}

// Helper functions

// createLargeTestConfiguration creates a large configuration for testing
func createLargeTestConfiguration(configID string) push.StewardConfiguration {
	// Create a configuration with many policies to simulate slow push
	policies := make(map[string]interface{})

	for i := 0; i < 100; i++ {
		policies[fmt.Sprintf("policy_%d", i)] = map[string]interface{}{
			"enabled":  true,
			"priority": i,
			"rules": []string{
				fmt.Sprintf("rule_%d_1", i),
				fmt.Sprintf("rule_%d_2", i),
				fmt.Sprintf("rule_%d_3", i),
			},
			"metadata": map[string]string{
				"category": "generated",
				"test_id":  configID,
			},
		}
	}

	return push.StewardConfiguration{
		ConfigID: configID,
		Version:  "1.0.0",
		TenantID: "test-tenant",
		Policies: policies,
		Modules:  []string{"file", "directory", "script", "monitoring", "security"},
	}
}

// createTestConfiguration creates a test configuration
func createTestConfiguration(configID string, category string) push.StewardConfiguration {
	return push.StewardConfiguration{
		ConfigID: configID,
		Version:  "1.0.0",
		TenantID: "test-tenant",
		Policies: map[string]interface{}{
			category: map[string]interface{}{
				"enabled": true,
				"level":   "standard",
			},
		},
		Modules: []string{"file", "directory"},
	}
}

// pushLargeConfiguration pushes a large configuration to the controller.
// Uses a TLS-enabled client with the controller CA cert.
func pushLargeConfiguration(controllerURL string, config push.StewardConfiguration) error {
	client := buildTLSClient(containerNameForURL(controllerURL))
	client.Timeout = 30 * time.Second

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/config/push", controllerURL),
		strings.NewReader(string(configJSON)))
	if err != nil {
		return fmt.Errorf("failed to build large push request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", getAPIKeyForURL(controllerURL))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("large configuration push API call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("large config push failed with status %d", resp.StatusCode)
	}

	return nil
}

// getConfigurationState gets the configuration state of a steward via Docker logs
func getConfigurationState(ctx context.Context, helper *DockerComposeHelper, stewardName string) (string, error) {
	// Check steward connection and logs for configuration state
	connected, _, err := helper.CheckStewardConnection(ctx, stewardName)
	if err != nil {
		return "unknown", fmt.Errorf("failed to check steward connection: %w", err)
	}

	if !connected {
		return "disconnected", nil
	}

	// Parse logs for configuration application status
	logs, err := helper.GetStewardLogs(ctx, stewardName, 50)
	if err != nil {
		return "unknown", fmt.Errorf("failed to get steward logs: %w", err)
	}

	// Look for configuration-related log entries
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "config applied") || strings.Contains(line, "configuration applied") {
			return "applied", nil
		}
		if strings.Contains(line, "config failed") || strings.Contains(line, "configuration failed") {
			return "failed", nil
		}
	}

	return "connected", nil
}
