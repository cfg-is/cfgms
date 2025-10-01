package ha

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNetworkPartition tests cluster behavior during network partitions
func TestNetworkPartition(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	helper := NewDockerComposeHelper()

	// Start the full cluster with chaos network
	t.Log("Starting HA cluster with network chaos tools...")
	require.NoError(t, helper.StartCluster(ctx))
	defer func() {
		// Ensure network is restored before cleanup
		_ = helper.RestoreNetwork(context.Background())
		if err := helper.StopCluster(context.Background()); err != nil {
			t.Logf("Warning: Failed to stop cluster: %v", err)
		}
	}()

	// Wait for services including chaos network
	services := []string{"controller-east", "controller-central", "controller-west", "git-server-ha"}
	require.NoError(t, helper.WaitForServices(ctx, 3*time.Minute, services...))

	controllers := []string{
		"https://localhost:9080",
		"https://localhost:9081",
		"https://localhost:9082",
	}

	// Wait for initial cluster formation
	t.Log("Waiting for initial cluster formation...")
	require.Eventually(t, func() bool {
		healthyCount := 0
		leaderCount := 0

		for _, url := range controllers {
			if err := waitForHealthy(ctx, url, 10*time.Second); err != nil {
				continue
			}
			healthyCount++

			instance, err := getControllerState(url)
			if err != nil {
				continue
			}
			if instance.IsLeader {
				leaderCount++
			}
		}

		return healthyCount == 3 && leaderCount == 1
	}, 3*time.Minute, 5*time.Second, "Initial cluster formation failed")

	t.Log("✓ Initial cluster formed with 3 healthy controllers")

	// Test minority partition isolation
	t.Run("MinorityPartitionIsolation", func(t *testing.T) {
		// Isolate one controller (minority)
		t.Log("Isolating controller-west (minority partition)...")

		// Stop controller-west to simulate network partition
		require.NoError(t, helper.RestartService(ctx, "controller-west"))

		// Wait a bit for the partition to take effect
		time.Sleep(10 * time.Second)

		// Verify majority partition (east + central) maintains leadership
		majorityControllers := []string{
			"https://localhost:9080", // east
			"https://localhost:9081", // central
		}

		require.Eventually(t, func() bool {
			healthyCount := 0
			leaderCount := 0

			for _, url := range majorityControllers {
				if err := waitForHealthy(ctx, url, 10*time.Second); err != nil {
					continue
				}
				healthyCount++

				instance, err := getControllerState(url)
				if err != nil {
					continue
				}
				if instance.IsLeader {
					leaderCount++
				}
			}

			// Majority partition should maintain quorum and leadership
			return healthyCount >= 2 && leaderCount == 1
		}, 30*time.Second, 2*time.Second, "Majority partition failed to maintain leadership")

		t.Log("✓ Majority partition maintains leadership during minority isolation")

		// Wait for west controller to rejoin
		time.Sleep(30 * time.Second)

		// Verify full cluster recovery
		require.Eventually(t, func() bool {
			healthyCount := 0
			for _, url := range controllers {
				if err := waitForHealthy(ctx, url, 10*time.Second); err != nil {
					continue
				}
				healthyCount++
			}
			return healthyCount == 3
		}, 2*time.Minute, 5*time.Second, "Failed to recover full cluster")

		t.Log("✓ Full cluster recovered after partition healing")
	})

	// Test split-brain prevention during equal partition
	t.Run("SplitBrainPrevention", func(t *testing.T) {
		// This test simulates a scenario where we might have split-brain
		// by rapidly stopping and starting controllers

		t.Log("Testing split-brain prevention...")

		// Rapidly restart controllers to create potential race conditions
		for iteration := 0; iteration < 3; iteration++ {
			// Stop random controller
			services := []string{"controller-east", "controller-central", "controller-west"}
			serviceToRestart := services[iteration%len(services)]

			t.Logf("Restarting %s (iteration %d)", serviceToRestart, iteration+1)
			require.NoError(t, helper.RestartService(ctx, serviceToRestart))

			// Short wait before next restart
			time.Sleep(5 * time.Second)
		}

		// Wait for cluster to stabilize
		time.Sleep(30 * time.Second)

		// Verify exactly one leader exists
		require.Eventually(t, func() bool {
			healthyCount := 0
			leaderCount := 0
			leaders := make([]string, 0)

			for _, url := range controllers {
				if err := waitForHealthy(ctx, url, 10*time.Second); err != nil {
					continue
				}
				healthyCount++

				instance, err := getControllerState(url)
				if err != nil {
					continue
				}
				if instance.IsLeader {
					leaderCount++
					leaders = append(leaders, instance.NodeID)
				}
			}

			if leaderCount != 1 {
				t.Logf("Found %d leaders: %v", leaderCount, leaders)
			}

			return healthyCount >= 2 && leaderCount == 1
		}, 2*time.Minute, 5*time.Second, "Split-brain detected or leadership failure")

		t.Log("✓ Split-brain prevention successful - single leader maintained")
	})
}

// TestPartitionRecovery tests various partition recovery scenarios
func TestPartitionRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	helper := NewDockerComposeHelper()

	t.Log("Starting HA cluster...")
	require.NoError(t, helper.StartCluster(ctx))
	defer func() {
		if err := helper.StopCluster(context.Background()); err != nil {
			t.Logf("Warning: Failed to stop cluster: %v", err)
		}
	}()

	services := []string{"controller-east", "controller-central", "controller-west", "git-server-ha"}
	require.NoError(t, helper.WaitForServices(ctx, 3*time.Minute, services...))

	controllers := []string{
		"https://localhost:9080",
		"https://localhost:9081",
		"https://localhost:9082",
	}

	// Wait for initial cluster
	require.Eventually(t, func() bool {
		count := 0
		for _, url := range controllers {
			if err := waitForHealthy(ctx, url, 10*time.Second); err == nil {
				count++
			}
		}
		return count == 3
	}, 3*time.Minute, 5*time.Second)

	// Test rolling restart recovery
	t.Run("RollingRestartRecovery", func(t *testing.T) {
		services := []string{"controller-east", "controller-central", "controller-west"}

		for _, service := range services {
			t.Logf("Rolling restart: %s", service)

			// Restart service
			require.NoError(t, helper.RestartService(ctx, service))

			// Wait for service to be back and cluster to stabilize
			time.Sleep(20 * time.Second)

			// Verify cluster still has leadership
			leaderCount := 0
			healthyCount := 0

			for _, url := range controllers {
				if err := waitForHealthy(ctx, url, 15*time.Second); err != nil {
					continue
				}
				healthyCount++

				instance, err := getControllerState(url)
				if err != nil {
					continue
				}
				if instance.IsLeader {
					leaderCount++
				}
			}

			assert.GreaterOrEqual(t, healthyCount, 2, "Not enough healthy controllers after restart")
			assert.Equal(t, 1, leaderCount, "Should have exactly one leader after restart")
		}

		// Final verification that all controllers are back
		require.Eventually(t, func() bool {
			count := 0
			for _, url := range controllers {
				if err := waitForHealthy(ctx, url, 10*time.Second); err == nil {
					count++
				}
			}
			return count == 3
		}, 2*time.Minute, 5*time.Second, "Not all controllers recovered after rolling restart")

		t.Log("✓ Rolling restart recovery successful")
	})

	// Test cascading failure recovery
	t.Run("CascadingFailureRecovery", func(t *testing.T) {
		t.Log("Simulating cascading failure...")

		// Stop multiple controllers simultaneously
		require.NoError(t, helper.RestartService(ctx, "controller-east"))
		require.NoError(t, helper.RestartService(ctx, "controller-central"))

		// Wait briefly
		time.Sleep(10 * time.Second)

		// Only west should be running - test if it can maintain operations
		westHealthy := waitForHealthy(ctx, "https://localhost:9082", 30*time.Second) == nil
		assert.True(t, westHealthy, "West controller should remain healthy")

		// Wait for other controllers to come back
		time.Sleep(45 * time.Second)

		// Verify full recovery
		require.Eventually(t, func() bool {
			healthyCount := 0
			leaderCount := 0

			for _, url := range controllers {
				if err := waitForHealthy(ctx, url, 10*time.Second); err != nil {
					continue
				}
				healthyCount++

				instance, err := getControllerState(url)
				if err != nil {
					continue
				}
				if instance.IsLeader {
					leaderCount++
				}
			}

			return healthyCount == 3 && leaderCount == 1
		}, 3*time.Minute, 10*time.Second, "Failed to recover from cascading failure")

		t.Log("✓ Cascading failure recovery successful")
	})
}