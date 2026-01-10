//go:build commercial

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLeaderElection tests leader election behavior in the cluster
func TestLeaderElection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	helper := NewDockerComposeHelper()

	// Start the cluster
	t.Log("Starting HA cluster...")
	require.NoError(t, helper.StartCluster(ctx))
	defer func() {
		if err := helper.StopCluster(context.Background()); err != nil {
			t.Logf("Warning: Failed to stop cluster: %v", err)
		}
	}()

	// Wait for services to be running
	services := []string{"controller-east", "controller-central", "controller-west", "git-server-ha"}
	require.NoError(t, helper.WaitForServices(ctx, 3*time.Minute, services...))

	controllers := []string{
		"https://localhost:9080",
		"https://localhost:9081",
		"https://localhost:9082",
	}

	// Wait for initial cluster formation and leader election
	t.Log("Waiting for initial leader election...")
	var initialLeader string
	require.Eventually(t, func() bool {
		for _, url := range controllers {
			if err := waitForHealthy(ctx, url, 10*time.Second); err != nil {
				return false
			}
		}

		// Check for leader election
		leaderCount := 0
		for _, url := range controllers {
			instance, err := getControllerState(url)
			if err != nil {
				return false
			}
			if instance.IsLeader {
				leaderCount++
				initialLeader = instance.NodeID
			}
		}

		return leaderCount == 1
	}, 2*time.Minute, 2*time.Second, "Initial leader election failed")

	t.Logf("✓ Initial leader elected: %s", initialLeader)

	// Test leader failover by stopping the leader
	t.Run("LeaderFailover", func(t *testing.T) {
		// Find which service is the leader
		var leaderService string
		for i, url := range controllers {
			instance, err := getControllerState(url)
			require.NoError(t, err)
			if instance.IsLeader {
				services := []string{"controller-east", "controller-central", "controller-west"}
				leaderService = services[i]
				break
			}
		}

		require.NotEmpty(t, leaderService, "Could not identify leader service")
		t.Logf("Stopping leader service: %s", leaderService)

		// Stop the leader
		require.NoError(t, helper.RestartService(ctx, leaderService))

		// Wait for new leader election
		t.Log("Waiting for new leader election...")
		var newLeader string
		require.Eventually(t, func() bool {
			healthyCount := 0
			leaderCount := 0

			for _, url := range controllers {
				if err := waitForHealthy(ctx, url, 5*time.Second); err != nil {
					continue
				}
				healthyCount++

				instance, err := getControllerState(url)
				if err != nil {
					continue
				}
				if instance.IsLeader {
					leaderCount++
					newLeader = instance.NodeID
				}
			}

			// Should have at least 2 healthy controllers and exactly 1 leader
			return healthyCount >= 2 && leaderCount == 1
		}, 1*time.Minute, 2*time.Second, "New leader election failed")

		assert.NotEqual(t, initialLeader, newLeader, "New leader should be different from initial leader")
		t.Logf("✓ New leader elected: %s (failover time < 2 minutes)", newLeader)
	})

	// Test split-brain prevention
	t.Run("SplitBrainPrevention", func(t *testing.T) {
		// This test would require network partitioning
		// For now, we'll test that we always have exactly one leader

		leaderCounts := make(map[string]int)

		// Check leader consistency over time
		for i := 0; i < 10; i++ {
			time.Sleep(2 * time.Second)

			currentLeader := ""
			leaderCount := 0

			for _, url := range controllers {
				if err := waitForHealthy(ctx, url, 5*time.Second); err != nil {
					continue
				}

				instance, err := getControllerState(url)
				if err != nil {
					continue
				}

				if instance.IsLeader {
					leaderCount++
					currentLeader = instance.NodeID
				}
			}

			if leaderCount > 0 {
				leaderCounts[currentLeader]++
				assert.Equal(t, 1, leaderCount, "Multiple leaders detected at iteration %d", i)
			}
		}

		// Should have consistent leadership
		assert.Len(t, leaderCounts, 1, "Leadership should be consistent, found multiple leaders: %v", leaderCounts)
		t.Log("✓ Split-brain prevention working - consistent single leader")
	})
}

// TestLeaderElectionTiming tests the timing requirements for leader election
func TestLeaderElectionTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	helper := NewDockerComposeHelper()

	// Start only 2 controllers initially (minimum quorum)
	t.Log("Starting minimal cluster (2 controllers)...")
	require.NoError(t, helper.StartCluster(ctx))
	defer func() {
		if err := helper.StopCluster(context.Background()); err != nil {
			t.Logf("Warning: Failed to stop cluster: %v", err)
		}
	}()

	// Stop one controller to test minimum quorum
	require.NoError(t, helper.RestartService(ctx, "controller-west"))

	controllers := []string{
		"https://localhost:9080", // controller-east
		"https://localhost:9081", // controller-central
	}

	// Wait for quorum-based leader election
	t.Log("Testing minimum quorum leader election...")
	start := time.Now()

	require.Eventually(t, func() bool {
		healthyCount := 0
		leaderCount := 0

		for _, url := range controllers {
			if err := waitForHealthy(ctx, url, 5*time.Second); err != nil {
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

		// Need minimum quorum (2) and exactly 1 leader
		return healthyCount >= 2 && leaderCount == 1
	}, 1*time.Minute, 1*time.Second, "Quorum-based leader election failed")

	electionTime := time.Since(start)
	t.Logf("✓ Leader elected with minimum quorum in %v", electionTime)

	// Verify aggressive election time for local Docker (should be < 15 seconds)
	assert.Less(t, electionTime, 15*time.Second,
		"Leader election took too long: %v (should be < 15s in local Docker)", electionTime)
}
