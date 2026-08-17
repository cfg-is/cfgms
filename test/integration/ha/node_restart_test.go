// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

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
)

// TestNodeRestart_RebuildsMembershipAndLeader verifies the fix for Issue #3394:
// a controller node that restarts into a live, healthy cluster must immediately
// rebuild its own membership view and learn the current leader from its durable
// store, not from log-entry replay that config.Applied blocks.
//
// Before the fix, a restarted node reported "count":1 (only itself) on
// GET /api/v1/ha/nodes and "health":"no_leader" on GET /api/v1/ha/leader even
// though the surviving nodes still held the correct 3-node view.
//
// The required post-restart recovery interval is ≤ 2 minutes from container
// start, as documented in docs/architecture/controller-operating-model.md.
func TestNodeRestart_RebuildsMembershipAndLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	helper := NewDockerComposeHelper()

	t.Log("Starting HA cluster for node-restart test...")
	require.NoError(t, helper.StartCluster(ctx))
	defer func() {
		if err := helper.StopCluster(context.Background()); err != nil {
			t.Logf("Warning: Failed to stop cluster: %v", err)
		}
	}()

	services := []string{"controller-east", "controller-central", "controller-west"}
	require.NoError(t, helper.WaitForServices(ctx, 3*time.Minute, services...))

	// Wait for all nodes to be reachable and report a full 3-node view.
	t.Log("Waiting for full cluster formation (3-node membership on all nodes)...")
	require.Eventually(t, func() bool {
		for _, url := range []string{controllerEastURL, controllerCentralURL, controllerWestURL} {
			nodes, err := getHANodes(url)
			if err != nil || len(nodes) != 3 {
				return false
			}
		}
		return true
	}, 3*time.Minute, 5*time.Second, "all nodes must report 3-node membership before restart")

	// Capture the leader that the survivors agree on (any node is fine as reference).
	leaderID, err := getHALeaderID(controllerCentralURL)
	require.NoError(t, err, "must be able to read leader from controller-central before restart")
	require.NotEmpty(t, leaderID, "a leader must be elected before restarting controller-east")
	t.Logf("Leader before restart: %s", leaderID)

	// Restart controller-east using the established integration-test helper.
	t.Log("Restarting controller-east...")
	require.NoError(t, helper.RestartService(ctx, "controller-east"))

	// After restart, controller-east must rebuild its own membership view from the
	// durable store and report count=3, not count=1.
	t.Log("Waiting for controller-east to rebuild membership after restart...")
	require.Eventually(t, func() bool {
		nodes, err := getHANodes(controllerEastURL)
		return err == nil && len(nodes) == 3
	}, 2*time.Minute, 5*time.Second,
		"restarted controller-east must report count=3 within the bounded 2-minute interval")

	// The restarted node must also learn the current leader — not report no_leader.
	t.Log("Verifying controller-east reports the current leader...")
	require.Eventually(t, func() bool {
		id, err := getHALeaderID(controllerEastURL)
		return err == nil && id != ""
	}, 2*time.Minute, 5*time.Second,
		"restarted controller-east must report a leader within the bounded 2-minute interval")

	// Snapshot the post-restart state for the detailed assertions below.
	nodes, err := getHANodes(controllerEastURL)
	require.NoError(t, err, "GET /api/v1/ha/nodes on restarted controller-east must succeed")

	restartedLeaderID, err := getHALeaderID(controllerEastURL)
	require.NoError(t, err, "GET /api/v1/ha/leader on restarted controller-east must succeed")

	t.Run("MembershipCount", func(t *testing.T) {
		assert.Len(t, nodes, 3,
			"restarted controller-east must report all 3 cluster members, not just itself")
	})

	t.Run("LeaderKnown", func(t *testing.T) {
		assert.NotEmpty(t, restartedLeaderID,
			"restarted controller-east must know the current leader")
	})

	t.Run("LeaderConsistency", func(t *testing.T) {
		// If the leader did not change during the restart (common case), the
		// restarted node must agree with the surviving nodes on who it is.
		// A failover during restart is valid; in that case the surviving nodes
		// will have elected a new leader and the restarted node must reflect it.
		survivorLeaderID, err := getHALeaderID(controllerCentralURL)
		require.NoError(t, err)
		assert.Equal(t, survivorLeaderID, restartedLeaderID,
			"restarted controller-east and survivor controller-central must agree on the leader")
	})

	t.Run("SurvivorsUnaffected", func(t *testing.T) {
		// The surviving nodes must still report the correct 3-node view throughout.
		for _, url := range []string{controllerCentralURL, controllerWestURL} {
			nodes, err := getHANodes(url)
			assert.NoError(t, err)
			assert.Len(t, nodes, 3, "surviving node %s must still report 3-node membership", url)
		}
	})
}

// getHANodes queries GET /api/v1/ha/nodes and returns the list of NodeInfo
// objects the controller reports. Returns an error if the request fails or the
// response cannot be decoded.
func getHANodes(baseURL string) ([]map[string]interface{}, error) {
	client := buildTLSClient(containerNameForURL(baseURL))

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/ha/nodes", baseURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", getAPIKeyForURL(baseURL))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /api/v1/ha/nodes returned %d", resp.StatusCode)
	}

	var body struct {
		Nodes []map[string]interface{} `json:"nodes"`
		Count int                      `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode /api/v1/ha/nodes: %w", err)
	}
	return body.Nodes, nil
}

// getHALeaderID queries GET /api/v1/ha/leader and returns the leader's node ID.
// Returns ("", nil) when the endpoint is reachable but reports no_leader.
// Returns a non-nil error only on transport or decode failure.
func getHALeaderID(baseURL string) (string, error) {
	client := buildTLSClient(containerNameForURL(baseURL))

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/ha/leader", baseURL), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-API-Key", getAPIKeyForURL(baseURL))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /api/v1/ha/leader returned %d", resp.StatusCode)
	}

	var body struct {
		NodeID string `json:"node_id"`
		Health string `json:"health"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode /api/v1/ha/leader: %w", err)
	}
	if body.Health == "no_leader" {
		return "", nil
	}
	return body.NodeID, nil
}
