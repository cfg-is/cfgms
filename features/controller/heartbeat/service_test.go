// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package heartbeat tests the steward-offline and HA-failover thresholds.
// Epic #1664: StewardOfflineTimeout (60 s) is distinct from HeartbeatTimeout (15 s HA-failover).
package heartbeat

import (
	"context"
	"testing"
	"time"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHeartbeatService_StewardOfflineThreshold_60s verifies that:
//  1. StewardOfflineTimeout defaults to 60 s when not configured.
//  2. A steward is not marked offline at 59 s of silence (under the threshold).
//  3. A steward is marked offline after 60 s of silence (at/over the threshold).
//
// This test distinguishes the steward-liveness path (StewardOfflineTimeout, 60 s)
// from the HA-failover path (HeartbeatTimeout, 15 s). After epic #1664 the stale-
// heartbeat checker uses StewardOfflineTimeout, so 15 s of silence must NOT trigger
// an offline transition.
func TestHeartbeatService_StewardOfflineThreshold_60s(t *testing.T) {
	svc, cp := newTestService(t)
	ctx := context.Background()

	// Default StewardOfflineTimeout must be 60 s (epic #1664).
	assert.Equal(t, 60*time.Second, svc.stewardOfflineTimeout,
		"default StewardOfflineTimeout must be 60s (epic #1664)")

	// Register the steward with a heartbeat.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-offline-test",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))

	status, ok := svc.GetStatus("steward-offline-test")
	require.True(t, ok)
	assert.True(t, status.Healthy, "steward must start healthy")

	// Simulate 59 s of silence — must NOT trigger offline (under threshold).
	svc.mu.Lock()
	svc.stewards["steward-offline-test"].LastHeartbeat = time.Now().Add(-59 * time.Second)
	svc.stewards["steward-offline-test"].Healthy = true
	svc.mu.Unlock()

	svc.checkStaleHeartbeats()

	status, ok = svc.GetStatus("steward-offline-test")
	require.True(t, ok)
	assert.True(t, status.Healthy,
		"steward must remain healthy at 59s — StewardOfflineTimeout is 60s, not 15s")

	// Simulate 61 s of silence — must trigger offline (over threshold).
	svc.mu.Lock()
	svc.stewards["steward-offline-test"].LastHeartbeat = time.Now().Add(-61 * time.Second)
	svc.stewards["steward-offline-test"].Healthy = true
	svc.mu.Unlock()

	svc.checkStaleHeartbeats()

	status, ok = svc.GetStatus("steward-offline-test")
	require.True(t, ok)
	assert.False(t, status.Healthy,
		"steward must be marked offline after 61s of silence (StewardOfflineTimeout=60s)")
}

// TestHeartbeatService_HAFailoverThreshold_15s verifies that:
//  1. HeartbeatTimeout defaults to 15 s (Story #198 requirement).
//  2. StewardOfflineTimeout does not affect HeartbeatTimeout.
//  3. The two fields are distinct and serve different purposes.
//
// HeartbeatTimeout is scoped to controller-HA failover detection (Story #198, <15 s).
// StewardOfflineTimeout is scoped to steward-liveness detection (epic #1664, 60 s).
// They must never be merged.
func TestHeartbeatService_HAFailoverThreshold_15s(t *testing.T) {
	svc, _ := newTestService(t)

	// HeartbeatTimeout must remain 15 s for HA-failover detection (Story #198).
	assert.Equal(t, 15*time.Second, svc.heartbeatTimeout,
		"HeartbeatTimeout (HA-failover) must default to 15s (Story #198)")

	// StewardOfflineTimeout must be 60 s for steward-liveness detection (epic #1664).
	assert.Equal(t, 60*time.Second, svc.stewardOfflineTimeout,
		"StewardOfflineTimeout must default to 60s (epic #1664)")

	// The two fields must be distinct — merging them would break one of the two invariants.
	assert.NotEqual(t, svc.heartbeatTimeout, svc.stewardOfflineTimeout,
		"HeartbeatTimeout and StewardOfflineTimeout must be distinct values")

	// StewardOfflineTimeout can be overridden without affecting HeartbeatTimeout.
	customSvc, _ := newTestService(t, func(cfg *Config) {
		cfg.StewardOfflineTimeout = 120 * time.Second
	})
	assert.Equal(t, 15*time.Second, customSvc.heartbeatTimeout,
		"overriding StewardOfflineTimeout must not change HeartbeatTimeout")
	assert.Equal(t, 120*time.Second, customSvc.stewardOfflineTimeout,
		"custom StewardOfflineTimeout must be respected")
}
