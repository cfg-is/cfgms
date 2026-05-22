// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package heartbeat tests the steward-offline and HA-failover thresholds.
// Epic #1664: StewardOfflineTimeout (60 s) is distinct from HeartbeatTimeout (15 s HA-failover).
package heartbeat

import (
	"context"
	"sync"
	"testing"
	"time"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTrustEvaluator is a real in-process TrustEvaluator used for testing.
// It records every RecordLiveness call so tests can assert on call arguments.
// It is NOT a mock — it is a functional test implementation that satisfies the
// TrustEvaluator interface contract.
type recordingTrustEvaluator struct {
	mu    sync.Mutex
	calls []trustCall
}

type trustCall struct {
	stewardID string
	healthy   bool
}

func (r *recordingTrustEvaluator) RecordLiveness(_ context.Context, stewardID string, healthy bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, trustCall{stewardID: stewardID, healthy: healthy})
	return nil
}

func (r *recordingTrustEvaluator) allCalls() []trustCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]trustCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// Compile-time: recordingTrustEvaluator satisfies TrustEvaluator.
var _ TrustEvaluator = (*recordingTrustEvaluator)(nil)

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

// TestHeartbeatService_TrustEvaluator_CalledOnHeartbeat verifies that the
// TrustEvaluator.RecordLiveness is called with healthy=true on each incoming
// heartbeat and with healthy=false when a steward is marked stale.
// It also verifies that a nil TrustEvaluator causes no panic (Issue #1694).
func TestHeartbeatService_TrustEvaluator_CalledOnHeartbeat(t *testing.T) {
	evaluator := &recordingTrustEvaluator{}
	_, cp := newTestService(t, func(cfg *Config) {
		cfg.TrustEvaluator = evaluator
	})
	ctx := context.Background()

	const stewardID = "steward-trust-test"

	// Send a heartbeat — evaluator must receive healthy=true for this steward.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))

	calls := evaluator.allCalls()
	require.NotEmpty(t, calls, "RecordLiveness must be called on heartbeat")
	last := calls[len(calls)-1]
	assert.Equal(t, stewardID, last.stewardID)
	assert.True(t, last.healthy, "heartbeat event must report healthy=true")
}

// TestHeartbeatService_TrustEvaluator_CalledOnStale verifies that the
// TrustEvaluator.RecordLiveness is called with healthy=false when a steward
// is detected stale by checkStaleHeartbeats (Issue #1694).
func TestHeartbeatService_TrustEvaluator_CalledOnStale(t *testing.T) {
	evaluator := &recordingTrustEvaluator{}
	svc, cp := newTestService(t, func(cfg *Config) {
		cfg.TrustEvaluator = evaluator
		cfg.StewardOfflineTimeout = 60 * time.Second
	})
	ctx := context.Background()

	const stewardID = "steward-stale-test"

	// Register the steward via an initial heartbeat.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))

	// Force the last-heartbeat timestamp past the stale threshold.
	svc.mu.Lock()
	svc.stewards[stewardID].LastHeartbeat = time.Now().Add(-61 * time.Second)
	svc.stewards[stewardID].Healthy = true
	svc.mu.Unlock()

	// checkStaleHeartbeats must fire the evaluator with healthy=false.
	svc.checkStaleHeartbeats()

	unhealthyCalls := 0
	for _, c := range evaluator.allCalls() {
		if c.stewardID == stewardID && !c.healthy {
			unhealthyCalls++
		}
	}
	assert.Equal(t, 1, unhealthyCalls,
		"RecordLiveness must be called exactly once with healthy=false on stale detection")
}

// TestHeartbeatService_TrustEvaluator_NilIsNoop verifies that a nil
// TrustEvaluator does not panic when heartbeats arrive or when stale
// detection fires (Issue #1694).
func TestHeartbeatService_TrustEvaluator_NilIsNoop(t *testing.T) {
	// newTestService wires no TrustEvaluator by default (nil).
	svc, cp := newTestService(t)
	ctx := context.Background()

	const stewardID = "steward-nil-eval-test"

	// Send heartbeat — must not panic.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))

	// Trigger stale detection — must not panic.
	svc.mu.Lock()
	svc.stewards[stewardID].LastHeartbeat = time.Now().Add(-61 * time.Second)
	svc.stewards[stewardID].Healthy = true
	svc.mu.Unlock()

	assert.NotPanics(t, svc.checkStaleHeartbeats,
		"nil TrustEvaluator must not cause a panic")
}
