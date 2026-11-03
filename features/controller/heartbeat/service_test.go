// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package heartbeat tests the steward-offline and HA-failover thresholds.
// Epic #1664: StewardOfflineTimeout (60 s) is distinct from HeartbeatTimeout (15 s HA-failover).
package heartbeat

import (
	"context"
	"strings"
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
	svc.stewards["steward-offline-test"].receivedAt = time.Now().Add(-59 * time.Second)
	svc.stewards["steward-offline-test"].Healthy = true
	svc.mu.Unlock()

	svc.checkStaleHeartbeats()

	status, ok = svc.GetStatus("steward-offline-test")
	require.True(t, ok)
	assert.True(t, status.Healthy,
		"steward must remain healthy at 59s — StewardOfflineTimeout is 60s, not 15s")

	// Simulate 61 s of silence — must trigger offline (over threshold).
	svc.mu.Lock()
	svc.stewards["steward-offline-test"].receivedAt = time.Now().Add(-61 * time.Second)
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
	svc.stewards[stewardID].receivedAt = time.Now().Add(-61 * time.Second)
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
	svc.stewards[stewardID].receivedAt = time.Now().Add(-61 * time.Second)
	svc.stewards[stewardID].Healthy = true
	svc.mu.Unlock()

	assert.NotPanics(t, svc.checkStaleHeartbeats,
		"nil TrustEvaluator must not cause a panic")
}

// TestHeartbeatService_StalenessUsesReceiptTime_NotStewardClock is the Issue #2037
// regression test. Staleness must be measured against the controller's receipt
// time, never the steward-supplied heartbeat timestamp. A steward whose clock is
// skewed far into the past (e.g. NTP drift) sends heartbeats stamped with an old
// timestamp, but if the controller is receiving them on time the steward is NOT
// offline. On the pre-fix code (which aged status.LastHeartbeat against now) this
// steward flapped to "timeout" on every check despite arriving on schedule.
func TestHeartbeatService_StalenessUsesReceiptTime_NotStewardClock(t *testing.T) {
	svc, cp := newTestService(t, func(cfg *Config) {
		cfg.StewardOfflineTimeout = 60 * time.Second
	})
	ctx := context.Background()

	const stewardID = "steward-skewed-clock"

	// The steward's clock is 90s behind the controller (> the 60s offline
	// timeout). It stamps the heartbeat with its own (old) time, but the
	// controller receives it right now.
	skewedSendTime := time.Now().Add(-90 * time.Second)
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: skewedSendTime,
	}))

	// A stale check immediately after receipt must NOT mark the steward offline:
	// only ~0s have elapsed since the controller received the heartbeat.
	svc.checkStaleHeartbeats()

	status, ok := svc.GetStatus(stewardID)
	require.True(t, ok)
	assert.True(t, status.Healthy,
		"steward with a skewed-old send timestamp but fresh receipt must stay healthy (Issue #2037)")

	// The reported send time is preserved for observability (steward clock),
	// while staleness is governed by the controller receipt time.
	assert.WithinDuration(t, skewedSendTime, status.LastHeartbeat, time.Second,
		"LastHeartbeat must still report the steward-supplied send time")

	// Sanity: once the controller has genuinely not received a heartbeat for
	// longer than the timeout, it IS marked offline — regardless of send time.
	svc.mu.Lock()
	svc.stewards[stewardID].receivedAt = time.Now().Add(-61 * time.Second)
	svc.stewards[stewardID].Healthy = true
	svc.mu.Unlock()

	svc.checkStaleHeartbeats()

	status, ok = svc.GetStatus(stewardID)
	require.True(t, ok)
	assert.False(t, status.Healthy,
		"steward must be marked offline after 61s with no receipt")
}

// TestHeartbeatService_Reasons_CappedReplacedAndHandedToHook verifies Issue
// #5651: reasons are re-capped on receive (steward input is untrusted), each
// heartbeat replaces the previous set, and the per-heartbeat hook receives the
// capped set.
func TestHeartbeatService_Reasons_CappedReplacedAndHandedToHook(t *testing.T) {
	var mu sync.Mutex
	var got [][]controlplaneTypes.HealthReason
	svc, cp := newTestService(t, func(cfg *Config) {
		cfg.OnHeartbeatReceived = func(_ string, reasons []controlplaneTypes.HealthReason) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, reasons)
		}
	})
	ctx := context.Background()
	const stewardID = "steward-reasons"

	long := strings.Repeat("x", 1000)
	many := make([]controlplaneTypes.HealthReason, controlplaneTypes.MaxHealthReasons+5)
	for i := range many {
		many[i] = controlplaneTypes.HealthReason{Component: long, Code: long, Message: long}
	}
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID, Status: controlplaneTypes.StatusDegraded, Timestamp: time.Now(), Reasons: many,
	}))

	status, ok := svc.GetStatus(stewardID)
	require.True(t, ok)
	require.Len(t, status.Reasons, controlplaneTypes.MaxHealthReasons)
	assert.Len(t, status.Reasons[0].Component, controlplaneTypes.MaxHealthReasonComponent)
	assert.Len(t, status.Reasons[0].Code, controlplaneTypes.MaxHealthReasonCode)
	assert.Len(t, status.Reasons[0].Message, controlplaneTypes.MaxHealthReasonMessageLen)

	// A later heartbeat replaces the set; a heartbeat with none clears it.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID, Status: controlplaneTypes.StatusDegraded, Timestamp: time.Now(),
		Reasons: []controlplaneTypes.HealthReason{{Component: "disk", Code: "disk.low"}},
	}))
	status, _ = svc.GetStatus(stewardID)
	assert.Equal(t, []controlplaneTypes.HealthReason{{Component: "disk", Code: "disk.low"}}, status.Reasons)

	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID, Status: controlplaneTypes.StatusHealthy, Timestamp: time.Now(),
	}))
	status, _ = svc.GetStatus(stewardID)
	assert.Empty(t, status.Reasons)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, got, 3)
	assert.Len(t, got[0], controlplaneTypes.MaxHealthReasons, "hook gets the capped set")
	assert.Len(t, got[0][0].Message, controlplaneTypes.MaxHealthReasonMessageLen)
	assert.Len(t, got[1], 1)
	assert.Empty(t, got[2])
}
