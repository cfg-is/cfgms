// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package heartbeat tests the DNA-hash tracking added to the heartbeat service.
package heartbeat

import (
	"context"
	"testing"
	"time"

	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ensure testControlPlane implements the full ControlPlaneProvider interface.
// If the interface gains new methods, the compiler will catch this assertion here.
var _ cpinterfaces.ControlPlaneProvider = (*testControlPlane)(nil)

// testControlPlane is a minimal in-process ControlPlaneProvider used exclusively
// by this test file to satisfy the Service constructor without requiring a real
// gRPC server.  It is NOT a mock — it records the heartbeat handler registered
// via SubscribeHeartbeats so tests can drive heartbeat processing directly.
type testControlPlane struct {
	heartbeatHandler func(context.Context, *controlplaneTypes.Heartbeat) error
}

func (p *testControlPlane) Name() string             { return "test" }
func (p *testControlPlane) Description() string      { return "test control plane" }
func (p *testControlPlane) IsConnected() bool        { return true }
func (p *testControlPlane) Available() (bool, error) { return true, nil }
func (p *testControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *testControlPlane) Start(_ context.Context) error { return nil }
func (p *testControlPlane) Stop(_ context.Context) error  { return nil }
func (p *testControlPlane) SendCommand(_ context.Context, _ *controlplaneTypes.Command) error {
	return nil
}
func (p *testControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.Command, ids []string) (*controlplaneTypes.FanOutResult, error) {
	return &controlplaneTypes.FanOutResult{Succeeded: ids, Failed: map[string]error{}}, nil
}
func (p *testControlPlane) SubscribeCommands(_ context.Context, _ string, _ cpinterfaces.CommandHandler) error {
	return nil
}
func (p *testControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (p *testControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ cpinterfaces.EventHandler) error {
	return nil
}
func (p *testControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (p *testControlPlane) SubscribeHeartbeats(_ context.Context, handler cpinterfaces.HeartbeatHandler) error {
	p.heartbeatHandler = handler
	return nil
}
func (p *testControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

// sendHeartbeat drives the registered handler directly, simulating a steward heartbeat.
func (p *testControlPlane) sendHeartbeat(ctx context.Context, hb *controlplaneTypes.Heartbeat) error {
	if p.heartbeatHandler == nil {
		return nil
	}
	return p.heartbeatHandler(ctx, hb)
}

// newTestService builds a heartbeat Service backed by the testControlPlane.
func newTestService(t *testing.T, opts ...func(*Config)) (*Service, *testControlPlane) {
	t.Helper()
	cp := &testControlPlane{}
	logger := logging.NewLogger("debug")
	cfg := &Config{
		ControlPlane:     cp,
		HeartbeatTimeout: 15 * time.Second,
		CheckInterval:    5 * time.Second,
		Logger:           logger,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	svc, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, svc.Start(context.Background()))
	return svc, cp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHeartbeatService_TracksDNAHash(t *testing.T) {
	svc, cp := newTestService(t)

	hb := &controlplaneTypes.Heartbeat{
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "deadbeef",
	}
	require.NoError(t, cp.sendHeartbeat(context.Background(), hb))

	status, ok := svc.GetStatus("steward-1")
	require.True(t, ok, "steward should be registered after heartbeat")
	assert.Equal(t, "deadbeef", status.DNAHash,
		"service must persist the DNA hash received in the heartbeat")
}

func TestHeartbeatService_UpdatesDNAHash(t *testing.T) {
	svc, cp := newTestService(t)
	ctx := context.Background()

	sendHB := func(hash string) {
		require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
			StewardID: "steward-2",
			Status:    controlplaneTypes.StatusHealthy,
			Timestamp: time.Now(),
			DNAHash:   hash,
		}))
	}

	sendHB("hash-v1")
	status, ok := svc.GetStatus("steward-2")
	require.True(t, ok)
	assert.Equal(t, "hash-v1", status.DNAHash)

	sendHB("hash-v2")
	status, ok = svc.GetStatus("steward-2")
	require.True(t, ok)
	assert.Equal(t, "hash-v2", status.DNAHash, "DNA hash must be updated on each heartbeat")
}

func TestHeartbeatService_HashMismatchCallback(t *testing.T) {
	mismatchCalled := false
	var mismatchStewardID string

	svc, cp := newTestService(t, func(cfg *Config) {
		cfg.OnDNAHashMismatch = func(stewardID string) {
			mismatchCalled = true
			mismatchStewardID = stewardID
		}
	})
	ctx := context.Background()

	// First heartbeat — no previous hash, callback must NOT fire.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-3",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "hash-initial",
	}))
	assert.False(t, mismatchCalled, "callback must not fire on initial heartbeat")

	// Simulate controller acknowledging a full sync by updating the expected hash.
	svc.SetExpectedDNAHash("steward-3", "hash-initial")

	// Second heartbeat with same hash — no mismatch.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-3",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "hash-initial",
	}))
	assert.False(t, mismatchCalled, "callback must not fire when hash matches expected")

	// Third heartbeat with unexpected hash change — mismatch.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-3",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "hash-unexpected",
	}))
	assert.True(t, mismatchCalled, "callback must fire when heartbeat hash differs from expected")
	assert.Equal(t, "steward-3", mismatchStewardID)
}

func TestHeartbeatService_NoCallbackOnEmptyHash(t *testing.T) {
	mismatchCalled := false
	svc, cp := newTestService(t, func(cfg *Config) {
		cfg.OnDNAHashMismatch = func(_ string) { mismatchCalled = true }
	})

	// Steward sends heartbeat without a DNA hash (older steward version).
	svc.SetExpectedDNAHash("steward-4", "some-hash")
	require.NoError(t, cp.sendHeartbeat(context.Background(), &controlplaneTypes.Heartbeat{
		StewardID: "steward-4",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "", // no hash sent
	}))
	assert.False(t, mismatchCalled,
		"callback must not fire when heartbeat carries no DNA hash (backward compat)")
}

func TestHeartbeatService_GetAllStatusesDNAHash(t *testing.T) {
	svc, cp := newTestService(t)
	ctx := context.Background()

	ids := []string{"s1", "s2", "s3"}
	for i, id := range ids {
		require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
			StewardID: id,
			Status:    controlplaneTypes.StatusHealthy,
			Timestamp: time.Now(),
			DNAHash:   []string{"h1", "h2", "h3"}[i],
		}))
	}

	all := svc.GetAllStatuses()
	require.Len(t, all, 3)
	assert.Equal(t, "h1", all["s1"].DNAHash)
	assert.Equal(t, "h2", all["s2"].DNAHash)
	assert.Equal(t, "h3", all["s3"].DNAHash)
}

func TestSetExpectedDNAHash_UnknownSteward(t *testing.T) {
	svc, _ := newTestService(t)

	// Call SetExpectedDNAHash for a steward that has never sent a heartbeat.
	// The service must create a placeholder entry rather than silently dropping it
	// so that subsequent heartbeats from this steward can be validated.
	svc.SetExpectedDNAHash("steward-new", "expected-hash")

	status, ok := svc.GetStatus("steward-new")
	require.True(t, ok,
		"SetExpectedDNAHash must create a steward entry even when none exists yet")
	assert.Equal(t, "expected-hash", status.expectedDNAHash,
		"the expected hash must be persisted for a newly created entry")
}
