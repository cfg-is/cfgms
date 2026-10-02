// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package heartbeat tests the DNA-hash tracking added to the heartbeat service.
package heartbeat

import (
	"context"
	"sync"
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

func (p *testControlPlane) Name() string      { return "test" }
func (p *testControlPlane) IsConnected() bool { return true }
func (p *testControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *testControlPlane) Start(_ context.Context) error { return nil }
func (p *testControlPlane) Stop(_ context.Context) error  { return nil }
func (p *testControlPlane) SendCommand(_ context.Context, _ *controlplaneTypes.SignedCommand) error {
	return nil
}
func (p *testControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, ids []string) (*controlplaneTypes.FanOutResult, error) {
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
func (p *testControlPlane) Reconnect(_ context.Context) error { return nil }

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

func TestHeartbeatService_ActiveSessionsAndConnectionState(t *testing.T) {
	svc, cp := newTestService(t)
	ctx := context.Background()

	hb := &controlplaneTypes.Heartbeat{
		StewardID:       "steward-ac",
		TenantID:        "tenant-ac",
		Status:          controlplaneTypes.StatusHealthy,
		Timestamp:       time.Now(),
		ActiveSessions:  1,
		ConnectionState: "connected",
	}
	require.NoError(t, cp.sendHeartbeat(ctx, hb))

	status, ok := svc.GetStatus("steward-ac")
	require.True(t, ok, "steward must be registered after heartbeat")
	assert.Equal(t, 1, status.ActiveSessions,
		"StewardStatus.ActiveSessions must equal the heartbeat active_sessions value")
	assert.Equal(t, "connected", status.ConnectionState,
		"StewardStatus.ConnectionState must equal the heartbeat connection_state value")
}

func TestSetExpectedDNAHash_UnknownSteward(t *testing.T) {
	svc, _ := newTestService(t)

	// Call SetExpectedDNAHash for a steward that has never sent a heartbeat.
	// The service must create a pre-populated entry rather than silently dropping it
	// so that subsequent heartbeats from this steward can be validated.
	svc.SetExpectedDNAHash("steward-new", "expected-hash")

	status, ok := svc.GetStatus("steward-new")
	require.True(t, ok,
		"SetExpectedDNAHash must create a steward entry even when none exists yet")
	assert.Equal(t, "expected-hash", status.expectedDNAHash,
		"the expected hash must be persisted for a newly created entry")
}

// TestHeartbeatService_SetOnDNAHashMismatch_WorksAfterConstruction verifies that
// SetOnDNAHashMismatch can be called after construction (late-wiring) and that
// the registered callback fires on subsequent hash mismatches (Issue #2524).
func TestHeartbeatService_SetOnDNAHashMismatch_WorksAfterConstruction(t *testing.T) {
	// Create service WITHOUT a mismatch callback in the Config.
	svc, cp := newTestService(t)
	ctx := context.Background()

	// Register the late-wired callback.
	var called []string
	svc.SetOnDNAHashMismatch(func(stewardID string) {
		called = append(called, stewardID)
	})

	// Prime the expected hash so mismatch detection is active.
	svc.SetExpectedDNAHash("steward-latewire", "hash-expected")

	// Heartbeat with matching hash — no trigger.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-latewire",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "hash-expected",
	}))
	assert.Empty(t, called, "late-wired callback must not fire on matching hash")

	// Heartbeat with different hash — must trigger the late-wired callback.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-latewire",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "hash-diverged",
	}))
	require.Len(t, called, 1, "late-wired callback must fire exactly once on mismatch")
	assert.Equal(t, "steward-latewire", called[0], "callback must receive the correct steward ID")
}

// TestHeartbeatService_SetOnDNAHashMismatch_ExactlyOnce is the REQUIRED TEST:
// a heartbeat carrying a DNA hash that differs from the expected hash triggers
// exactly one callback invocation for that steward ID; a heartbeat with a
// matching hash triggers none (Issue #2524).
func TestHeartbeatService_SetOnDNAHashMismatch_ExactlyOnce(t *testing.T) {
	var callCount int
	var lastStewardID string

	svc, cp := newTestService(t)
	svc.SetOnDNAHashMismatch(func(stewardID string) {
		callCount++
		lastStewardID = stewardID
	})
	ctx := context.Background()

	svc.SetExpectedDNAHash("steward-exact", "good-hash")

	// Matching heartbeat — zero callbacks.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-exact",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "good-hash",
	}))
	assert.Equal(t, 0, callCount, "matching hash must not trigger callback")

	// Mismatching heartbeat — exactly one callback with the right steward ID.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-exact",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "diverged-hash",
	}))
	assert.Equal(t, 1, callCount, "mismatching hash must trigger exactly one callback")
	assert.Equal(t, "steward-exact", lastStewardID, "callback must receive the correct steward ID")
}

// TestHeartbeatService_SetOnDNAHashMismatch_ReplacesConfigCallback verifies that
// SetOnDNAHashMismatch replaces (not appends to) any callback set at Config time,
// so server.go can override the default-nil with the real publisher callback.
func TestHeartbeatService_SetOnDNAHashMismatch_ReplacesConfigCallback(t *testing.T) {
	configCalls := 0
	laterCalls := 0

	svc, cp := newTestService(t, func(cfg *Config) {
		cfg.OnDNAHashMismatch = func(_ string) { configCalls++ }
	})
	ctx := context.Background()

	// Replace the Config-time callback with a different one.
	svc.SetOnDNAHashMismatch(func(_ string) { laterCalls++ })

	svc.SetExpectedDNAHash("steward-replace", "hash-A")
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-replace",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "hash-B", // mismatch
	}))

	assert.Equal(t, 0, configCalls, "Config-time callback must be replaced, not appended")
	assert.Equal(t, 1, laterCalls, "late-wired callback must fire on mismatch")
}

// TestHeartbeatService_FragmentRootCallback_FiresOnNonEmptyRoot verifies that
// onFragmentRoot fires with the correct steward ID and claimed root when a
// heartbeat carries a non-empty DNAAggregateRoot (ADR-017 §7 step 1).
//
// The heartbeat's TenantID is set here and must NOT be observable through the
// callback: the callback signature carries no tenant, so a steward-asserted tenant
// claim cannot be laundered into the controller-issued SYNC_DNA command.
func TestHeartbeatService_FragmentRootCallback_FiresOnNonEmptyRoot(t *testing.T) {
	type call struct {
		stewardID, root string
	}
	var mu sync.Mutex
	var calls []call

	_, cp := newTestService(t, func(cfg *Config) {
		cfg.OnFragmentRoot = func(_ context.Context, stewardID, claimedRoot string) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, call{stewardID, claimedRoot})
		}
	})
	ctx := context.Background()

	// Heartbeat without DNAAggregateRoot — callback must NOT fire.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "steward-root",
		TenantID:  "tenant-root",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))
	mu.Lock()
	gotCalls := len(calls)
	mu.Unlock()
	assert.Equal(t, 0, gotCalls, "callback must not fire when DNAAggregateRoot is empty")

	// Heartbeat with DNAAggregateRoot — callback must fire with correct args.
	const claimedRoot = "sha256:abc123def456"
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID:        "steward-root",
		TenantID:         "tenant-root",
		Status:           controlplaneTypes.StatusHealthy,
		Timestamp:        time.Now(),
		DNAAggregateRoot: claimedRoot,
	}))

	mu.Lock()
	allCalls := make([]call, len(calls))
	copy(allCalls, calls)
	mu.Unlock()

	require.Len(t, allCalls, 1, "callback must fire exactly once for one heartbeat carrying a root")
	assert.Equal(t, "steward-root", allCalls[0].stewardID)
	assert.Equal(t, claimedRoot, allCalls[0].root)
}

// TestHeartbeatService_FragmentRootCallback_NilIsNoop verifies that no panic occurs
// and no callback fires when OnFragmentRoot is nil (default).
func TestHeartbeatService_FragmentRootCallback_NilIsNoop(t *testing.T) {
	// No OnFragmentRoot in config — default nil.
	_, cp := newTestService(t)

	require.NoError(t, cp.sendHeartbeat(context.Background(), &controlplaneTypes.Heartbeat{
		StewardID:        "steward-noop",
		TenantID:         "tenant-noop",
		Status:           controlplaneTypes.StatusHealthy,
		Timestamp:        time.Now(),
		DNAAggregateRoot: "some-root",
	}))
	// No assertion needed — the test passes by not panicking.
}

// TestHeartbeatService_SetOnFragmentRoot_WorksAfterConstruction verifies that
// SetOnFragmentRoot can be called after construction and fires on subsequent
// heartbeats carrying a non-empty DNAAggregateRoot.
func TestHeartbeatService_SetOnFragmentRoot_WorksAfterConstruction(t *testing.T) {
	svc, cp := newTestService(t)
	ctx := context.Background()

	var fired int
	svc.SetOnFragmentRoot(func(_ context.Context, _, _ string) {
		fired++
	})

	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID:        "steward-latewire",
		TenantID:         "t1",
		Status:           controlplaneTypes.StatusHealthy,
		Timestamp:        time.Now(),
		DNAAggregateRoot: "root-v1",
	}))

	assert.Equal(t, 1, fired, "late-wired callback must fire on heartbeat with aggregate root")
}
