// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// testFeedbackControlPlane is a minimal in-process ControlPlaneProvider that lets
// tests drive heartbeat processing directly. It is NOT a mock — it captures the
// heartbeat handler registered by heartbeat.Service so tests can inject heartbeats
// and observe mismatch callback behaviour without a live gRPC stack.
type testFeedbackControlPlane struct {
	heartbeatHandler cpinterfaces.HeartbeatHandler
}

var _ cpinterfaces.ControlPlaneProvider = (*testFeedbackControlPlane)(nil)

func (p *testFeedbackControlPlane) Name() string      { return "test-feedback" }
func (p *testFeedbackControlPlane) IsConnected() bool { return true }
func (p *testFeedbackControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *testFeedbackControlPlane) Start(_ context.Context) error     { return nil }
func (p *testFeedbackControlPlane) Stop(_ context.Context) error      { return nil }
func (p *testFeedbackControlPlane) Reconnect(_ context.Context) error { return nil }
func (p *testFeedbackControlPlane) SendCommand(_ context.Context, _ *controlplaneTypes.SignedCommand) error {
	return nil
}
func (p *testFeedbackControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, ids []string) (*controlplaneTypes.FanOutResult, error) {
	return &controlplaneTypes.FanOutResult{Succeeded: ids, Failed: map[string]error{}}, nil
}
func (p *testFeedbackControlPlane) SubscribeCommands(_ context.Context, _ string, _ cpinterfaces.CommandHandler) error {
	return nil
}
func (p *testFeedbackControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (p *testFeedbackControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ cpinterfaces.EventHandler) error {
	return nil
}
func (p *testFeedbackControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (p *testFeedbackControlPlane) SubscribeHeartbeats(_ context.Context, handler cpinterfaces.HeartbeatHandler) error {
	p.heartbeatHandler = handler
	return nil
}
func (p *testFeedbackControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

func (p *testFeedbackControlPlane) injectHeartbeat(ctx context.Context, hb *controlplaneTypes.Heartbeat) error {
	if p.heartbeatHandler == nil {
		return nil
	}
	return p.heartbeatHandler(ctx, hb)
}

// TestDNASyncFeedbackLoop_SuppressesSubsequentMismatch is the REQUIRED TEST for
// the Issue #3329 restoration of the Issue #2524 feedback loop: after SyncDNA
// fires the postDNASyncHook and heartbeatService.SetExpectedDNAHash is updated
// to the newly-synced hash (now computed via fleetStorage.ContentHash, the
// aggregate-root-first hash — Issue #2906 — rather than the retired
// stewarddna.ComputeHash(dna.Attributes)), a subsequent heartbeat carrying that
// hash must NOT trigger a mismatch.
//
// This closes the gap left when the PR that retired ComputeHash(dna.Attributes)
// deleted this file's predecessor without restoring production wiring: with no
// call site setting expectedDNAHash, heartbeat.Service's mismatch detection
// (and the SetOnDNAHashMismatch → commandPublisher.TriggerDNASync path server.go
// wires at startup) was permanently inert.
func TestDNASyncFeedbackLoop_SuppressesSubsequentMismatch(t *testing.T) {
	ctx := context.Background()
	cp := &testFeedbackControlPlane{}

	// Real heartbeat service backed by the in-process control plane.
	heartbeatSvc, err := heartbeat.New(&heartbeat.Config{
		ControlPlane:     cp,
		HeartbeatTimeout: 15 * time.Second,
		CheckInterval:    5 * time.Second,
		Logger:           logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	require.NoError(t, heartbeatSvc.Start(ctx))

	// Wire the mismatch callback so we can count triggers.
	var mu sync.Mutex
	var mismatchCount int
	heartbeatSvc.SetOnDNAHashMismatch(func(_ string) {
		mu.Lock()
		mismatchCount++
		mu.Unlock()
	})

	// Real controller service with storage.
	controllerSvc := NewControllerServiceWithStorage(logging.NewNoopLogger(), newTestFleetStorage(t))
	require.NoError(t, controllerSvc.RegisterSteward("dev-feedback", "tenant-fb", "", "active"))

	// Wire the post-DNA-sync hook using the same closure as server.go's
	// SetPostDNASyncHook wiring so every SyncDNA call updates the expected hash
	// in the heartbeat service.
	controllerSvc.SetPostDNASyncHook(func(stewardID string, dna *commonpb.DNA) {
		hash, hashErr := fleetStorage.ContentHash(dna)
		require.NoError(t, hashErr)
		heartbeatSvc.SetExpectedDNAHash(stewardID, hash)
	})

	// Define the DNA that will be synced. Fragments are required by Issue #3319.
	attrs := map[string]string{"os": "linux", "hostname": "fb-host", "version": "1.0"}
	dna := makeTestDNA("dev-feedback", attrs)
	syncedHash, err := fleetStorage.ContentHash(dna)
	require.NoError(t, err)

	// Set a diverged expected hash to confirm the hook actually updates it.
	heartbeatSvc.SetExpectedDNAHash("dev-feedback", "old-stale-hash")

	// SyncDNA fires the hook → heartbeatSvc.SetExpectedDNAHash("dev-feedback", syncedHash).
	resp, err := controllerSvc.SyncDNA(ctx, dna)
	require.NoError(t, err)
	require.Equal(t, commonpb.Status_OK, resp.Code)

	// A heartbeat carrying the newly-synced hash must NOT trigger a mismatch.
	require.NoError(t, cp.injectHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: "dev-feedback",
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   syncedHash,
	}))

	mu.Lock()
	count := mismatchCount
	mu.Unlock()

	assert.Equal(t, 0, count,
		"heartbeat carrying the newly-synced hash must NOT trigger a mismatch after SyncDNA updates the expected hash")
}
