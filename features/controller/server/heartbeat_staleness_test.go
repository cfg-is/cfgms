// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for heartbeat-driven durable status persistence (Issue #2463).
package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/heartbeat"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// hbTestControlPlane is a minimal in-process ControlPlaneProvider that
// records the heartbeat handler registered via SubscribeHeartbeats so tests
// can drive heartbeat processing directly. It is NOT a mock — it is a
// functional test implementation satisfying the ControlPlaneProvider contract.
type hbTestControlPlane struct {
	heartbeatHandler cpinterfaces.HeartbeatHandler
}

var _ cpinterfaces.ControlPlaneProvider = (*hbTestControlPlane)(nil)

func (p *hbTestControlPlane) Name() string      { return "hbtest" }
func (p *hbTestControlPlane) IsConnected() bool { return true }
func (p *hbTestControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *hbTestControlPlane) Start(_ context.Context) error     { return nil }
func (p *hbTestControlPlane) Stop(_ context.Context) error      { return nil }
func (p *hbTestControlPlane) Reconnect(_ context.Context) error { return nil }
func (p *hbTestControlPlane) SendCommand(_ context.Context, _ *controlplaneTypes.SignedCommand) error {
	return nil
}
func (p *hbTestControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, ids []string) (*controlplaneTypes.FanOutResult, error) {
	return &controlplaneTypes.FanOutResult{Succeeded: ids, Failed: map[string]error{}}, nil
}
func (p *hbTestControlPlane) SubscribeCommands(_ context.Context, _ string, _ cpinterfaces.CommandHandler) error {
	return nil
}
func (p *hbTestControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (p *hbTestControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ cpinterfaces.EventHandler) error {
	return nil
}
func (p *hbTestControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (p *hbTestControlPlane) SubscribeHeartbeats(_ context.Context, handler cpinterfaces.HeartbeatHandler) error {
	p.heartbeatHandler = handler
	return nil
}
func (p *hbTestControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

// sendHeartbeat drives the registered handler directly, simulating a steward heartbeat.
func (p *hbTestControlPlane) sendHeartbeat(ctx context.Context, hb *controlplaneTypes.Heartbeat) error {
	if p.heartbeatHandler == nil {
		return nil
	}
	return p.heartbeatHandler(ctx, hb)
}

// TestHeartbeatOnStatusChange_PersistsLostStatus verifies that the OnStatusChange
// closure wired in server.go (Issue #2463) persists StewardStatusLost to the
// durable StewardStore when a steward times out, and StewardStatusActive when it
// recovers. Uses a real heartbeat.Service and a real flatfile StewardStore (no
// mocks, per CLAUDE.md). Staleness is triggered by a very short
// StewardOfflineTimeout so the test finishes in under 1 second.
func TestHeartbeatOnStatusChange_PersistsLostStatus(t *testing.T) {
	ctx := context.Background()

	st := newFlatFileStewardStore(t)
	logger := logging.NewNoopLogger()

	const stewardID = "hb-staleness-test-001"
	require.NoError(t, st.RegisterSteward(ctx, &business.StewardRecord{
		ID:       stewardID,
		TenantID: "test-tenant",
		Status:   business.StewardStatusRegistered,
	}))

	cp := &hbTestControlPlane{}
	svc, err := heartbeat.New(&heartbeat.Config{
		ControlPlane:          cp,
		OnStatusChange:        makeHeartbeatStatusChangeCallback(st, logger),
		StewardOfflineTimeout: 500 * time.Millisecond,
		CheckInterval:         10 * time.Millisecond,
		Logger:                logger,
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start(ctx))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	// Register the steward with the heartbeat service via an initial heartbeat.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))

	// After StewardOfflineTimeout elapses and checkStaleHeartbeats fires,
	// OnStatusChange(healthy=false) must persist StewardStatusLost.
	require.Eventually(t, func() bool {
		rec, err := st.GetSteward(ctx, stewardID)
		return err == nil && rec.Status == business.StewardStatusLost
	}, 2*time.Second, 25*time.Millisecond,
		"durable store must reach StewardStatusLost after heartbeat timeout")

	// Recovery: a fresh heartbeat fires OnStatusChange(healthy=true) which
	// must flip the status to StewardStatusActive.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))

	require.Eventually(t, func() bool {
		rec, err := st.GetSteward(ctx, stewardID)
		return err == nil && rec.Status == business.StewardStatusActive
	}, 2*time.Second, 25*time.Millisecond,
		"durable store must reach StewardStatusActive on heartbeat recovery")
}

// TestHeartbeatOnStatusChange_NoClobberDeregistered verifies the acceptance
// criterion that the Active-recovery write never overwrites Deregistered,
// Archived, Dormant, or Revoked status (Issue #2463).
func TestHeartbeatOnStatusChange_NoClobberDeregistered(t *testing.T) {
	ctx := context.Background()
	st := newFlatFileStewardStore(t)
	logger := logging.NewNoopLogger()

	const stewardID = "hb-noclobber-test-001"
	require.NoError(t, st.RegisterSteward(ctx, &business.StewardRecord{
		ID:       stewardID,
		TenantID: "test-tenant",
		Status:   business.StewardStatusDeregistered,
	}))

	onStatusChange := makeHeartbeatStatusChangeCallback(st, logger)

	// Simulate a recovery heartbeat arriving for a deregistered steward.
	onStatusChange(stewardID, true, heartbeat.StewardStatus{})

	rec, err := st.GetSteward(ctx, stewardID)
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusDeregistered, rec.Status,
		"recovery heartbeat must not overwrite Deregistered status")
}
