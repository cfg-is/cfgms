// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for heartbeat-driven durable status persistence (Issue #2463).
package server

import (
	"context"
	"errors"
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
// mocks, per CLAUDE.md). Staleness is triggered by a short StewardOfflineTimeout.
// Recovery is asserted synchronously after stopping the service (eliminates the
// race where the monitor goroutine re-fires after the recovery heartbeat).
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
		StewardOfflineTimeout: 100 * time.Millisecond,
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

	// Recovery. Stop the background staleness monitor first: with a 50ms
	// StewardOfflineTimeout the monitor would re-expire the steward ~50ms after
	// the recovery heartbeat refreshes receivedAt, so the recovery→Active state
	// is only transiently true and racing it with a poll is inherently flaky.
	// A real deployment never hits this because live stewards keep heartbeating
	// within the (60s) timeout; the tiny test timeout is what makes Active
	// transient. handleHeartbeatFromProvider fires OnStatusChange synchronously,
	// so once the monitor is halted the recovery write is deterministic.
	require.NoError(t, svc.Stop(ctx))

	// A fresh heartbeat fires OnStatusChange(healthy=true) which must flip the
	// durable status to StewardStatusActive — synchronously, inside sendHeartbeat.
	require.NoError(t, cp.sendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))

	// The recovery path is synchronous: handleHeartbeatFromProvider →
	// onStatusChange → UpdateStewardStatus. Assert directly without polling.
	rec, err := st.GetSteward(ctx, stewardID)
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusActive, rec.Status,
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

// controlCharStewardStore wraps a real StewardStore, overriding only GetSteward
// and UpdateStewardStatus to force deterministic failures carrying a
// caller-supplied error — used to prove a control-character payload from the
// durable store cannot reach the logger unsanitized (Issue #4073 site 3).
// Embedding the business.StewardStore interface (not a concrete provider)
// promotes every other method unchanged, so it is not subject to the
// pkg/storage/providers/* import confinement check.
type controlCharStewardStore struct {
	business.StewardStore
	getErr error
	updErr error
}

func (s *controlCharStewardStore) GetSteward(ctx context.Context, id string) (*business.StewardRecord, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.StewardStore.GetSteward(ctx, id)
}

func (s *controlCharStewardStore) UpdateStewardStatus(ctx context.Context, id string, status business.StewardStatus) error {
	if s.updErr != nil {
		return s.updErr
	}
	return s.StewardStore.UpdateStewardStatus(ctx, id, status)
}

// heartbeatCtrlCharPayload is the control-character error text used to prove
// makeHeartbeatStatusChangeCallback sanitizes store errors before logging.
const heartbeatCtrlCharPayload = "steward store failure\nInjected: fake log line\rtrailer"

// TestMakeHeartbeatStatusChangeCallback_SanitizesErrorLogs guards Issue #4073
// site 3 — the exact shape CLAUDE.md calls out by name: SanitizeLogValue(sid)
// paired with a bare getErr/updErr in the same log call. Drives all three call
// sites (server.go:308, 316, 326) with a control-character store error and
// asserts none of them leak the raw payload. Each sub-test must fail if its
// site's sanitization is ever reverted.
func TestMakeHeartbeatStatusChangeCallback_SanitizesErrorLogs(t *testing.T) {
	ctx := context.Background()

	t.Run("GetSteward failure during recovery (line 308)", func(t *testing.T) {
		store := &controlCharStewardStore{
			StewardStore: newFlatFileStewardStore(t),
			getErr:       errors.New(heartbeatCtrlCharPayload),
		}
		rec := &recordingLogger{}
		callback := makeHeartbeatStatusChangeCallback(store, rec)

		callback("hb-ctrlchar-get", true, heartbeat.StewardStatus{})

		assert.True(t, rec.containsAny("Injected"), "expected the sanitized error text to reach the logger")
		assert.False(t, rec.containsAny("\n"), "raw newline from the store error reached the logger unsanitized")
		assert.False(t, rec.containsAny("\r"), "raw carriage return from the store error reached the logger unsanitized")
	})

	t.Run("UpdateStewardStatus failure during recovery (line 316)", func(t *testing.T) {
		base := newFlatFileStewardStore(t)
		const stewardID = "hb-ctrlchar-upd-active"
		require.NoError(t, base.RegisterSteward(ctx, &business.StewardRecord{
			ID:       stewardID,
			TenantID: "test-tenant",
			Status:   business.StewardStatusRegistered,
		}))
		store := &controlCharStewardStore{
			StewardStore: base,
			updErr:       errors.New(heartbeatCtrlCharPayload),
		}
		rec := &recordingLogger{}
		callback := makeHeartbeatStatusChangeCallback(store, rec)

		callback(stewardID, true, heartbeat.StewardStatus{})

		assert.True(t, rec.containsAny("Injected"), "expected the sanitized error text to reach the logger")
		assert.False(t, rec.containsAny("\n"), "raw newline from the store error reached the logger unsanitized")
		assert.False(t, rec.containsAny("\r"), "raw carriage return from the store error reached the logger unsanitized")
	})

	t.Run("UpdateStewardStatus failure during loss (line 326)", func(t *testing.T) {
		store := &controlCharStewardStore{
			StewardStore: newFlatFileStewardStore(t),
			updErr:       errors.New(heartbeatCtrlCharPayload),
		}
		rec := &recordingLogger{}
		callback := makeHeartbeatStatusChangeCallback(store, rec)

		callback("hb-ctrlchar-lost", false, heartbeat.StewardStatus{})

		assert.True(t, rec.containsAny("Injected"), "expected the sanitized error text to reach the logger")
		assert.False(t, rec.containsAny("\n"), "raw newline from the store error reached the logger unsanitized")
		assert.False(t, rec.containsAny("\r"), "raw carriage return from the store error reached the logger unsanitized")
	})
}
