// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// testDNAWiringControlPlane is a minimal in-process ControlPlaneProvider that records
// SendCommand calls and delivers injected heartbeats to a registered handler. It is
// NOT a mock — it implements the real interface and records side-effects so server
// wiring tests can observe them without requiring a live gRPC stack.
type testDNAWiringControlPlane struct {
	mu               sync.Mutex
	sentCommands     []*controlplaneTypes.SignedCommand
	heartbeatHandler cpinterfaces.HeartbeatHandler
}

var _ cpinterfaces.ControlPlaneProvider = (*testDNAWiringControlPlane)(nil)

func (p *testDNAWiringControlPlane) Name() string      { return "test-dna-wiring" }
func (p *testDNAWiringControlPlane) IsConnected() bool { return true }
func (p *testDNAWiringControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *testDNAWiringControlPlane) Start(_ context.Context) error     { return nil }
func (p *testDNAWiringControlPlane) Stop(_ context.Context) error      { return nil }
func (p *testDNAWiringControlPlane) Reconnect(_ context.Context) error { return nil }
func (p *testDNAWiringControlPlane) SendCommand(_ context.Context, sc *controlplaneTypes.SignedCommand) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sentCommands = append(p.sentCommands, sc)
	return nil
}
func (p *testDNAWiringControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, ids []string) (*controlplaneTypes.FanOutResult, error) {
	return &controlplaneTypes.FanOutResult{Succeeded: ids, Failed: map[string]error{}}, nil
}
func (p *testDNAWiringControlPlane) SubscribeCommands(_ context.Context, _ string, _ cpinterfaces.CommandHandler) error {
	return nil
}
func (p *testDNAWiringControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (p *testDNAWiringControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ cpinterfaces.EventHandler) error {
	return nil
}
func (p *testDNAWiringControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (p *testDNAWiringControlPlane) SubscribeHeartbeats(_ context.Context, handler cpinterfaces.HeartbeatHandler) error {
	p.heartbeatHandler = handler
	return nil
}
func (p *testDNAWiringControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

// injectHeartbeat drives the registered heartbeat handler directly, simulating a
// steward heartbeat arriving on the control plane.
func (p *testDNAWiringControlPlane) injectHeartbeat(ctx context.Context, hb *controlplaneTypes.Heartbeat) error {
	if p.heartbeatHandler == nil {
		return nil
	}
	return p.heartbeatHandler(ctx, hb)
}

// syncDNAStewardIDs returns the steward IDs from all sync_dna commands recorded so far.
func (p *testDNAWiringControlPlane) syncDNAStewardIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for _, sc := range p.sentCommands {
		if sc.Command.Type == controlplaneTypes.CommandSyncDNA {
			ids = append(ids, sc.Command.StewardID)
		}
	}
	return ids
}

// TestServerWiring_DNAHashMismatch_TriggersDNASync is the REQUIRED TEST for AC5
// (Issue #2524): wires SetOnDNAHashMismatch → commandPublisher.TriggerDNASync
// using the exact same closure pattern from server.go:838-848, then verifies that
// a heartbeat with a differing hash triggers exactly one sync_dna command for the
// correct steward, while a heartbeat with a matching hash triggers none.
func TestServerWiring_DNAHashMismatch_TriggersDNASync(t *testing.T) {
	cp := &testDNAWiringControlPlane{}

	pub, err := commands.New(&commands.Config{
		ControlPlane: cp,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)

	heartbeatSvc, err := heartbeat.New(&heartbeat.Config{
		ControlPlane:     cp,
		HeartbeatTimeout: 15 * time.Second,
		CheckInterval:    5 * time.Second,
		Logger:           logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	require.NoError(t, heartbeatSvc.Start(context.Background()))

	// Apply the exact wiring from server.go:838-848.
	logger := logging.NewNoopLogger()
	if heartbeatSvc != nil && pub != nil {
		heartbeatSvc.SetOnDNAHashMismatch(func(stewardID string) {
			if _, err := pub.TriggerDNASync(context.Background(), stewardID); err != nil {
				logger.Warn("Failed to trigger DNA sync after hash mismatch",
					"steward_id", stewardID, "error", err)
			}
		})
	}

	const stewardID = "steward-wiring-ac5"
	const expectedHash = "hash-v1"

	heartbeatSvc.SetExpectedDNAHash(stewardID, expectedHash)

	// Matching heartbeat — wiring must NOT publish a sync_dna command.
	require.NoError(t, cp.injectHeartbeat(context.Background(), &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   expectedHash,
	}))
	assert.Empty(t, cp.syncDNAStewardIDs(),
		"matching DNA hash must not trigger TriggerDNASync through server.go wiring")

	// Mismatching heartbeat — wiring must publish exactly one sync_dna command
	// addressed to the correct steward ID.
	require.NoError(t, cp.injectHeartbeat(context.Background(), &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
		DNAHash:   "hash-diverged",
	}))

	ids := cp.syncDNAStewardIDs()
	require.Len(t, ids, 1,
		"mismatching DNA hash must trigger exactly one TriggerDNASync call through server.go wiring")
	assert.Equal(t, stewardID, ids[0],
		"TriggerDNASync must target the steward whose hash diverged")
}
