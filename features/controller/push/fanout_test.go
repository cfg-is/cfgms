// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package push_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/push"
	"github.com/cfgis/cfgms/features/controller/service"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// recordingControlPlane is a real ControlPlaneProvider implementation that records
// steward IDs from SendCommand calls and can be configured to fail for specific IDs.
type recordingControlPlane struct {
	mu       sync.Mutex
	received []string
	failFor  map[string]error
}

func newRecordingControlPlane(failFor map[string]error) *recordingControlPlane {
	if failFor == nil {
		failFor = make(map[string]error)
	}
	return &recordingControlPlane{failFor: failFor}
}

// ReceivedIDs returns a copy of the steward IDs that received a SendCommand call.
func (r *recordingControlPlane) ReceivedIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.received))
	copy(out, r.received)
	return out
}

func (r *recordingControlPlane) Name() string      { return "recording" }
func (r *recordingControlPlane) IsConnected() bool { return true }

func (r *recordingControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (r *recordingControlPlane) Start(_ context.Context) error { return nil }
func (r *recordingControlPlane) Stop(_ context.Context) error  { return nil }

func (r *recordingControlPlane) SendCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := cmd.Command.StewardID
	if err, fail := r.failFor[id]; fail {
		return err
	}
	r.received = append(r.received, id)
	return nil
}

func (r *recordingControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, _ []string) (*controlplaneTypes.FanOutResult, error) {
	return nil, fmt.Errorf("FanOutCommand must not be called; route via SendCommand through TriggerConfigSync")
}

func (r *recordingControlPlane) SubscribeCommands(_ context.Context, _ string, _ controlplaneInterfaces.CommandHandler) error {
	return nil
}

func (r *recordingControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}

func (r *recordingControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ controlplaneInterfaces.EventHandler) error {
	return nil
}

func (r *recordingControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}

func (r *recordingControlPlane) SubscribeHeartbeats(_ context.Context, _ controlplaneInterfaces.HeartbeatHandler) error {
	return nil
}

func (r *recordingControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

// makePublisher creates a real commands.Publisher backed by the recording control plane.
func makePublisher(t *testing.T, cp *recordingControlPlane) *commands.Publisher {
	t.Helper()
	pub, err := commands.New(&commands.Config{
		ControlPlane: cp,
		Signer:       nil, // unsigned for tests
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	return pub
}

func activeSteward(id string) *service.StewardInfo {
	return &service.StewardInfo{ID: id, Status: "active", TenantID: "tenant-test"}
}

func stewardWithStatus(id, status string) *service.StewardInfo {
	return &service.StewardInfo{ID: id, Status: status, TenantID: "tenant-test"}
}

func validFanoutCfg() *push.StewardConfiguration {
	return &push.StewardConfiguration{
		ConfigID: "cfg-001",
		Version:  "1.0.0",
		TenantID: "tenant-test",
	}
}

// TestFanout_EmptyList verifies that an empty steward list yields a zero-result.
func TestFanout_EmptyList(t *testing.T) {
	cp := newRecordingControlPlane(nil)
	pub := makePublisher(t, cp)

	result := push.Fanout(context.Background(), validFanoutCfg(), nil, pub, logging.NewNoopLogger())

	assert.Empty(t, result.Succeeded)
	assert.Empty(t, result.Failed)
	assert.Empty(t, cp.ReceivedIDs())
}

// TestFanout_ActiveStewards asserts that two active stewards each receive
// TriggerConfigSync and both appear in FanoutResult.Succeeded.
func TestFanout_ActiveStewards(t *testing.T) {
	cp := newRecordingControlPlane(nil)
	pub := makePublisher(t, cp)

	stewards := []*service.StewardInfo{
		activeSteward("steward-a"),
		activeSteward("steward-b"),
	}

	result := push.Fanout(context.Background(), validFanoutCfg(), stewards, pub, logging.NewNoopLogger())

	assert.Empty(t, result.Failed)
	assert.ElementsMatch(t, []string{"steward-a", "steward-b"}, result.Succeeded)
	assert.ElementsMatch(t, []string{"steward-a", "steward-b"}, cp.ReceivedIDs())
}

// TestFanout_SkipsNonActive asserts that stewards with status "registered" and
// "lost" are not sent a TriggerConfigSync command.
func TestFanout_SkipsNonActive(t *testing.T) {
	cp := newRecordingControlPlane(nil)
	pub := makePublisher(t, cp)

	stewards := []*service.StewardInfo{
		stewardWithStatus("steward-r", "registered"),
		stewardWithStatus("steward-l", "lost"),
	}

	result := push.Fanout(context.Background(), validFanoutCfg(), stewards, pub, logging.NewNoopLogger())

	assert.Empty(t, result.Succeeded)
	assert.Empty(t, result.Failed)
	assert.Empty(t, cp.ReceivedIDs(), "non-active stewards must not receive a SendCommand call")
}

// TestFanout_PartialFailure asserts that a TriggerConfigSync failure for one
// steward is captured in FanoutResult.Failed while the other steward succeeds.
func TestFanout_PartialFailure(t *testing.T) {
	sendErr := fmt.Errorf("transport: connection refused")
	cp := newRecordingControlPlane(map[string]error{
		"steward-fail": sendErr,
	})
	pub := makePublisher(t, cp)

	stewards := []*service.StewardInfo{
		activeSteward("steward-ok"),
		activeSteward("steward-fail"),
	}

	result := push.Fanout(context.Background(), validFanoutCfg(), stewards, pub, logging.NewNoopLogger())

	assert.ElementsMatch(t, []string{"steward-ok"}, result.Succeeded)
	require.Contains(t, result.Failed, "steward-fail")
	assert.ErrorContains(t, result.Failed["steward-fail"], "connection refused")
	assert.ElementsMatch(t, []string{"steward-ok"}, cp.ReceivedIDs())
}
