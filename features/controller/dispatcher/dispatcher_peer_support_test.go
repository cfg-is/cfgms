// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/run"
	script "github.com/cfgis/cfgms/features/modules/stdlib/script"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

type peerSupportSender struct{}

func (peerSupportSender) SendMsg(interface{}) error { return nil }

// newPeerSupportHarness wires the dispatcher to a real capability resolver over a
// real connection registry, the same resolver the controller hands the dispatcher.
func newPeerSupportHarness(t *testing.T) (*actionHarness, *registry.InMemoryRegistry) {
	t.Helper()
	reg := registry.NewRegistry()
	resolver := commands.NewCapabilityResolver(reg, nil, logging.NewNoopLogger(),
		commands.WithCapabilityResolveWait(50*time.Millisecond))
	h := newActionHarness(t, func(cfg *Config) { cfg.SigningVersions = resolver })
	return h, reg
}

func connectSteward(t *testing.T, reg *registry.InMemoryRegistry, id, state string, cmdTypes []int32) {
	t.Helper()
	conn := &registry.StewardConnection{StewardID: id, Sender: peerSupportSender{}, ConnectionID: "conn-" + id, ConnectedAt: time.Now()}
	require.NoError(t, reg.Register(conn))
	conn.SettleCapabilities(state, cmdTypes, []uint32{controlplaneTypes.SigningPayloadV1})
}

// A steward action for a floor-profile steward is refused before it is signed: the
// job ends "unsupported" with the controller's text, nothing is sent, the queue
// entry is gone and the device is free for its next dispatch.
func TestDispatcher_StewardAction_FloorStewardRefusedBeforeSigning(t *testing.T) {
	h, reg := newPeerSupportHarness(t)
	connectSteward(t, reg, "floor-1", registry.CapabilityFloor, controlplaneTypes.FloorProfile().CommandTypes)
	runID, _ := h.enqueueAction(t, "floor-1", "service.start", x509ActionProof)

	h.d.dispatchForDevice(context.Background(), "floor-1")

	assert.Zero(t, h.cp.sentCount(), "an unsupported action is neither signed nor sent")
	job := h.onlyJob(t, runID)
	assert.Equal(t, run.ResultCodeUnsupported, job.ResultCode)
	assert.Equal(t, run.JobStatusFailed, job.Status)
	assert.Equal(t, "steward too old: it does not support this action", job.Stderr)
	assert.Equal(t, job.Stderr, run.ResultCodeDetail(job.ResultCode))
	assert.Empty(t, h.q.PeekForDevice("floor-1"), "the queue entry is cancelled, not re-queued")
	h.requireLockReleased(t, "floor-1", "the device is released")

	// Nothing re-sends it on a later poll.
	h.d.dispatchForDevice(context.Background(), "floor-1")
	assert.Zero(t, h.cp.sentCount())
}

func TestDispatcher_StewardAction_CurrentStewardIsSent(t *testing.T) {
	h, reg := newPeerSupportHarness(t)
	all := make([]int32, 0, 15)
	for n := int32(1); n <= 15; n++ {
		all = append(all, n)
	}
	connectSteward(t, reg, "current-1", registry.CapabilityDeclared, all)
	runID, _ := h.enqueueAction(t, "current-1", "service.start", x509ActionProof)

	h.d.dispatchForDevice(context.Background(), "current-1")

	require.Equal(t, 1, h.cp.sentCount())
	assert.Equal(t, controlplaneTypes.CommandStewardAction, h.cp.lastSent().Command.Type)
	job := h.onlyJob(t, runID)
	assert.Equal(t, run.JobStatusDispatched, job.Status)
	assert.Empty(t, job.ResultCode)
}

// A steward the controller holds no state for is not gated.
func TestDispatcher_StewardAction_StewardWithNoRecordIsNotGated(t *testing.T) {
	h, _ := newPeerSupportHarness(t)
	runID, _ := h.enqueueAction(t, "unknown-1", "service.start", x509ActionProof)

	h.d.dispatchForDevice(context.Background(), "unknown-1")

	require.Equal(t, 1, h.cp.sentCount())
	assert.Equal(t, run.JobStatusDispatched, h.onlyJob(t, runID).Status)
}

// A dispatcher built without a resolver gates nothing.
func TestDispatcher_StewardAction_NoResolverIsNotGated(t *testing.T) {
	h := newActionHarness(t)
	runID, _ := h.enqueueAction(t, "any-1", "service.start", x509ActionProof)

	h.d.dispatchForDevice(context.Background(), "any-1")

	require.Equal(t, 1, h.cp.sentCount())
	assert.Equal(t, run.JobStatusDispatched, h.onlyJob(t, runID).Status)
}

// Recording the refusal for a job that is already closed reports it as such and
// leaves the first outcome in place.
func TestRecordJobUnsupported_AlreadyTerminalJobIsLeftAlone(t *testing.T) {
	h, reg := newPeerSupportHarness(t)
	connectSteward(t, reg, "floor-2", registry.CapabilityFloor, controlplaneTypes.FloorProfile().CommandTypes)
	runID, job := h.enqueueAction(t, "floor-2", "service.start", x509ActionProof)

	require.NoError(t, h.manager.RecordJobUnsupported(context.Background(), runID, job.JobID, job.ExecutionID))
	err := h.manager.RecordJobUnsupported(context.Background(), runID, job.JobID, job.ExecutionID)
	var terminal *script.JobAlreadyTerminalError
	require.ErrorAs(t, err, &terminal)
	got := h.onlyJob(t, runID)
	assert.Equal(t, run.ResultCodeUnsupported, got.ResultCode)
	assert.Equal(t, run.JobStatusFailed, got.Status)
}
