// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client exercises the config-hash wiring in the CommandSyncConfig handler.
//
// Issue #1316: after CommandSyncConfig applies a config, the DNA update event
// published to the controller must carry a "config_hash" equal to the SHA-256
// hex digest of the raw received config bytes.
package client

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/steward/execution"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testConfigSession overrides ReceiveConfig on testDataPlaneSession so the
// CommandSyncConfig handler receives a controlled configData payload.
// This follows the same pattern as testDataPlaneSession in client_transport_dna_test.go —
// a real in-process test implementation of the interface, not a mocking-framework stub.
type testConfigSession struct {
	testDataPlaneSession
	data    []byte
	version string
}

var _ dataplaneInterfaces.DataPlaneSession = (*testConfigSession)(nil)

func (s *testConfigSession) ReceiveConfig(_ context.Context) (*dpTypes.ConfigTransfer, error) {
	return &dpTypes.ConfigTransfer{Data: s.data, Version: s.version}, nil
}

// eventCapture is a real in-process implementation of ControlPlaneProvider
// (following the same pattern as testDataPlaneSession) that records every event
// passed to PublishEvent into a buffered channel for test assertions.
// It does not use any mocking framework; all methods are real, minimal implementations.
type eventCapture struct {
	events chan *cpTypes.Event
}

var _ controlplaneInterfaces.ControlPlaneProvider = (*eventCapture)(nil)

func newEventCapture() *eventCapture {
	return &eventCapture{events: make(chan *cpTypes.Event, 16)}
}

func (e *eventCapture) Name() string      { return "test-event-capture" }
func (e *eventCapture) IsConnected() bool { return true }

func (e *eventCapture) Initialize(_ context.Context, _ map[string]interface{}) error { return nil }
func (e *eventCapture) Start(_ context.Context) error                                { return nil }
func (e *eventCapture) Stop(_ context.Context) error                                 { return nil }

func (e *eventCapture) SendCommand(_ context.Context, _ *cpTypes.SignedCommand) error { return nil }
func (e *eventCapture) FanOutCommand(_ context.Context, _ *cpTypes.SignedCommand, ids []string) (*cpTypes.FanOutResult, error) {
	return &cpTypes.FanOutResult{Succeeded: ids, Failed: make(map[string]error)}, nil
}
func (e *eventCapture) SubscribeCommands(_ context.Context, _ string, _ controlplaneInterfaces.CommandHandler) error {
	return nil
}
func (e *eventCapture) PublishEvent(_ context.Context, event *cpTypes.Event) error {
	e.events <- event
	return nil
}
func (e *eventCapture) SubscribeEvents(_ context.Context, _ *cpTypes.EventFilter, _ controlplaneInterfaces.EventHandler) error {
	return nil
}
func (e *eventCapture) SendHeartbeat(_ context.Context, _ *cpTypes.Heartbeat) error { return nil }
func (e *eventCapture) SubscribeHeartbeats(_ context.Context, _ controlplaneInterfaces.HeartbeatHandler) error {
	return nil
}
func (e *eventCapture) GetStats(_ context.Context) (*cpTypes.ControlPlaneStats, error) {
	return &cpTypes.ControlPlaneStats{}, nil
}
func (e *eventCapture) Reconnect(_ context.Context) error { return nil }

// drainEvents non-blockingly collects all events currently in the channel.
// Called after handler.Wait() ensures all goroutines have finished, so there
// is no race between writing and reading the channel.
func drainEvents(ch <-chan *cpTypes.Event) []*cpTypes.Event {
	var out []*cpTypes.Event
	for {
		select {
		case evt := <-ch:
			out = append(out, evt)
		default:
			return out
		}
	}
}

// newMinimalClientWithCP creates a TransportClient with all fields set under
// the mutex before any goroutine can observe them, preventing data races.
func newMinimalClientWithCP(t *testing.T, sess dataplaneInterfaces.DataPlaneSession, exec *execution.Executor, cp controlplaneInterfaces.ControlPlaneProvider, stewardID, tenantID string) *TransportClient {
	t.Helper()
	c := &TransportClient{
		stewardID:        stewardID,
		tenantID:         tenantID,
		heartbeatStop:    make(chan struct{}),
		convergenceStop:  make(chan struct{}),
		convergeInterval: 30 * time.Minute,
		logger:           newTestLogger(t),
	}
	c.mu.Lock()
	c.configExecutor = exec
	c.controlPlane = cp
	c.dataPlaneSession = sess
	c.mu.Unlock()
	return c
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestCommandSyncConfig_DNAUpdateCarriesConfigHash verifies that after the
// CommandSyncConfig handler applies a configuration, the DNA update event
// published to the controller contains a "config_hash" field equal to
// fmt.Sprintf("%x", sha256.Sum256(rawConfigBytes)) (Issue #1316).
func TestCommandSyncConfig_DNAUpdateCarriesConfigHash(t *testing.T) {
	// Build minimal valid protobuf SignedConfig so proto.Unmarshal and
	// stewardconfig.FromProto both succeed without a signature verifier.
	protoConfig := &controllerpb.SignedConfig{
		Config: &controllerpb.StewardConfig{
			Steward: &controllerpb.StewardSettings{
				Id: "test-steward-for-hash",
			},
		},
	}
	configData, err := proto.Marshal(protoConfig)
	require.NoError(t, err, "proto.Marshal must succeed for minimal SignedConfig")

	expectedHash := fmt.Sprintf("%x", sha256.Sum256(configData))

	sess := &testConfigSession{
		testDataPlaneSession: *newTestSession(),
		data:                 configData,
		version:              "v-hash-test-1",
	}

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, sess, exec, capture, "steward-hash-test", "tenant-hash-test")

	handler, err := c.setupCommandHandler(context.Background(), "steward-hash-test")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-config-hash-1",
		Type:      cpTypes.CommandSyncConfig,
		StewardID: "steward-hash-test",
		TenantID:  "tenant-hash-test",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	// handler.Wait() blocks until the async executeCommand goroutine finishes,
	// providing deterministic synchronization without any wall-clock timeout.
	handler.Wait()

	events := drainEvents(capture.events)

	var dnaEvent *cpTypes.Event
	for _, evt := range events {
		if evt.Type == cpTypes.EventDNAChanged {
			dnaEvent = evt
			break
		}
	}

	require.NotNil(t, dnaEvent,
		"EventDNAChanged must be published after CommandSyncConfig; got event types: %v",
		func() []cpTypes.EventType {
			var types []cpTypes.EventType
			for _, e := range events {
				types = append(types, e.Type)
			}
			return types
		}())

	assert.Equal(t, expectedHash, dnaEvent.Details["config_hash"],
		"DNA update event must carry config_hash = sha256(raw configData)")
}

// TestCommandSyncConfig_InvalidProto_NoDNAEvent verifies that when the config
// bytes cannot be unmarshaled, the handler fails before reaching PublishDNAUpdate
// and no EventDNAChanged event is published (error path coverage for Issue #1316).
func TestCommandSyncConfig_InvalidProto_NoDNAEvent(t *testing.T) {
	sess := &testConfigSession{
		testDataPlaneSession: *newTestSession(),
		data:                 []byte("not-valid-protobuf-bytes"),
		version:              "v-error-test",
	}

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, sess, exec, capture, "steward-err-test", "tenant-err-test")

	handler, err := c.setupCommandHandler(context.Background(), "steward-err-test")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-config-error-1",
		Type:      cpTypes.CommandSyncConfig,
		StewardID: "steward-err-test",
		TenantID:  "tenant-err-test",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))
	handler.Wait()

	events := drainEvents(capture.events)

	for _, evt := range events {
		assert.NotEqual(t, cpTypes.EventDNAChanged, evt.Type,
			"no EventDNAChanged must be published when config processing fails before PublishDNAUpdate")
	}
}
