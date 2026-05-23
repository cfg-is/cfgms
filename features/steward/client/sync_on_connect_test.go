// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client exercises the on-(re)connect config sync introduced in Issue #1720.
//
// When a steward reconnects after being offline, it calls syncConfigNow to pull
// any config that was stored by the controller during the offline window.
package client

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/steward/execution"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configReturnSession overrides ReceiveConfig to return a real signed-config payload.
type configReturnSession struct {
	testDataPlaneSession
	data    []byte
	version string
}

func (s *configReturnSession) ReceiveConfig(_ context.Context) (*dpTypes.ConfigTransfer, error) {
	return &dpTypes.ConfigTransfer{Data: s.data, Version: s.version}, nil
}

// buildMinimalSignedConfigBytes returns a marshalled SignedConfig suitable for
// passing through syncConfigNow without a signature verifier.
func buildMinimalSignedConfigBytes(t *testing.T, stewardID string) []byte {
	t.Helper()
	protoConfig := &controllerpb.SignedConfig{
		Config: &controllerpb.StewardConfig{
			Steward: &controllerpb.StewardSettings{Id: stewardID},
		},
	}
	data, err := proto.Marshal(protoConfig)
	require.NoError(t, err)
	return data
}

// TestSyncConfigNow_AppliesConfigAndPublishesStatus verifies that syncConfigNow
// pulls config from the data plane, applies it via the executor, and publishes a
// config-applied event to the control plane. This is the core mechanism that delivers
// deferred config to a reconnecting steward (Issue #1720).
func TestSyncConfigNow_AppliesConfigAndPublishesStatus(t *testing.T) {
	const stewardID = "steward-sync-on-connect"
	configData := buildMinimalSignedConfigBytes(t, stewardID)

	sess := &configReturnSession{
		testDataPlaneSession: *newTestSession(),
		data:                 configData,
		version:              "v-deferred-1",
	}

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, sess, exec, capture, stewardID, "tenant-sync-test")

	err = c.syncConfigNow(context.Background(), "on-connect", nil)
	require.NoError(t, err, "syncConfigNow must succeed for a valid stored config")

	// Verify config-applied event published.
	events := drainEvents(capture.events)
	var configApplied bool
	for _, evt := range events {
		if evt.Type == cpTypes.EventConfigApplied {
			configApplied = true
			break
		}
	}
	assert.True(t, configApplied,
		"a config-applied event must be published after syncConfigNow completes; got types: %v",
		func() []cpTypes.EventType {
			var types []cpTypes.EventType
			for _, e := range events {
				types = append(types, e.Type)
			}
			return types
		}())
}

// TestSyncConfigNow_NilExecutor_ReturnsError verifies that syncConfigNow returns
// an error (rather than panicking) when the config executor has not yet been
// initialized. This guards the case where syncConfigNow is called before
// InitializeConfigExecutor in an unexpected ordering.
func TestSyncConfigNow_NilExecutor_ReturnsError(t *testing.T) {
	const stewardID = "steward-nil-exec"
	configData := buildMinimalSignedConfigBytes(t, stewardID)

	sess := &configReturnSession{
		testDataPlaneSession: *newTestSession(),
		data:                 configData,
		version:              "v-nil-exec",
	}

	capture := newEventCapture()
	// Create client WITHOUT an executor (configExecutor == nil).
	c := &TransportClient{
		stewardID:        stewardID,
		tenantID:         "tenant-nil-exec",
		heartbeatStop:    make(chan struct{}),
		convergenceStop:  make(chan struct{}),
		convergeInterval: 30 * time.Minute,
		logger:           newTestLogger(t),
	}
	c.mu.Lock()
	c.controlPlane = capture
	c.dataPlaneSession = sess
	c.mu.Unlock()

	err := c.syncConfigNow(context.Background(), "test", nil)
	require.Error(t, err, "syncConfigNow must return error when executor is not initialized")
	assert.Contains(t, err.Error(), "executor",
		"error message should mention the missing executor")
}
