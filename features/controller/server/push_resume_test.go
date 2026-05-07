// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	common "github.com/cfgis/cfgms/api/proto/common"
	ctrlproto "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/push"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// recordingControlPlane is a minimal ControlPlaneProvider for server-level tests.
// It records steward IDs from SendCommand calls and signals a WaitGroup so tests
// can synchronize with the fan-out goroutine.
type recordingControlPlane struct {
	mu       sync.Mutex
	received []string
	wg       sync.WaitGroup
}

// errorControlPlane is a ControlPlaneProvider whose SendCommand always returns an error,
// enabling tests for the PushStatusFailed branch in resumePendingPushes.
type errorControlPlane struct {
	recordingControlPlane
	sendErr error
}

func (c *recordingControlPlane) ReceivedIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.received))
	copy(out, c.received)
	return out
}

func (c *recordingControlPlane) Name() string      { return "recording" }
func (c *recordingControlPlane) IsConnected() bool { return true }

func (c *recordingControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (c *recordingControlPlane) Start(_ context.Context) error { return nil }
func (c *recordingControlPlane) Stop(_ context.Context) error  { return nil }

func (c *recordingControlPlane) SendCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
	defer c.wg.Done()
	c.mu.Lock()
	c.received = append(c.received, cmd.Command.StewardID)
	c.mu.Unlock()
	return nil
}

func (c *errorControlPlane) SendCommand(_ context.Context, _ *controlplaneTypes.SignedCommand) error {
	defer c.wg.Done()
	return c.sendErr
}

func (c *recordingControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, _ []string) (*controlplaneTypes.FanOutResult, error) {
	return nil, fmt.Errorf("FanOutCommand must not be called in resume tests")
}

func (c *recordingControlPlane) SubscribeCommands(_ context.Context, _ string, _ controlplaneInterfaces.CommandHandler) error {
	return nil
}

func (c *recordingControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}

func (c *recordingControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ controlplaneInterfaces.EventHandler) error {
	return nil
}

func (c *recordingControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}

func (c *recordingControlPlane) SubscribeHeartbeats(_ context.Context, _ controlplaneInterfaces.HeartbeatHandler) error {
	return nil
}

func (c *recordingControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

// makeRecordingPublisher creates a real commands.Publisher backed by the recording control plane.
func makeRecordingPublisher(t *testing.T, cp *recordingControlPlane) *commands.Publisher {
	t.Helper()
	pub, err := commands.New(&commands.Config{
		ControlPlane: cp,
		Signer:       nil,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = pub.Stop(ctx)
	})
	return pub
}

// registerResumeSteward registers a steward and transitions it to "active" status.
// Returns the controller-assigned steward ID.
func registerResumeSteward(t *testing.T, srv *Server, dnaID string) string {
	t.Helper()
	ctx := context.Background()
	resp, err := srv.controllerService.AcceptRegistration(ctx, &ctrlproto.RegisterRequest{
		Version:    "1.0.0",
		InitialDna: &common.DNA{Id: dnaID},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.StewardId)
	_, err = srv.controllerService.ProcessHeartbeat(ctx, &ctrlproto.HeartbeatRequest{
		StewardId: resp.StewardId,
		Status:    "active",
	})
	require.NoError(t, err)
	return resp.StewardId
}

// TestLeaderResumePendingPushes asserts that on startup as leader,
// GetPendingPushes() results trigger TriggerConfigSync for each affected
// steward and that the push record status is updated to completed.
func TestLeaderResumePendingPushes(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop() })

	// Wire a recording control plane and publisher. New() creates no commandPublisher
	// in OSS mode (no Transport config), so we inject one directly.
	rcp := &recordingControlPlane{}
	srv.commandPublisher = makeRecordingPublisher(t, rcp)

	// Register one active steward so resumePendingPushes has a delivery target.
	ctx := context.Background()
	stewardID := registerResumeSteward(t, srv, "resume-dna-1")

	// Create an in-progress push record as if a previous leader was interrupted.
	pushStore := srv.storageManager.GetPushStore()
	require.NotNil(t, pushStore, "push store must be available via storage manager")

	cfg2 := push.StewardConfiguration{
		ConfigID: "cfg-resume-001",
		Version:  "2.0.0",
		TenantID: "tenant-resume",
	}
	data, marshalErr := json.Marshal(&cfg2)
	require.NoError(t, marshalErr)

	pushID := "push-resume-test-1"
	require.NoError(t, pushStore.CreatePush(ctx, &business.PushRecord{
		ID:        pushID,
		ConfigID:  cfg2.ConfigID,
		TenantID:  cfg2.TenantID,
		Version:   cfg2.Version,
		Status:    business.PushStatusInProgress,
		Data:      data,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	// resumePendingPushes delivers to every active steward — expect one SendCommand.
	rcp.wg.Add(1)

	srv.resumePendingPushes(ctx)

	// Wait for the synchronous fan-out (resumePendingPushes calls push.Fanout directly).
	rcp.wg.Wait()

	// Verify TriggerConfigSync was dispatched to the active steward.
	assert.ElementsMatch(t, []string{stewardID}, rcp.ReceivedIDs(),
		"resumePendingPushes must trigger TriggerConfigSync for each active steward")

	// Verify the push record was updated to completed after successful delivery.
	updated, err := pushStore.GetPush(ctx, pushID)
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusCompleted, updated.Status,
		"push record must be marked completed after successful resume delivery")
}

// TestLeaderResumePendingPushes_NoPendingPushes verifies that resumePendingPushes
// is a no-op when no in_progress records exist in the push store.
func TestLeaderResumePendingPushes_NoPendingPushes(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop() })

	rcp := &recordingControlPlane{}
	srv.commandPublisher = makeRecordingPublisher(t, rcp)

	// No push records inserted — resumePendingPushes should be a no-op.
	srv.resumePendingPushes(context.Background())

	// No SendCommand calls should have been made.
	assert.Empty(t, rcp.ReceivedIDs(), "no SendCommand calls expected when push store is empty")
}

// TestLeaderResumePendingPushes_BadDataMarkedFailed verifies that a push record
// with an undecodable Data blob is marked PushStatusFailed and processing continues.
func TestLeaderResumePendingPushes_BadDataMarkedFailed(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop() })

	rcp := &recordingControlPlane{}
	srv.commandPublisher = makeRecordingPublisher(t, rcp)

	ctx := context.Background()
	pushStore := srv.storageManager.GetPushStore()
	require.NotNil(t, pushStore)

	pushID := "push-bad-data"
	require.NoError(t, pushStore.CreatePush(ctx, &business.PushRecord{
		ID:        pushID,
		ConfigID:  "cfg-bad",
		TenantID:  "tenant-bad",
		Version:   "1.0.0",
		Status:    business.PushStatusInProgress,
		Data:      []byte("{not valid json"),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	srv.resumePendingPushes(ctx)

	// Record with invalid data must be marked failed.
	updated, err := pushStore.GetPush(ctx, pushID)
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusFailed, updated.Status,
		"push record with invalid data must be marked failed")

	// No SendCommand calls should have been made.
	assert.Empty(t, rcp.ReceivedIDs())
}

// TestLeaderResumePendingPushes_DeliveryFailureMarkedFailed verifies that when
// all stewards fail delivery during resume, the push record is marked PushStatusFailed.
func TestLeaderResumePendingPushes_DeliveryFailureMarkedFailed(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop() })

	ecp := &errorControlPlane{
		sendErr: fmt.Errorf("simulated network failure"),
	}
	pub, err := commands.New(&commands.Config{
		ControlPlane: ecp,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = pub.Stop(ctx)
	})
	srv.commandPublisher = pub

	// Register an active steward so the fanout targets it and fails.
	ctx := context.Background()
	registerResumeSteward(t, srv, "resume-fail-dna-1")

	pushStore := srv.storageManager.GetPushStore()
	require.NotNil(t, pushStore)

	cfg2 := push.StewardConfiguration{
		ConfigID: "cfg-fail-001",
		Version:  "1.0.0",
		TenantID: "tenant-fail",
	}
	data, marshalErr := json.Marshal(&cfg2)
	require.NoError(t, marshalErr)

	pushID := "push-fail-test-1"
	require.NoError(t, pushStore.CreatePush(ctx, &business.PushRecord{
		ID:        pushID,
		ConfigID:  cfg2.ConfigID,
		TenantID:  cfg2.TenantID,
		Version:   cfg2.Version,
		Status:    business.PushStatusInProgress,
		Data:      data,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	// Expect one failed SendCommand attempt for the active steward.
	ecp.wg.Add(1)

	srv.resumePendingPushes(ctx)

	// Wait for the synchronous fan-out (resumePendingPushes calls push.Fanout directly).
	ecp.wg.Wait()

	// All deliveries failed — push record must be marked failed.
	updated, err := pushStore.GetPush(ctx, pushID)
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusFailed, updated.Status,
		"push record must be marked failed when all stewards fail delivery during resume")
}
