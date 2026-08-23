// SPDX-License-Identifier: AGPL-3.0-only
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
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
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

func (c *recordingControlPlane) Reconnect(_ context.Context) error {
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

// testNoPushStoreProvider is a purpose-built test implementation of
// interfaces.StorageProvider that deliberately declines CreatePushStore. Used to
// verify that the push requirement declaration fails closed when a provider does
// not supply PushStore.
type testNoPushStoreProvider struct{}

var _ interfaces.StorageProvider = (*testNoPushStoreProvider)(nil)

func (p *testNoPushStoreProvider) Name() string             { return "test-no-push-store" }
func (p *testNoPushStoreProvider) Description() string      { return "test-only: declines push store" }
func (p *testNoPushStoreProvider) GetVersion() string       { return "0.0.1-test" }
func (p *testNoPushStoreProvider) Available() (bool, error) { return true, nil }
func (p *testNoPushStoreProvider) ClusterCapable() bool     { return false }
func (p *testNoPushStoreProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{}
}
func (p *testNoPushStoreProvider) CreateClientTenantStore(_ map[string]interface{}) (business.ClientTenantStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateConfigStore(_ map[string]interface{}) (cfgconfig.ConfigStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateRBACStore(_ map[string]interface{}) (business.RBACStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateTenantStore(_ map[string]interface{}) (business.TenantStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateRegistrationTokenStore(_ map[string]interface{}) (business.RegistrationTokenStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateTriggerStore(_ map[string]interface{}) (business.TriggerStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreatePushStore(_ map[string]interface{}) (business.PushStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreatePendingRegistrationStore(_ map[string]interface{}) (business.PendingRegistrationStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateIPTrustStore(_ map[string]interface{}) (business.IPTrustStore, error) {
	return nil, business.ErrNotSupported
}
func (p *testNoPushStoreProvider) CreateAlertStore(_ map[string]interface{}) (business.AlertStore, error) {
	return nil, business.ErrNotSupported
}

// TestPushStoreRequirement_OSSCompositeStartsCleanly verifies that the push
// store requirement does not block startup in the OSS composite (flatfile+SQLite)
// deployment shape, where SQLite supplies a non-nil PushStore.
func TestPushStoreRequirement_OSSCompositeStartsCleanly(t *testing.T) {
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
	require.NoError(t, err, "OSS composite (flatfile+SQLite) must satisfy push store requirements")
	t.Cleanup(func() { _ = srv.Stop() })

	assert.NotNil(t, srv.storageManager.GetPushStore(),
		"OSS composite must supply a non-nil push store via SQLite")
}

// TestPushStoreRequirement_DatabaseProviderShapePassesValidation verifies that
// the push requirements are satisfied when a StorageManager supplies PushStore,
// as the database provider does after Issue #3402. The SQLite provider is
// already registered as a side effect of server.go's import and supplies a
// real PushStore here without requiring a live Postgres connection.
func TestPushStoreRequirement_DatabaseProviderShapePassesValidation(t *testing.T) {
	// The sqlite provider is registered via server.go's side-effect import.
	// Use its CreatePushStore (nil config → :memory: SQLite) to obtain a real
	// PushStore, then compose a StorageManager and validate push requirements.
	sqProv, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err, "sqlite provider must be registered (server.go side-effect import)")

	pushStore, err := sqProv.CreatePushStore(nil)
	require.NoError(t, err)

	sm := interfaces.NewStorageManagerFromStores(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, pushStore,
	)

	validationErr := interfaces.ValidateStorageRequirements(sm, collectActiveStorageRequirements(nil))
	assert.NoError(t, validationErr,
		"a StorageManager with PushStore available must satisfy push requirements")
}

// TestPushStoreRequirement_ProviderDecliningStoreBlocksStartup verifies that
// when a storage provider does not supply PushStore, ValidateStorageRequirements
// fails with an error that names the push subsystem — converting the previous
// silent skip (resumePendingPushes nil-guard) into a loud startup failure.
func TestPushStoreRequirement_ProviderDecliningStoreBlocksStartup(t *testing.T) {
	provider := &testNoPushStoreProvider{}
	interfaces.RegisterStorageProvider(provider)
	t.Cleanup(func() { interfaces.UnregisterStorageProvider("test-no-push-store") })

	//nolint:staticcheck // CreateAllStoresFromConfig is retained for single-provider and test use
	sm, err := interfaces.CreateAllStoresFromConfig("test-no-push-store", nil)
	require.NoError(t, err, "provider registration must succeed before validation")

	validationErr := interfaces.ValidateStorageRequirements(sm, collectActiveStorageRequirements(nil))
	require.Error(t, validationErr,
		"a provider that declines PushStore must cause startup to fail closed")
	assert.Contains(t, validationErr.Error(), "push",
		"error must name the push subsystem so operators can diagnose the failure")
}
