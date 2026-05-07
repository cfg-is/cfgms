// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// stubLeaderStatus is a minimal test double for leader-check behavior.
// It is NOT a mock: it has no expectations and carries only a fixed boolean.
type stubLeaderStatus struct{ leader bool }

func (s *stubLeaderStatus) IsLeader() bool { return s.leader }

// validPushPayload returns a minimal valid StewardConfiguration body.
func validPushPayload() push.StewardConfiguration {
	return push.StewardConfiguration{
		ConfigID: "cfg-001",
		Version:  "1.0.0",
		TenantID: "tenant-abc",
	}
}

func marshalPayload(t *testing.T, v interface{}) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

// setupPushServer creates a test server and returns the audit manager so tests
// can call Flush and then query the audit store for emitted events.
func setupPushServer(t *testing.T) (*Server, *audit.Manager) {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false
	logger := logging.NewNoopLogger()

	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil,
		auditMgr,
		nil, // No command publisher: fanout is out of scope for push handler unit tests
		nil, // No push store for audit-only push tests
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})

	return server, auditMgr
}

// TestHandleConfigPush_Leader verifies that a valid request on the leader node
// returns 202 Accepted with a non-empty push_id and status "accepted".
func TestHandleConfigPush_Leader(t *testing.T) {
	server := setupTestServer(t)
	// nil pushLeaderStatus → treated as leader (OSS single-node default)
	server.pushLeaderStatus = nil

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.PushID, "push_id must be non-empty")
	assert.Equal(t, "accepted", resp.Status)
}

// TestHandleConfigPush_NonLeader verifies that a request forwarded to a
// follower node returns 503 Service Unavailable with {"error":"not the leader"}.
func TestHandleConfigPush_NonLeader(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = &stubLeaderStatus{leader: false}

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "not the leader", resp["error"])
}

// TestHandleConfigPush_MissingFields verifies that omitting any required field
// returns 400 Bad Request with an informative error message.
func TestHandleConfigPush_MissingFields(t *testing.T) {
	tests := []struct {
		name    string
		payload push.StewardConfiguration
	}{
		{
			name: "missing config_id",
			payload: push.StewardConfiguration{
				Version:  "1.0.0",
				TenantID: "tenant-abc",
			},
		},
		{
			name: "missing version",
			payload: push.StewardConfiguration{
				ConfigID: "cfg-001",
				TenantID: "tenant-abc",
			},
		},
		{
			name: "missing tenant_id",
			payload: push.StewardConfiguration{
				ConfigID: "cfg-001",
				Version:  "1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := setupTestServer(t)

			body := marshalPayload(t, tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.handleConfigPush(rec, req)

			require.Equal(t, http.StatusBadRequest, rec.Code, "expected 400 for %s", tt.name)

			var resp map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			assert.Contains(t, resp["error"], "required", "error message must mention required fields")
		})
	}
}

// TestHandleConfigPush_InvalidJSON verifies that a malformed body returns 400
// with an appropriate error message.
func TestHandleConfigPush_InvalidJSON(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push",
		bytes.NewBufferString("{not valid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "invalid request body", resp["error"])
}

// TestHandleConfigPush_RouteRegistered verifies the route is wired into the
// router and that authentication is enforced (no key → 401, not 404).
func TestHandleConfigPush_RouteRegistered(t *testing.T) {
	server := setupTestServer(t)

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	// No API key supplied → 401, not 404. Route exists.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleConfigPush_AuditEventEmitted verifies that a successful push on
// the leader records a "config.push.initiated" audit event in the audit store.
func TestHandleConfigPush_AuditEventEmitted(t *testing.T) {
	server, auditMgr := setupPushServer(t)
	server.pushLeaderStatus = nil // leader

	payload := validPushPayload()
	body := marshalPayload(t, payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	// Flush the async audit write queue before querying the store.
	require.NoError(t, auditMgr.Flush(context.Background()))

	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"config.push.initiated"},
	})
	require.NoError(t, err)
	require.Len(t, entries, 1, "expected exactly one config.push.initiated audit entry")
	assert.Equal(t, payload.TenantID, entries[0].TenantID)
	assert.Equal(t, "config.push.initiated", entries[0].Action)
}

// syncedControlPlane is a real ControlPlaneProvider for handler-level fanout tests.
// It records steward IDs from SendCommand calls and signals a WaitGroup so tests
// can synchronize with the fire-and-forget goroutine.
type syncedControlPlane struct {
	mu       sync.Mutex
	received []string
	wg       sync.WaitGroup
}

func (c *syncedControlPlane) ReceivedIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.received))
	copy(out, c.received)
	return out
}

func (c *syncedControlPlane) Name() string      { return "synced-recording" }
func (c *syncedControlPlane) IsConnected() bool { return true }

func (c *syncedControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (c *syncedControlPlane) Start(_ context.Context) error { return nil }
func (c *syncedControlPlane) Stop(_ context.Context) error  { return nil }

func (c *syncedControlPlane) SendCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
	defer c.wg.Done()
	c.mu.Lock()
	c.received = append(c.received, cmd.Command.StewardID)
	c.mu.Unlock()
	return nil
}

func (c *syncedControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, _ []string) (*controlplaneTypes.FanOutResult, error) {
	return nil, fmt.Errorf("FanOutCommand must not be called; route via SendCommand through TriggerConfigSync")
}

func (c *syncedControlPlane) SubscribeCommands(_ context.Context, _ string, _ controlplaneInterfaces.CommandHandler) error {
	return nil
}

func (c *syncedControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}

func (c *syncedControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ controlplaneInterfaces.EventHandler) error {
	return nil
}

func (c *syncedControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}

func (c *syncedControlPlane) SubscribeHeartbeats(_ context.Context, _ controlplaneInterfaces.HeartbeatHandler) error {
	return nil
}

func (c *syncedControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

// registerActiveSteward registers a steward and immediately transitions it to
// "active" status via a heartbeat, matching the real steward lifecycle.
// Returns the controller-assigned steward ID (not the DNA ID).
func registerActiveSteward(t *testing.T, svc *service.ControllerService, dnaID string) string {
	t.Helper()
	ctx := context.Background()
	resp, err := svc.AcceptRegistration(ctx, &ctrlproto.RegisterRequest{
		Version:    "1.0.0",
		InitialDna: &common.DNA{Id: dnaID},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.StewardId, "AcceptRegistration must return a generated steward ID")
	_, err = svc.ProcessHeartbeat(ctx, &ctrlproto.HeartbeatRequest{
		StewardId: resp.StewardId,
		Status:    "active",
	})
	require.NoError(t, err)
	return resp.StewardId
}

// makeSyncedPublisher creates a real commands.Publisher backed by the synced control plane.
func makeSyncedPublisher(t *testing.T, cp *syncedControlPlane) *commands.Publisher {
	t.Helper()
	pub, err := commands.New(&commands.Config{
		ControlPlane: cp,
		Signer:       nil,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	return pub
}

// TestHandleConfigPush_FanoutNoActiveStewards verifies that when commandPublisher is
// wired but no active stewards exist, the handler still returns 202 and no SendCommand
// calls are dispatched.
func TestHandleConfigPush_FanoutNoActiveStewards(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = nil // leader

	cp := &syncedControlPlane{}
	server.commandPublisher = makeSyncedPublisher(t, cp)

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)
	// No active stewards → Fanout skips all → no SendCommand calls.
	// cp.received is never written by the goroutine, so this read is race-free.
	assert.Empty(t, cp.ReceivedIDs())
}

// TestHandleConfigPush_FanoutToActiveStewards verifies that when commandPublisher is
// wired and an active steward exists, the fire-and-forget goroutine dispatches
// TriggerConfigSync (via SendCommand) to that steward.
func TestHandleConfigPush_FanoutToActiveStewards(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = nil // leader

	cp := &syncedControlPlane{}
	server.commandPublisher = makeSyncedPublisher(t, cp)

	stewardID := registerActiveSteward(t, server.controllerService, "fanout-dna-1")

	// Expect exactly one TriggerConfigSync call (one active steward).
	cp.wg.Add(1)

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the fire-and-forget goroutine to deliver to the active steward.
	cp.wg.Wait()

	assert.ElementsMatch(t, []string{stewardID}, cp.ReceivedIDs())
}

// TestHandleConfigPush_PersistenceRecord verifies that a successful push request
// creates a PushRecord with status in_progress in the push store before fan-out
// begins. No commandPublisher is wired so the goroutine never runs and the record
// stays in_progress — confirming durable capture regardless of delivery state.
func TestHandleConfigPush_PersistenceRecord(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false
	logger := logging.NewNoopLogger()

	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	pushStore := storageManager.GetPushStore()
	require.NotNil(t, pushStore, "push store must be available from test storage")

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil,
		auditMgr,
		nil,       // No command publisher: goroutine never runs, record stays in_progress
		pushStore, // Wire real push store
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})

	server.pushLeaderStatus = nil // leader

	payload := validPushPayload()
	body := marshalPayload(t, payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	// The push record must be durably written before the handler returns 202.
	// No commandPublisher means the goroutine never runs, so the record
	// remains in_progress — exactly what GetPendingPushes returns.
	ctx := context.Background()
	pending, err := pushStore.GetPendingPushes(ctx)
	require.NoError(t, err)
	require.Len(t, pending, 1, "expected exactly one in_progress push record")

	record := pending[0]
	assert.Equal(t, business.PushStatusInProgress, record.Status)
	assert.Equal(t, payload.ConfigID, record.ConfigID)
	assert.Equal(t, payload.TenantID, record.TenantID)
	assert.Equal(t, payload.Version, record.Version)
	assert.NotEmpty(t, record.ID)
	assert.NotEmpty(t, record.Data, "push record must have marshalled payload for replay")
}

// failingControlPlane is a ControlPlaneProvider whose SendCommand always returns an error,
// enabling tests that verify the PushStatusFailed branch in the fan-out goroutine.
type failingControlPlane struct {
	syncedControlPlane
	sendErr error
}

func (c *failingControlPlane) SendCommand(_ context.Context, _ *controlplaneTypes.SignedCommand) error {
	defer c.wg.Done()
	return c.sendErr
}

// makePushServerWithStore creates a test server wired with both a command publisher
// and a real push store so that the fan-out goroutine's UpdatePushStatus paths can be exercised.
func makePushServerWithStore(t *testing.T, cp controlplaneInterfaces.ControlPlaneProvider) (*Server, business.PushStore) {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false
	logger := logging.NewNoopLogger()

	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	pushStore := storageManager.GetPushStore()
	require.NotNil(t, pushStore)

	pub, err := commands.New(&commands.Config{ControlPlane: cp, Signer: nil, Logger: logger})
	require.NoError(t, err)

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil,
		auditMgr,
		pub,       // real command publisher
		pushStore, // real push store
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})
	return server, pushStore
}

// TestHandleConfigPush_PersistenceStatusCompleted verifies that when the fan-out goroutine
// succeeds for all active stewards, the push record status is updated to completed.
func TestHandleConfigPush_PersistenceStatusCompleted(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)
	server.pushLeaderStatus = nil // leader

	stewardID := registerActiveSteward(t, server.controllerService, "persist-complete-dna-1")
	cp.wg.Add(1)

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the fire-and-forget goroutine to finish delivery and update status.
	cp.wg.Wait()

	// Allow the goroutine's UpdatePushStatus call to complete.
	assert.ElementsMatch(t, []string{stewardID}, cp.ReceivedIDs())

	// Status must be completed since delivery succeeded.
	ctx := context.Background()
	pending, err := pushStore.GetPendingPushes(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending, "no in_progress records should remain after successful delivery")

	// Retrieve the record by checking for completed status (GetPendingPushes skips completed).
	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.PushID)

	// Poll briefly for the status update to land (goroutine runs concurrently with wg.Wait).
	var updated *business.PushRecord
	for i := 0; i < 20; i++ {
		updated, err = pushStore.GetPush(ctx, resp.PushID)
		if err == nil && updated.Status == business.PushStatusCompleted {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusCompleted, updated.Status,
		"push record must be marked completed after successful fan-out delivery")
}

// TestHandleConfigPush_PersistenceStatusFailed verifies that when the fan-out goroutine
// fails for all targeted stewards, the push record status is updated to failed.
func TestHandleConfigPush_PersistenceStatusFailed(t *testing.T) {
	cp := &failingControlPlane{
		syncedControlPlane: syncedControlPlane{},
		sendErr:            fmt.Errorf("simulated delivery failure"),
	}
	server, pushStore := makePushServerWithStore(t, cp)
	server.pushLeaderStatus = nil // leader

	// Register an active steward so the fanout targets it and fails.
	registerActiveSteward(t, server.controllerService, "persist-fail-dna-1")
	cp.wg.Add(1)

	body := marshalPayload(t, validPushPayload())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the goroutine to attempt delivery and update the status.
	cp.wg.Wait()

	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.PushID)

	// Poll briefly for the status update to land.
	ctx := context.Background()
	var updated *business.PushRecord
	var err error
	for i := 0; i < 20; i++ {
		updated, err = pushStore.GetPush(ctx, resp.PushID)
		if err == nil && updated.Status == business.PushStatusFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusFailed, updated.Status,
		"push record must be marked failed when all targeted stewards fail delivery")
}
