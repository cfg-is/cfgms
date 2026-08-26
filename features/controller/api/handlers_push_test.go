// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
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
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	sqliteprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	configstorewriter "github.com/cfgis/cfgms/pkg/entitygraph/writers/configstore"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// stubLeaderStatus is a minimal test double for leadership-check behavior.
// It is NOT a mock: it has no expectations and carries only a fixed boolean.
type stubLeaderStatus struct{ leader bool }

func (s *stubLeaderStatus) HasLeadership() bool { return s.leader }

// validPushPayload returns a minimal valid configPushRequest body.
// The default selector is "all"; the TenantID is "tenant-abc".
func validPushPayload() configPushRequest {
	return configPushRequest{
		Selector: "all",
		StewardConfiguration: push.StewardConfiguration{
			ConfigID: "cfg-001",
			Version:  "1.0.0",
			TenantID: "tenant-abc",
		},
	}
}

func marshalPayload(t *testing.T, v interface{}) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

// newPushRequest builds a POST /api/v1/config/push request with the given
// principal and body. Use withAdminPrincipal or withScopedPrincipal to inject
// the principal after calling this.
func newPushRequest(t *testing.T, payload interface{}) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", marshalPayload(t, payload))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// setupPushServer creates a test server and returns the audit manager so tests
// can call Flush and then query the audit store for emitted events.
func setupPushServer(t *testing.T) (*Server, *audit.Manager) {
	t.Helper()
	setTestSecretsEnv(t)

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
		nil, // No blob store needed
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
	server.pushLeaderStatus = nil // nil → treated as leader

	req := withAdminPrincipal(newPushRequest(t, validPushPayload()))
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.PushID, "push_id must be non-empty")
	assert.Equal(t, "accepted", resp.Status)
}

// TestHandleConfigPush_NoLeadership_Rejects503 is the story #3389 REQUIRED TEST: the
// push gate rejects with 503 when leadership is held by Raft but the lease has
// expired. The leaderStatus interface only exposes HasLeadership() (Issue #3389 —
// IsRaftLeader() is intentionally not reachable through it, ADR-029 Decision 3), so
// "Raft leader with an expired lease" and "not the Raft leader at all" are the same
// observable state at this layer: HasLeadership() == false. stubLeaderStatus{leader:
// false} represents exactly that state — the handler cannot distinguish the two
// underlying causes, and per the interface's own design it should not need to.
func TestHandleConfigPush_NoLeadership_Rejects503(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = &stubLeaderStatus{leader: false}

	// Leadership check runs before principal check — no principal needed here.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", marshalPayload(t, validPushPayload()))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "not the leader", resp["error"])

	// REQUIRED TEST (promoted from Constraints to an explicit AC, story #3389): the
	// response must not name or imply which other node currently holds leadership.
	// respondError's wire shape is always exactly {"error": message} — asserting the
	// map has no keys beyond "error" is what makes this independently verifiable
	// rather than an unstated assumption about respondError's implementation.
	assert.Len(t, resp, 1, "error response must carry no fields beyond \"error\" — no node ID, address, or topology hint")
}

// TestHandleConfigPush_RealSingleServerMode_AcceptsUnconditionally is the story
// #3389 REQUIRED TEST: SingleServerMode accepts pushes unconditionally — no new
// rejection path for OSS single-node. Unlike the other tests in this file, this
// wires a REAL *ha.Manager (not a nil pushLeaderStatus, which only proves the
// nil-checker shortcut) constructed in SingleServerMode, proving HasLeadership()
// itself returns true unconditionally there and that the real type satisfies
// leaderStatus end to end.
func TestHandleConfigPush_RealSingleServerMode_AcceptsUnconditionally(t *testing.T) {
	server := setupTestServer(t)

	storageManager := pkgtesting.SetupTestStorage(t)
	haManager, err := ha.NewManager(ha.DefaultConfig(), logging.NewNoopLogger(), storageManager, nil, "")
	require.NoError(t, err)
	require.Equal(t, ha.SingleServerMode, haManager.GetDeploymentMode())

	server.pushLeaderStatus = haManager

	req := withAdminPrincipal(newPushRequest(t, validPushPayload()))
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "a real SingleServerMode ha.Manager must never reject a push")
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

			req := withAdminPrincipal(newPushRequest(t, tt.payload))
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
	req = withAdminPrincipal(req)
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", marshalPayload(t, validPushPayload()))
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
	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
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

func (c *syncedControlPlane) Reconnect(_ context.Context) error { return nil }

// registerActiveSteward registers a steward with the given tenantID and
// immediately transitions it to "active" status via a heartbeat, matching
// the real steward lifecycle. Returns the controller-assigned steward ID.
func registerActiveSteward(t *testing.T, svc *service.ControllerService, dnaID string, tenantID string) string {
	t.Helper()
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
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

	payload := validPushPayload()
	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)
	// No active stewards → Fanout skips all → no SendCommand calls.
	// cp.received is never written by the goroutine, so this read is race-free.
	assert.Empty(t, cp.ReceivedIDs())
}

// TestHandleConfigPush_FanoutToActiveStewards verifies that when commandPublisher is
// wired and an active steward exists in the push's tenant, the fire-and-forget
// goroutine dispatches TriggerConfigSync (via SendCommand) to that steward.
func TestHandleConfigPush_FanoutToActiveStewards(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = nil // leader

	cp := &syncedControlPlane{}
	server.commandPublisher = makeSyncedPublisher(t, cp)

	payload := validPushPayload()
	stewardID := registerActiveSteward(t, server.controllerService, "fanout-dna-1", payload.TenantID)

	// Expect exactly one TriggerConfigSync call (one active steward).
	cp.wg.Add(1)

	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the fire-and-forget goroutine to deliver to the active steward.
	cp.wg.Wait()

	assert.ElementsMatch(t, []string{stewardID}, cp.ReceivedIDs())
}

// newConfigStoreWriterProvider builds a real SQLite-backed entity-graph provider
// and a real configstore.Writer over it, wires the writer into the server via
// SetConfigStoreWriter, and returns the provider so the test can query it. No
// mocks: the writer records desired-state observations into a live SQLite store.
func newConfigStoreWriterProvider(t *testing.T, server *Server) *sqliteprovider.SQLiteEntityGraphProvider {
	t.Helper()
	p, err := sqliteprovider.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	w, err := configstorewriter.New(p)
	require.NoError(t, err)
	server.SetConfigStoreWriter(w)
	return p
}

// TestHandleConfigPush_ConfigStoreWriterIngestsDesiredState verifies the happy
// path of the egConfigstoreWriter block: with a real SQLite-backed writer wired
// via SetConfigStoreWriter, a successful push records a desired-state observation
// for each targeted steward's EID, retrievable via GetDesiredState with the
// config revision carried by the push.
func TestHandleConfigPush_ConfigStoreWriterIngestsDesiredState(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = nil // leader

	p := newConfigStoreWriterProvider(t, server)

	payload := validPushPayload()
	stewardID := registerActiveSteward(t, server.controllerService, "eg-ingest-dna-1", payload.TenantID)

	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	// Ingest is synchronous (runs before the 202 response), so the desired-state
	// observation is already durable in the entity graph for the targeted steward.
	eid, err := egtypes.NewEID("cfgms", "controller", stewardID)
	require.NoError(t, err)

	ds, err := p.GetDesiredState(context.Background(), eid)
	require.NoError(t, err)
	require.NotNil(t, ds, "desired-state observation must be recorded for the targeted steward")
	assert.Equal(t, payload.Version, ds.ConfigRevision,
		"desired-state ConfigRevision must match the pushed config version")
}

// TestHandleConfigPush_ConfigStoreWriterFailureDoesNotBlock verifies the
// best-effort error path: when the wired writer's Ingest fails, the failure is
// swallowed (logged as a warning) and the push still returns 202 Accepted. The
// failure is produced by a real closed-store provider, not a mock.
func TestHandleConfigPush_ConfigStoreWriterFailureDoesNotBlock(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = nil // leader

	p, err := sqliteprovider.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	w, err := configstorewriter.New(p)
	require.NoError(t, err)
	// Close the underlying store so every Ingest attempt fails against a real,
	// non-mock provider whose database connection is gone.
	require.NoError(t, p.Close())
	server.SetConfigStoreWriter(w)

	payload := validPushPayload()
	registerActiveSteward(t, server.controllerService, "eg-fail-dna-1", payload.TenantID)

	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	// The Ingest failure must not block the push.
	require.Equal(t, http.StatusAccepted, rec.Code)
}

// TestHandleConfigPush_PersistenceRecord verifies that a successful push request
// creates a PushRecord with status in_progress in the push store before fan-out
// begins. No commandPublisher is wired so the goroutine never runs and the record
// stays in_progress — confirming durable capture regardless of delivery state.
func TestHandleConfigPush_PersistenceRecord(t *testing.T) {
	setTestSecretsEnv(t)

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
		nil,       // No blob store needed
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})

	server.pushLeaderStatus = nil // leader

	payload := validPushPayload()
	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
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

// syncedPushStore wraps a real PushStore and signals statusUpdated after each
// UpdatePushStatus call has committed to the underlying store. The fan-out
// goroutine calls UpdatePushStatus as its final action (after SendCommand →
// wg.Done fires), so tests that assert on the terminal record status must block
// on this signal — not on the control plane's WaitGroup, which unblocks too early.
// This replaces the prohibited time.Sleep polling loop with a deterministic
// completion primitive tied to the exact write the test is asserting on.
type syncedPushStore struct {
	business.PushStore
	statusUpdated chan struct{}
}

func newSyncedPushStore(inner business.PushStore) *syncedPushStore {
	return &syncedPushStore{
		PushStore:     inner,
		statusUpdated: make(chan struct{}, 1),
	}
}

// UpdatePushStatus delegates to the wrapped store, then signals statusUpdated
// after the write returns so a waiting test observes the committed final state.
// The buffered channel plus non-blocking send means callers that never drain it
// (tests that don't assert on status) are unaffected.
func (s *syncedPushStore) UpdatePushStatus(ctx context.Context, id string, status business.PushStatus) error {
	err := s.PushStore.UpdatePushStatus(ctx, id, status)
	select {
	case s.statusUpdated <- struct{}{}:
	default:
	}
	return err
}

// waitForStatusUpdate blocks until the fan-out goroutine's UpdatePushStatus call
// completes, failing the test on timeout. Deterministic: the signal fires only
// after the underlying store write returns.
func (s *syncedPushStore) waitForStatusUpdate(t *testing.T) {
	t.Helper()
	select {
	case <-s.statusUpdated:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fan-out goroutine to update push status")
	}
}

// makePushServerWithStore creates a test server wired with both a command publisher
// and a real push store so that the fan-out goroutine's UpdatePushStatus paths can be exercised.
// The returned store is a syncedPushStore wrapping the real store; tests that assert on
// the terminal push status use waitForStatusUpdate to synchronize with the goroutine.
func makePushServerWithStore(t *testing.T, cp controlplaneInterfaces.ControlPlaneProvider) (*Server, *syncedPushStore) {
	t.Helper()
	setTestSecretsEnv(t)

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

	rawPushStore := storageManager.GetPushStore()
	require.NotNil(t, rawPushStore)
	pushStore := newSyncedPushStore(rawPushStore)

	pub, err := commands.New(&commands.Config{ControlPlane: cp, Signer: nil, Logger: logger})
	require.NoError(t, err)

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil,
		auditMgr,
		pub,       // real command publisher
		pushStore, // synced push store (wraps the real store, signals on status update)
		nil,       // No blob store needed
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

	payload := validPushPayload()
	stewardID := registerActiveSteward(t, server.controllerService, "persist-complete-dna-1", payload.TenantID)
	cp.wg.Add(1)

	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the fire-and-forget goroutine to finish delivery (SendCommand → wg.Done).
	cp.wg.Wait()
	assert.ElementsMatch(t, []string{stewardID}, cp.ReceivedIDs())

	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.PushID)

	// UpdatePushStatus runs after wg.Done() inside the goroutine. Block on the
	// push store's completion signal so the terminal status write has committed
	// before we assert — no sleep-based polling.
	pushStore.waitForStatusUpdate(t)

	ctx := context.Background()
	updated, err := pushStore.GetPush(ctx, resp.PushID)
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusCompleted, updated.Status,
		"push record must be marked completed after successful fan-out delivery")

	// Now that UpdatePushStatus has completed, no in_progress records should remain.
	pending, err := pushStore.GetPendingPushes(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending, "no in_progress records should remain after successful delivery")
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

	payload := validPushPayload()
	// Register an active steward so the fanout targets it and fails.
	registerActiveSteward(t, server.controllerService, "persist-fail-dna-1", payload.TenantID)
	cp.wg.Add(1)

	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for the goroutine to attempt delivery and update the status.
	cp.wg.Wait()

	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.PushID)

	// Block on the push store's completion signal so the terminal status write
	// has committed before we assert — no sleep-based polling.
	pushStore.waitForStatusUpdate(t)

	ctx := context.Background()
	updated, err := pushStore.GetPush(ctx, resp.PushID)
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusFailed, updated.Status,
		"push record must be marked failed when all targeted stewards fail delivery")
}

// --- Selector targeting + tenant isolation tests (Issue #2366 ACs) ---

// TestHandleConfigPush_EmptySelector verifies that a request with an empty
// selector is rejected with 400 — there is no implicit "all" default.
func TestHandleConfigPush_EmptySelector(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = nil

	body := configPushRequest{
		Selector: "", // explicitly empty
		StewardConfiguration: push.StewardConfiguration{
			ConfigID: "cfg-001",
			Version:  "1.0.0",
			TenantID: "tenant-abc",
		},
	}
	req := withAdminPrincipal(newPushRequest(t, body))
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "selector is required")
}

// TestHandleConfigPush_MissingPrincipal verifies that a request without an
// authenticated principal is rejected with 401.
func TestHandleConfigPush_MissingPrincipal(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = nil

	// No principal injected into context.
	req := newPushRequest(t, validPushPayload())
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleConfigPush_TenantCallerCrosstenantRejected verifies that a
// tenant-scoped caller submitting a cfg.TenantID different from their own is
// rejected with 403, and no push record or fan-out is produced.
func TestHandleConfigPush_TenantCallerCrosstenantRejected(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)
	server.pushLeaderStatus = nil

	payload := validPushPayload() // TenantID = "tenant-abc"
	// Caller belongs to "tenant-other" — different from cfg.TenantID "tenant-abc".
	req := withScopedPrincipal(newPushRequest(t, payload), "tenant-other")
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "tenant")

	// No push record must have been created.
	ctx := context.Background()
	pending, err := pushStore.GetPendingPushes(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending, "403 must not produce a push record")

	// No fan-out must have been triggered.
	assert.Empty(t, cp.ReceivedIDs(), "403 must not trigger fan-out")
}

// TestHandleConfigPush_AdminCallerTenantScoped verifies that an admin caller
// (TenantID == "") pushing a config labelled with "tenant-a" reaches ONLY
// tenant-a stewards — never stewards from another tenant.
func TestHandleConfigPush_AdminCallerTenantScoped(t *testing.T) {
	cp := &syncedControlPlane{}
	server, _ := makePushServerWithStore(t, cp)
	server.pushLeaderStatus = nil

	// Register one steward in each tenant.
	stewardA := registerActiveSteward(t, server.controllerService, "admin-scope-dna-a", "tenant-a")
	registerActiveSteward(t, server.controllerService, "admin-scope-dna-b", "tenant-b")

	// Admin push targets only "tenant-a" stewards.
	payload := configPushRequest{
		Selector: "all",
		StewardConfiguration: push.StewardConfiguration{
			ConfigID: "cfg-admin-scope",
			Version:  "1.0.0",
			TenantID: "tenant-a",
		},
	}

	// Exactly one steward (stewardA) should receive a SendCommand.
	cp.wg.Add(1)

	req := withAdminPrincipal(newPushRequest(t, payload))
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	cp.wg.Wait()

	received := cp.ReceivedIDs()
	assert.ElementsMatch(t, []string{stewardA}, received,
		"admin push must reach only the tenant-a steward, not tenant-b")
}

// TestHandleConfigPush_FanoutTenantIsolation verifies that a steward belonging
// to a different tenant, or excluded by the selector, never receives
// SendCommand / TriggerConfigSync.
func TestHandleConfigPush_FanoutTenantIsolation(t *testing.T) {
	cp := &syncedControlPlane{}
	server, _ := makePushServerWithStore(t, cp)
	server.pushLeaderStatus = nil

	payload := validPushPayload() // TenantID = "tenant-abc"

	// Register target steward (matching tenant).
	stewardTarget := registerActiveSteward(t, server.controllerService, "isolation-dna-target", payload.TenantID)
	// Register non-target steward (different tenant — must NOT receive command).
	stewardOther := registerActiveSteward(t, server.controllerService, "isolation-dna-other", "tenant-other")

	// Expect exactly one SendCommand call (only the matching-tenant steward).
	cp.wg.Add(1)

	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	cp.wg.Wait()

	received := cp.ReceivedIDs()
	assert.ElementsMatch(t, []string{stewardTarget}, received,
		"fan-out must reach only the tenant-matched steward")
	assert.NotContains(t, received, stewardOther,
		"steward from a different tenant must never receive SendCommand")
}

// TestHandleConfigPush_ExplicitTenantPrefix_OutsideSubtreeRejected verifies that
// a selector carrying an explicit tenant-path prefix outside the config's tenant
// subtree is rejected with 403 (handlers_push.go:103-110). An admin caller passes
// the earlier caller-vs-cfg.TenantID auth check, so execution reaches the selector
// prefix check — which the existing TestHandleConfigPush_TenantCallerCrosstenantRejected
// never does (it is rejected at the earlier auth gate).
func TestHandleConfigPush_ExplicitTenantPrefix_OutsideSubtreeRejected(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)
	server.pushLeaderStatus = nil // leader

	body := configPushRequest{
		Selector: "tenant-other/all",
		StewardConfiguration: push.StewardConfiguration{
			ConfigID: "cfg-001",
			Version:  "1.0.0",
			TenantID: "tenant-abc",
		},
	}
	// Admin caller passes the caller-vs-cfg auth check, reaching the prefix branch.
	req := withAdminPrincipal(newPushRequest(t, body))
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "outside config tenant subtree")

	// The 403 prefix rejection must short-circuit before persistence and fan-out.
	pending, err := pushStore.GetPendingPushes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, pending, "403 prefix rejection must not create a push record")
	assert.Empty(t, cp.ReceivedIDs(), "403 prefix rejection must not trigger fan-out")
}

// TestHandleConfigPush_ExplicitTenantPrefix_ScopesToSubtree verifies that a valid
// in-subtree tenant-path prefix drives filter.TenantSubtree = parsedTenantPath
// (handlers_push.go:111): fan-out is scoped to the prefixed sub-tenant, reaching
// only its steward and excluding a sibling sub-tenant under the same config tenant.
func TestHandleConfigPush_ExplicitTenantPrefix_ScopesToSubtree(t *testing.T) {
	cp := &syncedControlPlane{}
	server, _ := makePushServerWithStore(t, cp)
	server.pushLeaderStatus = nil // leader

	// Two active stewards under sibling sub-tenants of tenant-abc.
	inScope := registerActiveSteward(t, server.controllerService, "push-prefix-c1", "tenant-abc/client-1")
	registerActiveSteward(t, server.controllerService, "push-prefix-c2", "tenant-abc/client-2")

	body := configPushRequest{
		Selector: "tenant-abc/client-1/all",
		StewardConfiguration: push.StewardConfiguration{
			ConfigID: "cfg-001",
			Version:  "1.0.0",
			TenantID: "tenant-abc",
		},
	}

	// Exactly one in-subtree steward should receive a SendCommand.
	cp.wg.Add(1)

	req := withAdminPrincipal(newPushRequest(t, body))
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code, "body: %s", rec.Body.String())

	cp.wg.Wait()
	assert.ElementsMatch(t, []string{inScope}, cp.ReceivedIDs(),
		"explicit prefix must scope fan-out to tenant-abc/client-1, excluding sibling client-2")
}

// --- GET /api/v1/config/push/{id} tests ---

// newGetPushRequest builds a GET /api/v1/config/push/{id} request with the
// push ID already injected as a mux URL variable (for direct handler calls).
func newGetPushRequest(t *testing.T, pushID string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/push/"+pushID, nil)
	return mux.SetURLVars(req, map[string]string{"id": pushID})
}

// createPushRecord inserts a push record directly into the store, returning the ID.
// Data is set to a minimal JSON blob to satisfy the NOT NULL column constraint.
func createPushRecord(t *testing.T, store business.PushStore, id, tenantID, configID string) *business.PushRecord {
	t.Helper()
	now := time.Now().UTC()
	rec := &business.PushRecord{
		ID:        id,
		ConfigID:  configID,
		TenantID:  tenantID,
		Version:   "1.0.0",
		Status:    business.PushStatusCompleted,
		Data:      []byte(`{"config_id":"` + configID + `","tenant_id":"` + tenantID + `","version":"1.0.0"}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, store.CreatePush(context.Background(), rec))
	return rec
}

// TestHandleGetConfigPush_NilStoreSends503 verifies that GET /api/v1/config/push/{id}
// returns 503 (not a panic) when the push store is not configured.
func TestHandleGetConfigPush_NilStoreSends503(t *testing.T) {
	server := setupTestServer(t)
	// pushStore is nil in setupTestServer (no store passed to New).

	req := newGetPushRequest(t, "push-does-not-matter")
	// No principal needed — nil-store check fires first.
	rec := httptest.NewRecorder()

	server.handleGetConfigPush(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "push store not available")
}

// failingGetPushStore wraps a real PushStore and overrides only GetPush to return
// a generic (non-ErrPushNotFound) error, exercising the 500 branch of
// handleGetConfigPush. It is not a mock: every method other than GetPush delegates
// to the wrapped real store, so any unanticipated call still hits a real
// implementation rather than a nil embedded interface.
type failingGetPushStore struct {
	business.PushStore
}

// newFailingGetPushStore wraps a real PushStore so all methods except GetPush
// delegate to a real implementation.
func newFailingGetPushStore(inner business.PushStore) *failingGetPushStore {
	return &failingGetPushStore{PushStore: inner}
}

func (f *failingGetPushStore) GetPush(_ context.Context, _ string) (*business.PushRecord, error) {
	return nil, errors.New("forced push store retrieval failure")
}

// TestHandleGetConfigPush_StorageError_Returns500 verifies that when GetPush
// returns a generic (non-ErrPushNotFound) error, handleGetConfigPush returns 500
// with "failed to retrieve push record" rather than 404 or a panic.
func TestHandleGetConfigPush_StorageError_Returns500(t *testing.T) {
	cp := &syncedControlPlane{}
	server, rawPushStore := makePushServerWithStore(t, cp)
	// Swap in a store whose GetPush always fails with a generic error, wrapping the
	// real store so every other method delegates to a real implementation. The
	// nil-store guard passed (store is non-nil); this exercises the 500 branch.
	server.pushStore = newFailingGetPushStore(rawPushStore)

	req := withAdminPrincipal(newGetPushRequest(t, "push-storage-error"))
	rec := httptest.NewRecorder()

	server.handleGetConfigPush(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "failed to retrieve push record", resp["error"])
}

// TestHandleGetConfigPush_UnknownID404 verifies that an unknown push ID returns 404.
func TestHandleGetConfigPush_UnknownID404(t *testing.T) {
	cp := &syncedControlPlane{}
	server, _ := makePushServerWithStore(t, cp)

	req := withAdminPrincipal(newGetPushRequest(t, "nonexistent-push-id"))
	rec := httptest.NewRecorder()

	server.handleGetConfigPush(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "push not found", resp["error"])
}

// TestHandleGetConfigPush_OwnTenantCanRead verifies that a caller retrieves the
// push record when their tenant matches the record's tenant.
func TestHandleGetConfigPush_OwnTenantCanRead(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)

	const ownerTenant = "tenant-abc"
	rec := createPushRecord(t, pushStore, "push-readable-001", ownerTenant, "cfg-001")

	req := withScopedPrincipal(newGetPushRequest(t, rec.ID), ownerTenant)
	httpRec := httptest.NewRecorder()

	server.handleGetConfigPush(httpRec, req)

	require.Equal(t, http.StatusOK, httpRec.Code)

	var resp PushStatusResponse
	require.NoError(t, json.Unmarshal(httpRec.Body.Bytes(), &resp))
	assert.Equal(t, rec.ID, resp.PushID)
	assert.Equal(t, ownerTenant, resp.TenantID)
	assert.Equal(t, "cfg-001", resp.ConfigID)
	assert.Equal(t, string(business.PushStatusCompleted), resp.Status)
}

// TestHandleGetConfigPush_CrossTenantReturn404 verifies that a caller from a
// different tenant receives 404 (not 403, not the record) to avoid leaking
// cross-tenant push existence.
func TestHandleGetConfigPush_CrossTenantReturn404(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)

	const ownerTenant = "tenant-abc"
	rec := createPushRecord(t, pushStore, "push-owned-by-abc", ownerTenant, "cfg-001")

	// Caller belongs to a different tenant.
	req := withScopedPrincipal(newGetPushRequest(t, rec.ID), "tenant-other")
	httpRec := httptest.NewRecorder()

	server.handleGetConfigPush(httpRec, req)

	// Must return 404, not 403, to avoid confirming the push ID exists.
	require.Equal(t, http.StatusNotFound, httpRec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(httpRec.Body.Bytes(), &resp))
	assert.Equal(t, "push not found", resp["error"])
}

// ── [REQUIRED TEST] Session-principal cross-tenant isolation (Issue #3143) ───────

// withSessionPrincipal injects a web-session principal exactly as
// authenticationMiddleware builds it (middleware.go webPrincipal block): GlobalScope
// is hardcoded true regardless of the account's real scope, while TenantID carries the
// session's tenant. Any handler that gates cross-tenant access on GlobalScope instead
// of the tenant subtree is bypassed by this principal.
func withSessionPrincipal(req *http.Request, tenantID string) *http.Request {
	p := &Principal{
		ID:          "web-acct:" + tenantID,
		Name:        "web-session:" + tenantID,
		Assurance:   session.AssuranceBasic,
		GlobalScope: true,
		TenantID:    tenantID,
	}
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, tenantID)
	return req.WithContext(ctx)
}

// TestHandleGetConfigPush_SessionPrincipal_CrossTenantBlocked is the required AC test
// for Issue #3143: a web-session caller scoped to tenant-a (GlobalScope=true, as set by
// the middleware) must not read tenant-b's push record. Under the previous
// "!principal.GlobalScope && record.TenantID != callerTenant" guard the GlobalScope
// flag short-circuited the check and the record was returned; the tenant-subtree guard
// makes the flag irrelevant.
func TestHandleGetConfigPush_SessionPrincipal_CrossTenantBlocked(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)

	rec := createPushRecord(t, pushStore, "push-owned-by-tenant-b", "tenant-b", "cfg-001")

	req := withSessionPrincipal(newGetPushRequest(t, rec.ID), "tenant-a")
	httpRec := httptest.NewRecorder()

	server.handleGetConfigPush(httpRec, req)

	// 404 (not 403) so the caller cannot confirm the push ID exists.
	require.Equal(t, http.StatusNotFound, httpRec.Code,
		"session principal scoped to tenant-a must not read tenant-b's push record (body: %s)", httpRec.Body.String())
	var resp map[string]string
	require.NoError(t, json.Unmarshal(httpRec.Body.Bytes(), &resp))
	assert.Equal(t, "push not found", resp["error"])
	assert.NotContains(t, httpRec.Body.String(), "cfg-001", "no record detail may leak cross-tenant")
}

// TestHandleGetConfigPush_SessionPrincipal_OwnSubtreeAllowed verifies the fix does not
// over-restrict: a session principal scoped to tenant-a reads its own record and records
// in its descendant tenants.
func TestHandleGetConfigPush_SessionPrincipal_OwnSubtreeAllowed(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)

	own := createPushRecord(t, pushStore, "push-owned-by-tenant-a", "tenant-a", "cfg-own")
	child := createPushRecord(t, pushStore, "push-owned-by-child", "tenant-a/child-1", "cfg-child")

	for _, tc := range []struct {
		name   string
		pushID string
		tenant string
	}{
		{"own_tenant", own.ID, "tenant-a"},
		{"descendant_tenant", child.ID, "tenant-a/child-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := withSessionPrincipal(newGetPushRequest(t, tc.pushID), "tenant-a")
			httpRec := httptest.NewRecorder()

			server.handleGetConfigPush(httpRec, req)

			require.Equal(t, http.StatusOK, httpRec.Code,
				"session principal scoped to tenant-a must read %s (body: %s)", tc.tenant, httpRec.Body.String())
			var resp PushStatusResponse
			require.NoError(t, json.Unmarshal(httpRec.Body.Bytes(), &resp))
			assert.Equal(t, tc.tenant, resp.TenantID)
		})
	}
}

// TestHandleGetConfigPush_AdminCanReadAnyTenant verifies that an admin caller
// can read a push record regardless of its tenant.
func TestHandleGetConfigPush_AdminCanReadAnyTenant(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)

	rec := createPushRecord(t, pushStore, "push-any-tenant-001", "tenant-xyz", "cfg-001")

	req := withAdminPrincipal(newGetPushRequest(t, rec.ID))
	httpRec := httptest.NewRecorder()

	server.handleGetConfigPush(httpRec, req)

	require.Equal(t, http.StatusOK, httpRec.Code)
	var resp PushStatusResponse
	require.NoError(t, json.Unmarshal(httpRec.Body.Bytes(), &resp))
	assert.Equal(t, rec.ID, resp.PushID)
	assert.Equal(t, "tenant-xyz", resp.TenantID)
}

// TestHandleGetConfigPush_RouteRegistered verifies that GET /api/v1/config/push/{id}
// is wired into the router and enforces authentication (no key → 401, not 404).
func TestHandleGetConfigPush_RouteRegistered(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/push/some-push-id", nil)
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	// No API key supplied → 401, not 404. Route exists and auth is enforced.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleGetConfigPush_MissingPrincipal verifies that a request without an
// authenticated principal returns 401 (after the push store nil-check passes).
func TestHandleGetConfigPush_MissingPrincipal(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)

	rec := createPushRecord(t, pushStore, "push-no-principal", "tenant-abc", "cfg-001")

	// No principal injected.
	req := newGetPushRequest(t, rec.ID)
	httpRec := httptest.NewRecorder()

	server.handleGetConfigPush(httpRec, req)

	require.Equal(t, http.StatusUnauthorized, httpRec.Code)
}

// TestHandleConfigPush_SelectorParseError verifies that an invalid selector
// expression returns 400 with the parse error message.
func TestHandleConfigPush_SelectorParseError(t *testing.T) {
	server := setupTestServer(t)
	server.pushLeaderStatus = nil

	body := configPushRequest{
		Selector: "badkey:value", // "badkey" is not a valid selector key
		StewardConfiguration: push.StewardConfiguration{
			ConfigID: "cfg-001",
			Version:  "1.0.0",
			TenantID: "tenant-abc",
		},
	}
	req := withAdminPrincipal(newPushRequest(t, body))
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "badkey")
}

// TestHandleConfigPush_FleetQueryError_Returns500 verifies that when the fleet
// query fails during selector resolution, the handler returns 500 with
// "fleet query failed" and produces no push record or fan-out. Uses the shared
// failingFleetQuery double (handlers_stewards_test.go) — a real FleetQuery
// implementation with deterministic error behavior, not a mock.
func TestHandleConfigPush_FleetQueryError_Returns500(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)
	server.pushLeaderStatus = nil // leader
	server.fleetQuery = &failingFleetQuery{}

	payload := validPushPayload()
	req := withScopedPrincipal(newPushRequest(t, payload), payload.TenantID)
	rec := httptest.NewRecorder()

	server.handleConfigPush(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "fleet query failed", resp["error"])

	// A failed fleet query must short-circuit before persistence and fan-out.
	pending, err := pushStore.GetPendingPushes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, pending, "500 fleet-query failure must not create a push record")
	assert.Empty(t, cp.ReceivedIDs(), "500 fleet-query failure must not trigger fan-out")
}

// ── Tenant isolation regression test — Issue #2781 ───────────────────────────

// TestGetConfigPush_AssuranceBoundary is a table-driven regression test
// confirming that the Assurance-based tenant-isolation gate in handlers_push.go
// is byte-for-byte equivalent to the deleted IsAdmin-based check:
//   - AssuranceBasic (admin) principal gets global read access regardless of the record's tenant.
//   - AssuranceMachine (API key) principal sees only same-tenant records (404 otherwise).
func TestGetConfigPush_AssuranceBoundary(t *testing.T) {
	const recordTenant = "tenant-abc"

	cases := []struct {
		name       string
		principal  *Principal
		callerTID  string // tenantID context value
		wantStatus int
	}{
		{
			name:       "AssuranceBasic_admin_any_tenant",
			principal:  &Principal{ID: "mtls-admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""},
			callerTID:  "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "AssuranceMachine_same_tenant",
			principal:  &Principal{ID: "api-key-abc", Assurance: session.AssuranceMachine, TenantID: recordTenant},
			callerTID:  recordTenant,
			wantStatus: http.StatusOK,
		},
		{
			name:       "AssuranceMachine_cross_tenant_404",
			principal:  &Principal{ID: "api-key-other", Assurance: session.AssuranceMachine, TenantID: "tenant-other"},
			callerTID:  "tenant-other",
			wantStatus: http.StatusNotFound,
		},
		{
			// Defense-in-depth: relay-grant principal (AssuranceMachine, tenant-other scoped)
			// must not see tenant-abc's push record — the handler's Assurance check is the barrier.
			name:       "relay_grant_AssuranceMachine_cross_tenant_404",
			principal:  &Principal{ID: "relay:device-1:exec-001", Name: "relay-script:device-1", Assurance: session.AssuranceMachine, TenantID: "tenant-other"},
			callerTID:  "tenant-other",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cp := &syncedControlPlane{}
			server, pushStore := makePushServerWithStore(t, cp)

			rec := createPushRecord(t, pushStore, "push-iso-"+tc.name, recordTenant, "cfg-001")

			req := newGetPushRequest(t, rec.ID)
			ctx := context.WithValue(req.Context(), principalContextKey, tc.principal)
			ctx = context.WithValue(ctx, ctxkeys.TenantID, tc.callerTID)
			req = req.WithContext(ctx)
			httpRec := httptest.NewRecorder()

			server.handleGetConfigPush(httpRec, req)

			assert.Equal(t, tc.wantStatus, httpRec.Code,
				"principal %+v accessing record in %q", tc.principal, recordTenant)
		})
	}
}
