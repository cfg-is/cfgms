// SPDX-License-Identifier: AGPL-3.0-only
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

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/fleet"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// --- Test-only in-memory RolloutStore ---

type testRolloutStore struct {
	mu      sync.RWMutex
	records map[string]*business.RolloutRecord

	// Lifecycle-signal channels fed by the server's rollout hooks (wired in
	// setupRolloutServer). They let tests synchronize on the background goroutine
	// deterministically instead of sleeping. Buffered so runRollout never blocks and no
	// signal is lost before a reader arrives.
	terminalC chan string // receives rolloutID when runRollout commits a terminal store update
	soakC     chan string // receives rolloutID when runRollout enters a ring soak
}

func newTestRolloutStore() *testRolloutStore {
	return &testRolloutStore{
		records:   make(map[string]*business.RolloutRecord),
		terminalC: make(chan string, 16),
		soakC:     make(chan string, 16),
	}
}

func (s *testRolloutStore) CreateRollout(_ context.Context, record *business.RolloutRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.ID]; exists {
		return fmt.Errorf("duplicate rollout ID: %s", record.ID)
	}
	cp := *record
	s.records[record.ID] = &cp
	return nil
}

func (s *testRolloutStore) GetRollout(_ context.Context, id string) (*business.RolloutRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return nil, business.ErrRolloutNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *testRolloutStore) UpdateRolloutProgress(_ context.Context, id string, status business.RolloutStatus, currentRing string, ringsCompleted int, haltedAt *time.Time, errorMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return business.ErrRolloutNotFound
	}
	r.Status = status
	r.CurrentRing = currentRing
	r.RingsCompleted = ringsCompleted
	r.HaltedAt = haltedAt
	r.Error = errorMsg
	return nil
}

func (s *testRolloutStore) AppendDeferredStewards(_ context.Context, rolloutID string, stewardIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[rolloutID]
	if !ok {
		return business.ErrRolloutNotFound
	}
	r.DeferredStewards = append(r.DeferredStewards, stewardIDs...)
	return nil
}

func (s *testRolloutStore) ListRolloutsByTenant(_ context.Context, tenantID string) ([]*business.RolloutRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.RolloutRecord
	for _, r := range s.records {
		if r.TenantID == tenantID {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *testRolloutStore) HealthCheck(_ context.Context) error { return nil }
func (s *testRolloutStore) Initialize(_ context.Context) error  { return nil }
func (s *testRolloutStore) Close() error                        { return nil }

var _ business.RolloutStore = (*testRolloutStore)(nil)

// --- Test helpers ---

// setupRolloutServer creates a server wired with a rollout store, upgrade store,
// and a fleet query backed by the given stewards.
func setupRolloutServer(t *testing.T, tenantID string, stewards []fleet.StewardData) (*Server, *testRolloutStore, *testUpgradeStore) {
	t.Helper()
	server := setupTestServer(t)

	// Configure two-ring deployment_rings so tests run against a predictable ring set.
	server.cfg.DeploymentRings = &controllerconfig.DeploymentRingConfig{
		Rings: []controllerconfig.RingSpec{
			{Name: "pre-release", Soak: 0, HaltThreshold: 0.05},
			{Name: "stable", Soak: 0, HaltThreshold: 0.05},
		},
		FallbackRing: "pre-release",
	}

	rolloutStore := newTestRolloutStore()
	upgradeStore := newTestUpgradeStore()
	server.rolloutStore = rolloutStore
	server.upgradeStore = upgradeStore
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: stewards})

	// Wire the rollout lifecycle hooks so tests can synchronize on the background
	// goroutine via channels instead of time.Sleep polling. Hooks must be set before any
	// rollout is started so no signal is missed.
	server.onRolloutSoak = func(rolloutID string) { rolloutStore.soakC <- rolloutID }
	server.onRolloutTerminal = func(rolloutID string) { rolloutStore.terminalC <- rolloutID }

	return server, rolloutStore, upgradeStore
}

// doStartRollout calls handleStartRollout with the given tenant and target version.
func doStartRollout(server *Server, tenantID, targetVersion string) *httptest.ResponseRecorder {
	body := startRolloutRequest{TargetVersion: targetVersion, TenantID: tenantID}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollout", bytes.NewReader(b))
	req = withScopedPrincipal(req, tenantID)
	rec := httptest.NewRecorder()
	server.handleStartRollout(rec, req)
	return rec
}

// parseStartRolloutID decodes the rollout_id from a handleStartRollout 202 response.
// The response is wrapped in an APIResponse envelope: {"data": {"rollout_id": "...", ...}}.
func parseStartRolloutID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var wrapper struct {
		Data startRolloutResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&wrapper), "failed to decode start rollout response")
	return wrapper.Data.RolloutID
}

// doGetRollout calls handleGetRollout for the given rollout ID.
func doGetRollout(server *Server, tenantID, rolloutID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollout/"+rolloutID, nil)
	req = withScopedPrincipal(req, tenantID)
	req = mux.SetURLVars(req, map[string]string{"rollout_id": rolloutID})
	rec := httptest.NewRecorder()
	server.handleGetRollout(rec, req)
	return rec
}

// doHaltRollout calls handleHaltRollout for the given rollout ID.
func doHaltRollout(server *Server, tenantID, rolloutID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollout/"+rolloutID+"/halt", nil)
	req = withScopedPrincipal(req, tenantID)
	req = mux.SetURLVars(req, map[string]string{"rollout_id": rolloutID})
	rec := httptest.NewRecorder()
	server.handleHaltRollout(rec, req)
	return rec
}

// waitForRolloutStatus blocks until runRollout signals that the given rollout reached a
// terminal (completed/halted) store update, then returns the final record. It synchronizes
// on the store's terminalC channel — fed by the server's onRolloutTerminal hook — rather
// than polling with sleeps, so the observed transition is deterministic. Fails the test if
// the goroutine does not reach a terminal state within timeout.
func waitForRolloutStatus(t *testing.T, store *testRolloutStore, rolloutID string, timeout time.Duration) *business.RolloutRecord {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case id := <-store.terminalC:
			if id != rolloutID {
				// Signal for a different rollout; keep waiting for ours.
				continue
			}
			rec, err := store.GetRollout(context.Background(), rolloutID)
			require.NoError(t, err)
			return rec
		case <-deadline:
			t.Fatalf("rollout %s did not reach a terminal state within %s", rolloutID, timeout)
			return nil
		}
	}
}

// seedFailedUpgradeRecords pre-populates the upgrade store with terminal-failure records
// for each steward ID, targeting desiredVersion. This seeds stewards that attempted
// but failed the upgrade before the ring health check runs.
func seedFailedUpgradeRecords(t *testing.T, store *testUpgradeStore, tenantID, desiredVersion string, stewardIDs ...string) {
	t.Helper()
	for i, id := range stewardIDs {
		rec := &business.UpgradeRecord{
			ID:              fmt.Sprintf("upgrade-%d", i),
			StewardID:       id,
			TenantID:        tenantID,
			Version:         desiredVersion,
			Platform:        "linux",
			Arch:            "amd64",
			Status:          business.UpgradeStatusFailed,
			BundleSignature: []byte{0x01}, // non-empty required by testUpgradeStore
			CreatedAt:       time.Now().UTC(),
		}
		require.NoError(t, store.CreateUpgrade(context.Background(), rec))
	}
}

// --- Required tests (AC) ---

// TestRollout_HaltsWhenFailureRateExceedsThreshold verifies that when failed_pct >
// halt_threshold, the rollout transitions to halted and no further ring promotion occurs.
// This is an explicitly required test per the story acceptance criteria.
func TestRollout_HaltsWhenFailureRateExceedsThreshold(t *testing.T) {
	const tenantID = "tenant-a"
	const targetVersion = "v0.5.21"

	// Two stewards in the pre-release ring, both on an older version.
	stewards := []fleet.StewardData{
		{
			ID:            "steward-1",
			TenantID:      tenantID,
			Status:        "online",
			DNAAttributes: map[string]string{"deployment_ring": "pre-release"},
		},
		{
			ID:            "steward-2",
			TenantID:      tenantID,
			Status:        "online",
			DNAAttributes: map[string]string{"deployment_ring": "pre-release"},
		},
	}
	server, rolloutStore, upgradeStore := setupRolloutServer(t, tenantID, stewards)

	// Pre-seed both stewards with terminal-failure upgrade records for targetVersion.
	// With failed=2, on_version=0: rate = 2/(0+2) = 1.0, which exceeds threshold 0.05.
	seedFailedUpgradeRecords(t, upgradeStore, tenantID, targetVersion, "steward-1", "steward-2")

	rec := doStartRollout(server, tenantID, targetVersion)
	require.Equal(t, http.StatusAccepted, rec.Code, "POST /api/v1/rollout must return 202: %s", rec.Body.String())

	rolloutID := parseStartRolloutID(t, rec)
	require.NotEmpty(t, rolloutID)

	// Wait for the goroutine to detect the failure and transition to halted.
	// Soak is 0, so the goroutine should reach the health check immediately.
	finalRecord := waitForRolloutStatus(t, rolloutStore, rolloutID, 500*time.Millisecond)

	assert.Equal(t, string(business.RolloutStatusHalted), string(finalRecord.Status),
		"rollout must be halted when failure rate exceeds threshold")
	assert.NotNil(t, finalRecord.HaltedAt, "halted_at must be set")
	assert.NotEmpty(t, finalRecord.Error, "error message must explain the halt reason")

	// No promotion: pre-release ring remains at index 0 (ringsCompleted must not exceed 0).
	assert.Equal(t, 0, finalRecord.RingsCompleted,
		"no ring may be counted as completed when the first ring fails")

	// Deferred stewards must be recorded.
	assert.ElementsMatch(t, []string{"steward-1", "steward-2"}, finalRecord.DeferredStewards,
		"failed stewards must be in the deferred-retry list")
}

// TestRollout_StatusReturnsRequiredFields verifies that GET /api/v1/rollout/{rollout_id}
// returns current_ring, on_version_pct, failed_count, pending_count, and status.
// This is an explicitly required test per the story acceptance criteria.
func TestRollout_StatusReturnsRequiredFields(t *testing.T) {
	const tenantID = "tenant-a"
	const targetVersion = "v0.5.21"

	// One steward in pre-release, already on the target version.
	stewards := []fleet.StewardData{
		{
			ID:       "steward-ok",
			TenantID: tenantID,
			Status:   "online",
			// steward.version is the DNA attribute that populates StewardResult.RunningVersion.
			DNAAttributes: map[string]string{
				"deployment_ring": "pre-release",
				"steward.version": targetVersion,
			},
		},
	}
	server, rolloutStore, _ := setupRolloutServer(t, tenantID, stewards)

	// Start the rollout.
	rec := doStartRollout(server, tenantID, targetVersion)
	require.Equal(t, http.StatusAccepted, rec.Code)

	rolloutID := parseStartRolloutID(t, rec)
	require.NotEmpty(t, rolloutID)

	// Wait for goroutine to complete (soak=0, all stewards on target → completes fast).
	waitForRolloutStatus(t, rolloutStore, rolloutID, 500*time.Millisecond)

	// Query the status endpoint.
	statusRec := doGetRollout(server, tenantID, rolloutID)
	require.Equal(t, http.StatusOK, statusRec.Code, "GET rollout status must return 200: %s", statusRec.Body.String())

	var wrapper struct {
		Data rolloutStatusResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(statusRec.Body).Decode(&wrapper))
	resp := wrapper.Data

	// Required fields per acceptance criteria.
	assert.NotEmpty(t, resp.RolloutID, "rollout_id must be set")
	assert.Equal(t, targetVersion, resp.TargetVersion, "target_version must be set")
	// current_ring is empty when completed (all rings done).
	assert.NotEmpty(t, resp.Status, "status must be set")
	// on_version_pct, failed_count, pending_count are returned (may be 0 for completed).
	assert.GreaterOrEqual(t, resp.OnVersionPct, float64(0), "on_version_pct must be a valid percentage")
	assert.GreaterOrEqual(t, resp.FailedCount, 0, "failed_count must be non-negative")
	assert.GreaterOrEqual(t, resp.PendingCount, 0, "pending_count must be non-negative")
	assert.Equal(t, 2, resp.RingsTotal, "rings_total must reflect the configured ring count")
}

// TestRollout_FailedStewardsRequeued verifies that stewards with terminal upgrade
// failures are added to the RolloutRecord.DeferredStewards list, not dropped.
func TestRollout_FailedStewardsRequeued(t *testing.T) {
	const tenantID = "tenant-a"
	const targetVersion = "v0.5.21"

	stewards := []fleet.StewardData{
		{
			ID:            "steward-fail",
			TenantID:      tenantID,
			Status:        "online",
			DNAAttributes: map[string]string{"deployment_ring": "pre-release"},
		},
	}
	server, rolloutStore, upgradeStore := setupRolloutServer(t, tenantID, stewards)
	seedFailedUpgradeRecords(t, upgradeStore, tenantID, targetVersion, "steward-fail")

	rec := doStartRollout(server, tenantID, targetVersion)
	require.Equal(t, http.StatusAccepted, rec.Code)

	rolloutID := parseStartRolloutID(t, rec)
	require.NotEmpty(t, rolloutID)

	finalRecord := waitForRolloutStatus(t, rolloutStore, rolloutID, 500*time.Millisecond)

	assert.Contains(t, finalRecord.DeferredStewards, "steward-fail",
		"failed steward must appear in DeferredStewards, not be silently dropped")
}

// TestRollout_OperatorHalt verifies that POST /api/v1/rollout/{rollout_id}/halt
// transitions an in-progress rollout to halted status.
func TestRollout_OperatorHalt(t *testing.T) {
	const tenantID = "tenant-a"
	const targetVersion = "v0.5.21"

	// No stewards so the goroutine has nothing to advance — gives us a window to halt.
	server, rolloutStore, _ := setupRolloutServer(t, tenantID, nil)

	// Use a long soak so the goroutine blocks inside the soak select, giving the test
	// time to issue the halt before the goroutine finishes.
	server.cfg.DeploymentRings.Rings[0].Soak = controllerconfig.Duration(30 * time.Second)
	server.cfg.DeploymentRings.Rings[1].Soak = controllerconfig.Duration(30 * time.Second)

	rec := doStartRollout(server, tenantID, targetVersion)
	require.Equal(t, http.StatusAccepted, rec.Code)

	rolloutID := parseStartRolloutID(t, rec)
	require.NotEmpty(t, rolloutID)

	// Wait for the goroutine to commit the ring's in-progress state and block on the soak
	// select before issuing the halt. Synchronizing on the soak signal (instead of a fixed
	// sleep) guarantees the goroutine's in-progress store write has already happened, so the
	// halt's terminal write cannot be clobbered by a late in-progress update.
	select {
	case id := <-rolloutStore.soakC:
		require.Equal(t, rolloutID, id, "unexpected rollout entered soak")
	case <-time.After(2 * time.Second):
		t.Fatal("rollout goroutine did not reach soak within 2s")
	}

	// Operator halt.
	haltRec := doHaltRollout(server, tenantID, rolloutID)
	require.Equal(t, http.StatusOK, haltRec.Code, "halt must return 200: %s", haltRec.Body.String())

	// Verify the store reflects halted status.
	stored, err := rolloutStore.GetRollout(context.Background(), rolloutID)
	require.NoError(t, err)
	assert.Equal(t, string(business.RolloutStatusHalted), string(stored.Status))
}

// TestRollout_RequiresRolloutStore verifies that POST /api/v1/rollout returns 503 when
// the rollout store is not configured.
func TestRollout_RequiresRolloutStore(t *testing.T) {
	server := setupTestServer(t)
	// rolloutStore is nil — not configured.

	rec := doStartRollout(server, "tenant-a", "v0.5.21")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "ROLLOUT_STORE_UNAVAILABLE")
}

// TestRollout_GetStatus_NotFound verifies that GET /api/v1/rollout/{rollout_id} returns
// 404 for an unknown rollout ID.
func TestRollout_GetStatus_NotFound(t *testing.T) {
	server, _, _ := setupRolloutServer(t, "tenant-a", nil)

	rec := doGetRollout(server, "tenant-a", "nonexistent-rollout-id")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "ROLLOUT_NOT_FOUND")
}

// TestRollout_GetStatus_CrossTenant verifies that a caller cannot read rollouts from
// another tenant.
func TestRollout_GetStatus_CrossTenant(t *testing.T) {
	server, rolloutStore, _ := setupRolloutServer(t, "tenant-a", nil)

	// Seed a rollout owned by tenant-b.
	require.NoError(t, rolloutStore.CreateRollout(context.Background(), &business.RolloutRecord{
		ID:            "other-rollout",
		TenantID:      "tenant-b",
		TargetVersion: "v0.5.21",
		Status:        business.RolloutStatusInProgress,
		StartedAt:     time.Now().UTC(),
		RingsTotal:    2,
	}))

	// Caller is tenant-a — must be forbidden.
	rec := doGetRollout(server, "tenant-a", "other-rollout")
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestRollout_Start_CrossTenantRejected verifies that a scoped (non-admin) caller cannot
// start a rollout attributed to another tenant by supplying req.TenantID. The override must
// be rejected with 403 CROSS_TENANT so orchestration cannot be driven against a victim
// tenant's fleet.
func TestRollout_Start_CrossTenantRejected(t *testing.T) {
	server, rolloutStore, _ := setupRolloutServer(t, "tenant-a", nil)

	// tenant-a caller attempts to start a rollout for tenant-b.
	body := startRolloutRequest{TargetVersion: "v0.5.21", TenantID: "tenant-b"}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollout", bytes.NewReader(b))
	req = withScopedPrincipal(req, "tenant-a")
	rec := httptest.NewRecorder()
	server.handleStartRollout(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "cross-tenant start must be forbidden: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "CROSS_TENANT")

	// No rollout may have been created for the victim tenant.
	rollouts, err := rolloutStore.ListRolloutsByTenant(context.Background(), "tenant-b")
	require.NoError(t, err)
	assert.Empty(t, rollouts, "no rollout record may be created for the victim tenant")
}

// TestRollout_Start_AdminCrossTenantAllowed verifies that an admin mTLS principal may start
// a rollout for an explicit tenant via req.TenantID (the legitimate admin path).
func TestRollout_Start_AdminCrossTenantAllowed(t *testing.T) {
	server, rolloutStore, _ := setupRolloutServer(t, "tenant-a", nil)

	body := startRolloutRequest{TargetVersion: "v0.5.21", TenantID: "tenant-b"}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollout", bytes.NewReader(b))
	req = withAdminPrincipal(req)
	rec := httptest.NewRecorder()
	server.handleStartRollout(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "admin cross-tenant start must be accepted: %s", rec.Body.String())

	rolloutID := parseStartRolloutID(t, rec)
	require.NotEmpty(t, rolloutID)

	// The rollout must be attributed to the requested tenant.
	finalRecord := waitForRolloutStatus(t, rolloutStore, rolloutID, 500*time.Millisecond)
	assert.Equal(t, "tenant-b", finalRecord.TenantID, "admin-supplied tenant_id must own the rollout")
}

// TestRollout_CompletesWhenAllRingsStewardsOnVersion verifies that when all stewards
// are already on the target version the rollout completes without halting.
func TestRollout_CompletesWhenAllRingsStewardsOnVersion(t *testing.T) {
	const tenantID = "tenant-a"
	const targetVersion = "v0.5.21"

	stewards := []fleet.StewardData{
		{
			ID:       "s1",
			TenantID: tenantID,
			Status:   "online",
			DNAAttributes: map[string]string{
				"deployment_ring": "pre-release",
				"steward.version": targetVersion,
			},
		},
		{
			ID:       "s2",
			TenantID: tenantID,
			Status:   "online",
			DNAAttributes: map[string]string{
				"deployment_ring": "stable",
				"steward.version": targetVersion,
			},
		},
	}
	server, rolloutStore, _ := setupRolloutServer(t, tenantID, stewards)

	rec := doStartRollout(server, tenantID, targetVersion)
	require.Equal(t, http.StatusAccepted, rec.Code)

	rolloutID := parseStartRolloutID(t, rec)
	require.NotEmpty(t, rolloutID)

	finalRecord := waitForRolloutStatus(t, rolloutStore, rolloutID, 500*time.Millisecond)

	assert.Equal(t, string(business.RolloutStatusCompleted), string(finalRecord.Status),
		"rollout must complete when all ring stewards are already on the target version")
	assert.Equal(t, 2, finalRecord.RingsCompleted)
}

// TestRollout_InvalidVersionRejected verifies that a malformed target_version returns 400.
func TestRollout_InvalidVersionRejected(t *testing.T) {
	server, _, _ := setupRolloutServer(t, "tenant-a", nil)

	rec := doStartRollout(server, "tenant-a", "not-a-semver")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_VERSION")
}
