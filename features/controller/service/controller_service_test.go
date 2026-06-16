// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestFleetStorage creates a real SQLite storage manager for controller service tests.
func newTestFleetStorage(t *testing.T) *fleetStorage.Manager {
	t.Helper()
	cfg := fleetStorage.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.EnableDeduplication = false
	mgr, err := fleetStorage.NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

// openFleetStorageAt opens a fleet storage Manager rooted at dataDir. Reusing
// the same dataDir across two calls (with a Close in between) simulates a real
// controller restart: the second Manager starts with an empty in-memory index
// and must read persisted records back from the on-disk SQLite store.
func openFleetStorageAt(t *testing.T, dataDir string) *fleetStorage.Manager {
	t.Helper()
	cfg := fleetStorage.DefaultConfig()
	cfg.DataDir = dataDir
	cfg.EnableDeduplication = false
	mgr, err := fleetStorage.NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	return mgr
}

// makeTestDNA builds a DNA proto for testing.
func makeTestDNA(id string, attrs map[string]string) *commonpb.DNA {
	return &commonpb.DNA{
		Id:              id,
		Attributes:      attrs,
		SyncFingerprint: "fp-" + id,
	}
}

func TestNewControllerServiceWithStorage(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	assert.NotNil(t, svc)
	assert.Equal(t, 0, svc.GetStewardCount())
}

func TestNewControllerService_NoStorage(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	assert.NotNil(t, svc)
	// storeDNA with nil storage should be a no-op
	svc.storeDNA(context.Background(), "dev-1", "tenant-a", makeTestDNA("dev-1", nil), "online")
}

// TestStorageReady_OKWithWorkingStorage: a real-state readiness round-trip
// succeeds against a live durable store (Issue #2012).
func TestStorageReady_OKWithWorkingStorage(t *testing.T) {
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), newTestFleetStorage(t))
	require.NoError(t, svc.StorageReady(context.Background()))
}

// TestStorageReady_ErrorWithNoStorage: a controller with no durable storage is
// NOT ready — readiness must surface that rather than masking it (a candidate
// whose storage failed to initialize must be rejected by the cutover smoketest).
func TestStorageReady_ErrorWithNoStorage(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	err := svc.StorageReady(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

// TestStorageReady_ErrorWhenStoreUnreachable: when the durable store can no
// longer be round-tripped (here, closed mid-flight to simulate an unreachable
// backend), readiness fails. This is the real-state signal the old
// object-presence health check could not produce.
func TestStorageReady_ErrorWhenStoreUnreachable(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	require.NoError(t, svc.StorageReady(context.Background()))

	// Close the backend; a subsequent round-trip must fail.
	require.NoError(t, storage.Close())
	err := svc.StorageReady(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "round-trip failed")
}

func TestLoadFromStorage_EmptyStorage(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	err := svc.LoadFromStorage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, svc.GetStewardCount())
}

func TestLoadFromStorage_WarmRegistry(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	// Pre-populate storage with two stewards
	dna1 := makeTestDNA("dev-1", map[string]string{"os": "linux", "hostname": "h1"})
	dna2 := makeTestDNA("dev-2", map[string]string{"os": "windows", "hostname": "h2"})

	require.NoError(t, storage.Store(ctx, "dev-1", dna1, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "online"}))
	require.NoError(t, storage.Store(ctx, "dev-2", dna2, &fleetStorage.StoreOptions{TenantID: "tenant-b", Status: "offline"}))

	// Create new service and warm from storage (simulates controller restart)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	require.NoError(t, svc.LoadFromStorage(ctx))

	assert.Equal(t, 2, svc.GetStewardCount())

	info1, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok)
	assert.Equal(t, "tenant-a", info1.TenantID)
	assert.NotNil(t, info1.DNA)

	info2, ok := svc.GetStewardInfo("dev-2")
	require.True(t, ok)
	assert.Equal(t, "tenant-b", info2.TenantID)
}

func TestLoadFromStorage_LiveStewardNotOverwritten(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	// Pre-populate storage
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-old", Status: "offline"}))

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	// Register a live steward BEFORE loading from storage
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:            "dev-1",
		TenantID:      "tenant-live",
		DNA:           makeTestDNA("dev-1", map[string]string{"os": "linux"}),
		LastHeartbeat: time.Now(),
		Status:        "online",
		Metrics:       make(map[string]string),
	}
	svc.mu.Unlock()

	// Load from storage — should not overwrite the live entry
	require.NoError(t, svc.LoadFromStorage(ctx))

	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok)
	// The live entry should be preserved
	assert.Equal(t, "tenant-live", info.TenantID)
	assert.Equal(t, "online", info.Status)
}

// TestRecordHeartbeat_AdvancesRegistryAndPromotes proves the Issue #1986 fix:
// a control-plane heartbeat advances the API-served registry's LastHeartbeat and
// promotes a freshly-registered steward to "active". Without RecordHeartbeat the
// registry is frozen at the warm-loaded StoredAt and status never leaves
// "registered" even while the steward heartbeats.
func TestRecordHeartbeat_AdvancesRegistryAndPromotes(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())

	registeredAt := time.Now().Add(-72 * time.Hour)
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:            "dev-1",
		TenantID:      "tenant-a",
		LastHeartbeat: registeredAt,
		Status:        "registered",
		Metrics:       make(map[string]string),
	}
	svc.mu.Unlock()

	beat := time.Now()
	ok := svc.RecordHeartbeat("dev-1", "v0.5.0-dev", beat)
	require.True(t, ok, "heartbeat for a known steward must be recorded")

	info, found := svc.GetStewardInfo("dev-1")
	require.True(t, found)
	assert.WithinDuration(t, beat, info.LastHeartbeat, time.Millisecond,
		"last_seen must advance to the heartbeat timestamp, not stay at registration time")
	assert.Equal(t, "active", info.Status, "first heartbeat must promote registered -> active")
	assert.Equal(t, "v0.5.0-dev", info.Version, "heartbeat must populate the reported version")
}

// TestRecordHeartbeat_ZeroTimestampFallsBackToNow ensures a heartbeat carrying no
// timestamp still advances last_seen rather than zeroing it.
func TestRecordHeartbeat_ZeroTimestampFallsBackToNow(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{ID: "dev-1", Status: "active", LastHeartbeat: time.Now().Add(-time.Hour)}
	svc.mu.Unlock()

	before := time.Now()
	ok := svc.RecordHeartbeat("dev-1", "", time.Time{})
	require.True(t, ok)

	info, _ := svc.GetStewardInfo("dev-1")
	assert.False(t, info.LastHeartbeat.Before(before), "zero ts must fall back to now, not zero out last_seen")
}

// TestRecordHeartbeat_UnknownStewardReturnsFalse ensures heartbeats for stewards
// this controller does not know about are reported (not silently created).
func TestRecordHeartbeat_UnknownStewardReturnsFalse(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	ok := svc.RecordHeartbeat("ghost", "v1", time.Now())
	assert.False(t, ok, "heartbeat for an unknown steward must return false")
	_, found := svc.GetStewardInfo("ghost")
	assert.False(t, found, "RecordHeartbeat must not fabricate a registry entry")
}

func TestStoreDNA_WriteOnSync(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	// Register a steward
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:       "dev-1",
		TenantID: "tenant-a",
		DNA:      dna,
		Status:   "online",
		Metrics:  make(map[string]string),
	}
	svc.mu.Unlock()

	// Call SyncDNA — should persist to storage
	resp, err := svc.SyncDNA(ctx, dna)
	require.NoError(t, err)
	assert.Equal(t, commonpb.Status_OK, resp.Code)

	// Verify the DNA was persisted
	result, err := storage.QueryFleet(ctx, &fleetStorage.FleetFilter{TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, result.TotalCount, int64(1))
}

func TestStoreDNA_WriteOnHeartbeat(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	// Register a steward with known DNA
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:       "dev-1",
		TenantID: "tenant-a",
		DNA:      dna,
		Status:   "offline",
		Metrics:  make(map[string]string),
	}
	svc.mu.Unlock()

	// Process a heartbeat — should trigger storage write with updated status
	resp, err := svc.ProcessHeartbeat(ctx, &controllerpb.HeartbeatRequest{
		StewardId: "dev-1",
		Status:    "online",
		Metrics:   map[string]string{"cpu": "42"},
	})
	require.NoError(t, err)
	assert.Equal(t, commonpb.Status_OK, resp.Code)

	// Verify status was updated in storage
	ids, err := storage.ListAllDeviceIDs(ctx)
	require.NoError(t, err)
	assert.Contains(t, ids, "dev-1")
}

func TestStoreDNA_HeartbeatUnknownSteward(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	resp, err := svc.ProcessHeartbeat(ctx, &controllerpb.HeartbeatRequest{
		StewardId: "unknown-steward",
		Status:    "online",
	})
	require.NoError(t, err)
	assert.Equal(t, commonpb.Status_NOT_FOUND, resp.Code)
}

func TestSyncDNA_UnknownSteward(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	dna := makeTestDNA("unknown", nil)
	resp, err := svc.SyncDNA(ctx, dna)
	require.NoError(t, err)
	assert.Equal(t, commonpb.Status_NOT_FOUND, resp.Code)
}

func TestDNASurvivesControllerRestart(t *testing.T) {
	// This integration test verifies that DNA persisted during one controller
	// session is available after simulating a restart (new service, same storage).
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	// --- Session 1: register steward and sync DNA ---
	svc1 := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	dna := makeTestDNA("dev-persist", map[string]string{
		"os":           "linux",
		"architecture": "amd64",
		"hostname":     "persistent-host",
	})

	svc1.mu.Lock()
	svc1.stewards["dev-persist"] = &StewardInfo{
		ID:       "dev-persist",
		TenantID: "tenant-persist",
		DNA:      dna,
		Status:   "online",
		Metrics:  make(map[string]string),
	}
	svc1.mu.Unlock()

	resp, err := svc1.SyncDNA(ctx, dna)
	require.NoError(t, err)
	assert.Equal(t, commonpb.Status_OK, resp.Code)

	// --- Session 2: new service instance, same storage (simulates restart) ---
	svc2 := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	require.NoError(t, svc2.LoadFromStorage(ctx))

	// DNA should survive the simulated restart
	assert.Equal(t, 1, svc2.GetStewardCount())

	info, ok := svc2.GetStewardInfo("dev-persist")
	require.True(t, ok)
	assert.Equal(t, "tenant-persist", info.TenantID)
	require.NotNil(t, info.DNA)
	assert.Equal(t, "linux", info.DNA.Attributes["os"])
	assert.Equal(t, "amd64", info.DNA.Attributes["architecture"])
	assert.Equal(t, "persistent-host", info.DNA.Attributes["hostname"])
}

// TestRegisterSteward_PersistsAcrossManagerRestart proves a steward registered
// via the HTTP path survives a controller restart. The second ControllerService
// is backed by a fresh storage Manager opened on the same data directory — its
// in-memory index is empty, so warm-load must read steward records from SQL.
// This is the path a real restart depends on; tests that reuse one Manager keep
// the index populated and cannot catch a regression here.
func TestRegisterSteward_PersistsAcrossManagerRestart(t *testing.T) {
	dataDir := t.TempDir()
	ctx := context.Background()

	// --- Session 1: register two stewards, then shut storage down. ---
	mgr1 := openFleetStorageAt(t, dataDir)
	svc1 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr1)
	require.NoError(t, svc1.RegisterSteward("steward-1", "tenant-a", "addr-1", "registered"))
	require.NoError(t, svc1.RegisterSteward("steward-2", "tenant-b", "addr-2", "quarantined"))
	require.NoError(t, mgr1.Close())

	// --- Session 2: fresh Manager on the same data dir (empty index). ---
	mgr2 := openFleetStorageAt(t, dataDir)
	defer func() { _ = mgr2.Close() }()
	svc2 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr2)
	require.NoError(t, svc2.LoadFromStorage(ctx))

	assert.Equal(t, 2, svc2.GetStewardCount())

	info1, ok := svc2.GetStewardInfo("steward-1")
	require.True(t, ok)
	assert.Equal(t, "tenant-a", info1.TenantID)
	assert.Equal(t, "registered", info1.Status)

	info2, ok := svc2.GetStewardInfo("steward-2")
	require.True(t, ok)
	assert.Equal(t, "tenant-b", info2.TenantID)
	assert.Equal(t, "quarantined", info2.Status)
}

// TestDNASurvivesControllerRestart_FreshManager verifies that DNA synced during
// one controller session is warm-loaded after a restart when the new controller
// opens a fresh storage Manager (empty in-memory index) on the same data dir.
func TestDNASurvivesControllerRestart_FreshManager(t *testing.T) {
	dataDir := t.TempDir()
	ctx := context.Background()

	// --- Session 1: register, then sync full DNA. ---
	mgr1 := openFleetStorageAt(t, dataDir)
	svc1 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr1)
	require.NoError(t, svc1.RegisterSteward("dev-persist", "tenant-persist", "addr-1", "registered"))

	dna := makeTestDNA("dev-persist", map[string]string{
		"os":           "linux",
		"architecture": "amd64",
		"hostname":     "persistent-host",
	})
	resp, err := svc1.SyncDNA(ctx, dna)
	require.NoError(t, err)
	require.Equal(t, commonpb.Status_OK, resp.Code)
	require.NoError(t, mgr1.Close())

	// --- Session 2: fresh Manager on the same data dir. ---
	mgr2 := openFleetStorageAt(t, dataDir)
	defer func() { _ = mgr2.Close() }()
	svc2 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr2)
	require.NoError(t, svc2.LoadFromStorage(ctx))

	assert.Equal(t, 1, svc2.GetStewardCount())

	info, ok := svc2.GetStewardInfo("dev-persist")
	require.True(t, ok)
	assert.Equal(t, "tenant-persist", info.TenantID)
	require.NotNil(t, info.DNA)
	assert.Equal(t, "linux", info.DNA.Attributes["os"])
	assert.Equal(t, "amd64", info.DNA.Attributes["architecture"])
	assert.Equal(t, "persistent-host", info.DNA.Attributes["hostname"])
}

func TestLoadFromStorage_NilStorage(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	// LoadFromStorage with no storage should be a no-op, not a panic
	err := svc.LoadFromStorage(context.Background())
	require.NoError(t, err)
}

func TestRegisterSteward_Idempotent(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterSteward("steward-1", "tenant-a", "addr-1", "registered"))

	// Second call with same ID overwrites (idempotent)
	require.NoError(t, svc.RegisterSteward("steward-1", "tenant-a", "addr-2", "quarantined"))

	all := svc.GetAllStewards()
	assert.Len(t, all, 1)
	assert.Equal(t, "quarantined", all[0].Status)
}

func TestRegisterSteward_MultipleStewards(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterSteward("steward-1", "tenant-a", "addr-1", "registered"))
	require.NoError(t, svc.RegisterSteward("steward-2", "tenant-b", "addr-2", "registered"))

	all := svc.GetAllStewards()
	assert.Len(t, all, 2)

	ids := make(map[string]bool)
	for _, s := range all {
		ids[s.ID] = true
	}
	assert.True(t, ids["steward-1"])
	assert.True(t, ids["steward-2"])
}

func TestRegisterSteward_FieldsPopulated(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())

	before := time.Now()
	require.NoError(t, svc.RegisterSteward("steward-1", "tenant-x", "addr-1", "registered"))
	after := time.Now()

	info, ok := svc.GetStewardInfo("steward-1")
	require.True(t, ok)
	assert.Equal(t, "steward-1", info.ID)
	assert.Equal(t, "tenant-x", info.TenantID)
	assert.Equal(t, "registered", info.Status)
	assert.True(t, !info.LastHeartbeat.Before(before))
	assert.True(t, !info.LastHeartbeat.After(after))
}

// --- Issue #2008: registry repopulation on cert-reuse reconnect / restart ---

// TestEnsureSteward_AddsAbsentStewardWithDurableTenant proves the PRIMARY fix:
// a steward that reconnects via cert-reuse (no fresh HTTP registration) is added
// to the admin registry on the authenticated connect, with its tenant resolved
// authoritatively from durable storage.
func TestEnsureSteward_AddsAbsentStewardWithDurableTenant(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	// Seed durable storage as if the steward had registered in a previous run.
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "registered"}))

	// Fresh service WITHOUT warm-load: the steward is absent from the registry,
	// exactly the cert-reuse reconnect gap.
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	_, found := svc.GetStewardInfo("dev-1")
	require.False(t, found, "precondition: steward must be absent before the connect hook fires")

	// Connect hook supplies only the mTLS CN and an empty tenant.
	svc.EnsureSteward("dev-1", "", "active")

	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok, "EnsureSteward must add the absent steward")
	assert.Equal(t, "active", info.Status)
	assert.Equal(t, "tenant-a", info.TenantID, "tenant must come from durable storage, not the empty hook value")
	assert.NotNil(t, info.DNA)
}

// TestEnsureSteward_IgnoresCallerTenantWhenDurableExists proves a steward-supplied
// tenant can never override the authoritative storage-derived tenant.
func TestEnsureSteward_IgnoresCallerTenantWhenDurableExists(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-real", Status: "registered"}))

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	// A hostile/incorrect tenant is passed in; storage must win.
	svc.EnsureSteward("dev-1", "tenant-attacker", "active")

	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok)
	assert.Equal(t, "tenant-real", info.TenantID, "durable tenant must override any caller-supplied tenant")
}

// TestEnsureSteward_RefreshesExistingWithoutDuplicating proves idempotence: an
// already-present entry is refreshed (LastHeartbeat advanced, registered->active)
// rather than duplicated.
func TestEnsureSteward_RefreshesExistingWithoutDuplicating(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())

	old := time.Now().Add(-time.Hour)
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:            "dev-1",
		TenantID:      "tenant-a",
		LastHeartbeat: old,
		Status:        "registered",
		Metrics:       make(map[string]string),
	}
	svc.mu.Unlock()

	svc.EnsureSteward("dev-1", "", "active")

	assert.Equal(t, 1, svc.GetStewardCount(), "existing steward must not be duplicated")
	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok)
	assert.Equal(t, "active", info.Status, "registered must be promoted to active on reconnect")
	assert.True(t, info.LastHeartbeat.After(old), "LastHeartbeat must be refreshed")
	assert.Equal(t, "tenant-a", info.TenantID, "tenant must be preserved")
}

// TestEnsureSteward_TrulyNewStewardNoOp proves the safe behaviour for a steward
// with no durable record and no supplied tenant: EnsureSteward declines rather
// than fabricating an entry with an unknown tenant (HTTP registration is the
// correct first-contact path).
func TestEnsureSteward_TrulyNewStewardNoOp(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	svc.EnsureSteward("brand-new", "", "active")

	_, found := svc.GetStewardInfo("brand-new")
	assert.False(t, found, "a steward with no durable tenant must not be fabricated")
	assert.Equal(t, 0, svc.GetStewardCount())
}

// TestEnsureSteward_SurvivesControllerRestart proves the upserted entry is
// persisted to durable storage so a later restart's warm-load finds it.
func TestEnsureSteward_SurvivesControllerRestart(t *testing.T) {
	dataDir := t.TempDir()
	ctx := context.Background()

	// Run 1: seed registration record, then a reconnecting steward is ensured.
	mgr1 := openFleetStorageAt(t, dataDir)
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, mgr1.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "registered"}))
	svc1 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr1)
	svc1.EnsureSteward("dev-1", "", "active")
	info1, ok := svc1.GetStewardInfo("dev-1")
	require.True(t, ok)
	assert.Equal(t, "active", info1.Status)
	require.NoError(t, mgr1.Close())

	// Run 2: simulated restart — fresh manager + service, warm-load from disk.
	mgr2 := openFleetStorageAt(t, dataDir)
	t.Cleanup(func() { _ = mgr2.Close() })
	svc2 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr2)
	require.NoError(t, svc2.LoadFromStorage(ctx))

	info2, ok := svc2.GetStewardInfo("dev-1")
	require.True(t, ok, "ensured steward must survive a controller restart via warm-load")
	assert.Equal(t, "tenant-a", info2.TenantID)
	assert.Equal(t, "active", info2.Status, "persisted status must round-trip as active across restart")
	assert.NotNil(t, info2.DNA, "DNA must round-trip across restart")
}

// TestEnsureSteward_ConcurrentCallsNoDuplicate proves the check-and-insert under
// s.mu serializes concurrent connect-hook upserts: many simultaneous
// EnsureSteward calls for the same steward produce exactly one registry entry
// (no TOCTOU duplicate) carrying the durable tenant.
func TestEnsureSteward_ConcurrentCallsNoDuplicate(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "registered"}))

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			svc.EnsureSteward("dev-1", "", "active")
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, svc.GetStewardCount(), "concurrent EnsureSteward must not duplicate the entry")
	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok)
	assert.Equal(t, "tenant-a", info.TenantID)
	assert.Equal(t, "active", info.Status)
}

// TestRecordHeartbeat_BackstopAddsAbsentStewardWithDurableTenant proves the
// BACKSTOP: a heartbeat from a steward absent in the registry self-heals within
// one beat when a durable tenant is resolvable.
func TestRecordHeartbeat_BackstopAddsAbsentStewardWithDurableTenant(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "registered"}))

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	_, found := svc.GetStewardInfo("dev-1")
	require.False(t, found, "precondition: steward absent before heartbeat")

	beat := time.Now()
	ok := svc.RecordHeartbeat("dev-1", "v1", beat)
	require.True(t, ok, "backstop must record the heartbeat for an absent-but-known steward")

	info, found := svc.GetStewardInfo("dev-1")
	require.True(t, found, "backstop must add the absent steward")
	assert.Equal(t, "active", info.Status)
	assert.Equal(t, "tenant-a", info.TenantID, "tenant must be durable-derived, not steward-supplied")
	assert.WithinDuration(t, beat, info.LastHeartbeat, time.Millisecond)
}

// TestRecordHeartbeat_BackstopDeclinesWithoutDurableTenant proves the
// no-fabrication contract is preserved when no durable tenant exists: rather
// than guessing a tenant, RecordHeartbeat returns false and leaves repopulation
// to the connect hook / HTTP registration.
func TestRecordHeartbeat_BackstopDeclinesWithoutDurableTenant(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)

	ok := svc.RecordHeartbeat("ghost", "v1", time.Now())
	assert.False(t, ok, "no durable tenant -> must not fabricate a tenant-scoped entry")
	_, found := svc.GetStewardInfo("ghost")
	assert.False(t, found)
}

// TestRecordHeartbeat_BackstopRefreshesExisting proves the backstop does not
// duplicate or disturb an already-present entry.
func TestRecordHeartbeat_BackstopRefreshesExisting(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "registered"}))

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	require.NoError(t, svc.LoadFromStorage(ctx))
	require.Equal(t, 1, svc.GetStewardCount())

	beat := time.Now()
	ok := svc.RecordHeartbeat("dev-1", "v2", beat)
	require.True(t, ok)

	assert.Equal(t, 1, svc.GetStewardCount(), "existing steward must not be duplicated by the backstop")
	info, _ := svc.GetStewardInfo("dev-1")
	assert.Equal(t, "active", info.Status)
	assert.Equal(t, "v2", info.Version)
}
