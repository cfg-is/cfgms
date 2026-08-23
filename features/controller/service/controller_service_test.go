// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/tagstore"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
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

// makeTestDNA builds a DNA proto for testing. Host facts travel exclusively as
// ADR-017 fragments now that DNA.Attributes has been removed (Issue #3331):
// "hostname" and "os" get their own fragments so the DNA passes the
// fragment-based integrity check (Issue #3319), and every other attribute lands
// in a host:test fragment so FlattenDNAFragments round-trips the whole input map.
func makeTestDNA(id string, attrs map[string]string) *commonpb.DNA {
	var frags []*commonpb.Fragment
	if h := attrs["hostname"]; h != "" {
		frags = append(frags, mustFragment("hostname", map[string]interface{}{"hostname": h}))
	}
	if o := attrs["os"]; o != "" {
		frags = append(frags, mustFragment("host:os", map[string]interface{}{"os": o}))
	}
	other := make(map[string]interface{}, len(attrs))
	for k, v := range attrs {
		if k == "hostname" || k == "os" {
			continue
		}
		other[k] = v
	}
	if len(other) > 0 {
		frags = append(frags, mustFragment("host:test", other))
	}
	return &commonpb.DNA{
		Id:              id,
		SyncFingerprint: "fp-" + id,
		Fragments:       frags,
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
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux", "hostname": "dev-1-host"})
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
	flat := FlattenDNAFragments(info.DNA.GetFragments())
	assert.Equal(t, "linux", flat["os"])
	assert.Equal(t, "amd64", flat["architecture"])
	assert.Equal(t, "persistent-host", flat["hostname"])
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
	flat := FlattenDNAFragments(info.DNA.GetFragments())
	assert.Equal(t, "linux", flat["os"])
	assert.Equal(t, "amd64", flat["architecture"])
	assert.Equal(t, "persistent-host", flat["hostname"])
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

// TestRegisterStewardWithAttributes_SetsInitialDNA verifies that hostname and OS
// provided at registration are visible in GetStewardInfo immediately — before any
// SyncDNA call — closing the identity-blind window (Issue #2640).
func TestRegisterStewardWithAttributes_SetsInitialDNA(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())

	initialAttrs := map[string]string{"hostname": "worker-01", "os": "linux"}
	require.NoError(t, svc.RegisterStewardWithAttributes("s-attrs", "tenant-a", "addr-1", "registered", initialAttrs))

	info, ok := svc.GetStewardInfo("s-attrs")
	require.True(t, ok)
	require.NotNil(t, info.DNA)
	flat := FlattenDNAFragments(info.DNA.GetFragments())
	assert.Equal(t, "worker-01", flat["hostname"], "hostname must be visible before SyncDNA")
	assert.Equal(t, "linux", flat["os"], "os must be visible before SyncDNA")
}

// TestRegisterStewardWithAttributes_NilAttrsIsIdenticalToRegisterSteward proves the
// existing callers are unaffected: nil initialAttrs yields the same result as the
// original RegisterSteward (DNA with only the steward ID, no host facts).
func TestRegisterStewardWithAttributes_NilAttrsIsIdenticalToRegisterSteward(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterStewardWithAttributes("s-nil", "tenant-a", "addr-1", "registered", nil))

	info, ok := svc.GetStewardInfo("s-nil")
	require.True(t, ok)
	require.NotNil(t, info.DNA)
	assert.Empty(t, info.DNA.GetFragments(), "nil initialAttrs must not seed any DNA fragment")
	assert.Empty(t, FlattenDNAFragments(info.DNA.GetFragments()), "nil initialAttrs must not set any DNA host facts")
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
	require.NoError(t, storage.SetDeviceTenant(ctx, "dev-1", "tenant-a"))

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
	require.NoError(t, storage.SetDeviceTenant(ctx, "dev-1", "tenant-real"))

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
	require.NoError(t, mgr1.SetDeviceTenant(ctx, "dev-1", "tenant-a"))
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
	require.NoError(t, storage.SetDeviceTenant(ctx, "dev-1", "tenant-a"))

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
	require.NoError(t, storage.SetDeviceTenant(ctx, "dev-1", "tenant-a"))

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

// TestGetStewardInfo_ConcurrentSyncDNA_NoRace verifies that concurrent SyncDNA
// writes and GetStewardInfo reads do not produce a data race. The race detector
// catches aliased DNA pointers escaping the registry lock; proto.Clone on read
// prevents that.
func TestGetStewardInfo_ConcurrentSyncDNA_NoRace(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:       "dev-1",
		TenantID: "tenant-a",
		DNA:      dna,
		Status:   "active",
		Metrics:  make(map[string]string),
	}
	svc.mu.Unlock()

	ctx := context.Background()
	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			newDNA := makeTestDNA("dev-1", map[string]string{"os": "linux", "iter": fmt.Sprintf("%d", n)})
			_, _ = svc.SyncDNA(ctx, newDNA)
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			info, ok := svc.GetStewardInfo("dev-1")
			if ok && info.DNA != nil {
				_ = info.DNA.Id
				// Reads every fragment's canonical bytes — the race detector
				// needs the copy's payload touched, not just its slice header.
				_ = FlattenDNAFragments(info.DNA.GetFragments())
			}
		}()
	}

	wg.Wait()
}

// TestGetAllStewards_ReturnsDNACopies verifies that GetAllStewards returns fully
// isolated copies: mutating the returned DNA or Metrics must not alter the live
// registry entry.
func TestGetAllStewards_ReturnsDNACopies(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:       "dev-1",
		TenantID: "tenant-a",
		DNA:      dna,
		Status:   "active",
		Metrics:  map[string]string{"cpu": "10"},
	}
	svc.mu.Unlock()

	all := svc.GetAllStewards()
	require.Len(t, all, 1)

	require.NotEmpty(t, all[0].DNA.GetFragments(), "copy must carry the host:os fragment")
	all[0].DNA.Fragments[0].CanonicalBytes = []byte(`{"os":"windows"}`)
	all[0].Metrics["cpu"] = "99"

	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok)
	assert.Equal(t, "linux", FlattenDNAFragments(info.DNA.GetFragments())["os"],
		"live DNA must not be affected by returned copy mutation")
	assert.Equal(t, "10", info.Metrics["cpu"], "live Metrics must not be affected by returned copy mutation")
}

// TestRecordHeartbeat_VersionCapped verifies that an oversized Version string
// supplied by a steward is truncated to maxVersionLen before storage.
func TestRecordHeartbeat_VersionCapped(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:      "dev-1",
		Status:  "active",
		Metrics: make(map[string]string),
	}
	svc.mu.Unlock()

	longVersion := strings.Repeat("a", 200)
	ok := svc.RecordHeartbeat("dev-1", longVersion, time.Now())
	require.True(t, ok)

	info, found := svc.GetStewardInfo("dev-1")
	require.True(t, found)
	assert.Len(t, info.Version, maxVersionLen, "version must be capped at maxVersionLen characters")
	assert.Equal(t, strings.Repeat("a", maxVersionLen), info.Version)
}

// --- Deployment ring resolution tests (Issue #2271) ---

// makeTestRingConfig returns a DeploymentRingConfig with four rings and versions
// suitable for ring-resolution unit tests.
func makeTestRingConfig() controllerconfig.DeploymentRingConfig {
	return controllerconfig.DeploymentRingConfig{
		FallbackRing: "default",
		Rings: []controllerconfig.RingSpec{
			{Name: "pre-release", DesiredVersion: "v0.6.0-rc1"},
			{Name: "early", DesiredVersion: "v0.5.21"},
			{Name: "default", DesiredVersion: "v0.5.20"},
			{Name: "stable", DesiredVersion: "v0.5.19"},
		},
	}
}

// TestSetRingConfig_AuditLogsOnChange verifies SetRingConfig emits a "ring_set_changed"
// INFO audit log entry with actor, before, and after fields when the ring set changes.
func TestSetRingConfig_AuditLogsOnChange(t *testing.T) {
	lc := logging.NewCapturingLogger()
	svc := NewControllerService(lc)

	initial := makeTestRingConfig()
	svc.SetRingConfig(initial)

	// First set emits ring_set_changed (from empty → initial config).
	// CapturingLogger only records Info/InfoCtx into InfoEntries, so finding the
	// entry there is itself proof the audit event was emitted at INFO level.
	entry, ok := lc.FindInfo("ring_set_changed")
	require.True(t, ok, "expected INFO log entry with msg='ring_set_changed' on first SetRingConfig")
	_, hasActor := entry["actor"]
	assert.True(t, hasActor, "ring_set_changed entry must include actor field")
	_, hasAfter := entry["after"]
	assert.True(t, hasAfter, "ring_set_changed entry must include after field")

	// State is persisted correctly.
	got := svc.GetRingConfig()
	require.Len(t, got.Rings, 4)
	assert.Equal(t, "early", got.Rings[1].Name)
	assert.Equal(t, "v0.5.21", got.Rings[1].DesiredVersion)

	// Record current entry count; a second change must add exactly one more.
	countBefore := lc.InfoCount()

	// Update the ring config (version bump on early ring).
	updated := makeTestRingConfig()
	updated.Rings[1].DesiredVersion = "v0.5.22"
	svc.SetRingConfig(updated)

	countAfter := lc.InfoCount()
	assert.Equal(t, countBefore+1, countAfter,
		"SetRingConfig on changed config must emit exactly one additional log entry")

	got2 := svc.GetRingConfig()
	assert.Equal(t, "v0.5.22", got2.Rings[1].DesiredVersion,
		"SetRingConfig must persist the updated version")
}

// TestSetRingConfig_NoopOnEqualConfig verifies SetRingConfig does not emit an audit
// entry when the config is unchanged (confirmed via equal comparison logic).
func TestSetRingConfig_NoopOnEqualConfig(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	rings := makeTestRingConfig()

	// Set twice with identical config — must not panic or corrupt state.
	svc.SetRingConfig(rings)
	svc.SetRingConfig(rings)

	got := svc.GetRingConfig()
	assert.Len(t, got.Rings, 4)
}

// ---- UpdateStewardTenant tests ----

func TestUpdateStewardTenant_Success(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterSteward("s-move", "tenant-src", "addr", "registered"))

	require.NoError(t, svc.UpdateStewardTenant("s-move", "tenant-dst"))

	info, ok := svc.GetStewardInfo("s-move")
	require.True(t, ok)
	assert.Equal(t, "tenant-dst", info.TenantID, "TenantID must reflect the new tenant after move")
}

func TestUpdateStewardTenant_NotFound(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	err := svc.UpdateStewardTenant("nonexistent", "tenant-dst")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUpdateStewardTenant_PreservesOtherFields(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterSteward("s-preserve", "tenant-old", "addr-1", "active"))

	require.NoError(t, svc.UpdateStewardTenant("s-preserve", "tenant-new"))

	info, ok := svc.GetStewardInfo("s-preserve")
	require.True(t, ok)
	assert.Equal(t, "tenant-new", info.TenantID)
	assert.Equal(t, "active", info.Status, "Status must not change on tenant update")
	assert.Equal(t, "s-preserve", info.ID, "ID must not change on tenant update")
}

// ---------------------------------------------------------------------------
// SetPostDNASyncHook tests (Issue #2524)
// ---------------------------------------------------------------------------

// TestSetPostDNASyncHook_FiresAfterSyncDNA verifies that a hook registered via
// SetPostDNASyncHook is invoked after a successful SyncDNA call, receiving the
// correct steward ID and DNA proto (Issue #2524).
func TestSetPostDNASyncHook_FiresAfterSyncDNA(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	ctx := context.Background()

	require.NoError(t, svc.RegisterSteward("steward-hook", "tenant-1", "", "active"))

	type hookCall struct {
		stewardID string
		dna       *commonpb.DNA
	}
	var calls []hookCall
	svc.SetPostDNASyncHook(func(stewardID string, dna *commonpb.DNA) {
		calls = append(calls, hookCall{stewardID: stewardID, dna: dna})
	})

	dna := makeTestDNA("steward-hook", map[string]string{"os": "linux", "hostname": "hook-host", "arch": "amd64"})
	status, err := svc.SyncDNA(ctx, dna)
	require.NoError(t, err)
	require.Equal(t, commonpb.Status_OK, status.Code)

	require.Len(t, calls, 1, "hook must be called exactly once after SyncDNA")
	assert.Equal(t, "steward-hook", calls[0].stewardID)
	assert.Equal(t, FlattenDNAFragments(dna.GetFragments()), FlattenDNAFragments(calls[0].dna.GetFragments()))
}

// TestSetPostDNASyncHook_NotFiredForUnknownSteward verifies that the hook does
// NOT fire when SyncDNA is called for an unregistered steward (Issue #2524).
func TestSetPostDNASyncHook_NotFiredForUnknownSteward(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	ctx := context.Background()

	hookCalled := false
	svc.SetPostDNASyncHook(func(_ string, _ *commonpb.DNA) { hookCalled = true })

	dna := makeTestDNA("unknown-steward", map[string]string{"os": "linux"})
	status, err := svc.SyncDNA(ctx, dna)
	require.NoError(t, err)
	assert.Equal(t, commonpb.Status_NOT_FOUND, status.Code)
	assert.False(t, hookCalled, "hook must not fire for an unknown steward")
}

// TestSetPostDNASyncHook_NilHookIsNoop verifies that a nil hook (default) does
// not cause a panic when SyncDNA is called (Issue #2524).
func TestSetPostDNASyncHook_NilHookIsNoop(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	ctx := context.Background()

	require.NoError(t, svc.RegisterSteward("steward-nil-hook", "tenant-1", "", "active"))

	dna := makeTestDNA("steward-nil-hook", map[string]string{"os": "windows"})
	status, err := svc.SyncDNA(ctx, dna)
	require.NoError(t, err, "nil postDNASyncHook must not cause a panic")
	assert.Equal(t, commonpb.Status_OK, status.Code)
}

// TestSetPostDNASyncHook_HookReceivesDNACopy verifies that the hook receives
// the same DNA instance passed to SyncDNA (no accidental nil or empty DNA).
func TestSetPostDNASyncHook_HookReceivesDNACopy(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	ctx := context.Background()

	require.NoError(t, svc.RegisterSteward("steward-dnacopy", "tenant-1", "", "active"))

	var hookDNA *commonpb.DNA
	svc.SetPostDNASyncHook(func(_ string, dna *commonpb.DNA) { hookDNA = dna })

	attrs := map[string]string{"version": "2.0", "platform": "linux", "hostname": "dnacopy-host", "os": "linux"}
	dna := makeTestDNA("steward-dnacopy", attrs)
	_, err := svc.SyncDNA(ctx, dna)
	require.NoError(t, err)

	require.NotNil(t, hookDNA, "hook must receive non-nil DNA")
	assert.Equal(t, attrs, FlattenDNAFragments(hookDNA.GetFragments()), "hook DNA host facts must match the synced DNA")
}

// ---------------------------------------------------------------------------
// SetTagStore / TagStore tests (Issue #2542)
// ---------------------------------------------------------------------------

// newTagStoreForTest builds a real, initialized tagstore.Store backed by an
// on-disk SQLite file under t.TempDir(). No mocks — CFGMS mandates real
// components in tests.
func newTagStoreForTest(t *testing.T) *tagstore.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "tags_svc_test.db")
	store, err := tagstore.NewFromDSN("file:"+dbPath, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(context.Background()))
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestSetTagStore_ReturnsWiredStore verifies that after wiring a real
// tagstore.Store via SetTagStore, TagStore() returns that exact instance.
func TestSetTagStore_ReturnsWiredStore(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	store := newTagStoreForTest(t)

	svc.SetTagStore(store)

	require.Same(t, store, svc.TagStore(), "TagStore() must return the wired store instance")
}

// TestTagStore_NilBeforeWiring verifies that TagStore() returns nil before
// SetTagStore has been called (the late-wiring default).
func TestTagStore_NilBeforeWiring(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())

	assert.Nil(t, svc.TagStore(), "TagStore() must be nil before wiring")
}

// TestSetTagStore_ConcurrentAccess_NoRace verifies that concurrent SetTagStore
// writes and TagStore() reads do not produce a data race, consistent with the
// TestGetStewardInfo_ConcurrentSyncDNA_NoRace pattern. Run with -race.
func TestSetTagStore_ConcurrentAccess_NoRace(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	store := newTagStoreForTest(t)

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			svc.SetTagStore(store)
		}()
	}

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = svc.TagStore()
		}()
	}

	wg.Wait()

	require.Same(t, store, svc.TagStore(), "final TagStore() must return the wired store")
}

// ---------------------------------------------------------------------------
// SetStewardHidden tests (Issue #2944)
// ---------------------------------------------------------------------------

func TestSetStewardHidden_Success(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterSteward("s-hide", "tenant-a", "addr", "active"))

	// Default: not hidden.
	all := svc.GetAllStewards()
	require.Len(t, all, 1)
	assert.False(t, all[0].Hidden, "freshly registered steward must not be hidden")

	// Hide it.
	require.NoError(t, svc.SetStewardHidden("s-hide", true))
	all = svc.GetAllStewards()
	require.Len(t, all, 1)
	assert.True(t, all[0].Hidden, "GetAllStewards must reflect hidden=true after SetStewardHidden")

	// Un-hide it.
	require.NoError(t, svc.SetStewardHidden("s-hide", false))
	all = svc.GetAllStewards()
	require.Len(t, all, 1)
	assert.False(t, all[0].Hidden, "GetAllStewards must reflect hidden=false after SetStewardHidden")
}

func TestSetStewardHidden_NotFound(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	err := svc.SetStewardHidden("nonexistent", true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSetStewardHidden_PreservesOtherFields(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterSteward("s-preserve-hide", "tenant-b", "addr-2", "active"))

	require.NoError(t, svc.SetStewardHidden("s-preserve-hide", true))

	info, ok := svc.GetStewardInfo("s-preserve-hide")
	require.True(t, ok)
	assert.True(t, info.Hidden, "Hidden must be set")
	assert.Equal(t, "active", info.Status, "Status must not change on SetStewardHidden")
	assert.Equal(t, "tenant-b", info.TenantID, "TenantID must not change on SetStewardHidden")
}

// TestLookupDurableTenant_SurvivesControllerRestart is the acceptance test for
// Issue #3324: (1) RegisterSteward writes the steward→tenant mapping to the
// independent device_tenant table; (2) after a controller restart,
// lookupDurableTenant resolves the tenant correctly from device_tenant; (3) a
// device present only in dna_history (not device_tenant) returns ok=false,
// proving that tenant resolution no longer falls back to the flat DNA store.
func TestLookupDurableTenant_SurvivesControllerRestart(t *testing.T) {
	dataDir := t.TempDir()
	ctx := context.Background()

	mgr1 := openFleetStorageAt(t, dataDir)
	svc1 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr1)
	require.NoError(t, svc1.RegisterSteward("dev-mapped", "tenant-x", "addr-1", "registered"))

	// Seed a second device ONLY into dna_history to prove lookupDurableTenant
	// does not fall back to dna_history for tenant resolution.
	dna := makeTestDNA("dev-dnaonly", map[string]string{"os": "linux"})
	require.NoError(t, mgr1.Store(ctx, "dev-dnaonly", dna, &fleetStorage.StoreOptions{TenantID: "tenant-y", Status: "registered"}))
	// Deliberately NOT calling mgr1.SetDeviceTenant for "dev-dnaonly".

	require.NoError(t, mgr1.Close())

	mgr2 := openFleetStorageAt(t, dataDir)
	t.Cleanup(func() { _ = mgr2.Close() })
	svc2 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr2)

	// (1)+(2): RegisterSteward wrote device_tenant; survives restart.
	tid, ok := svc2.lookupDurableTenant("dev-mapped")
	require.True(t, ok, "lookupDurableTenant must resolve a registered steward after restart")
	assert.Equal(t, "tenant-x", tid)

	// (3): dna_history-only device must not resolve via lookupDurableTenant.
	_, ok = svc2.lookupDurableTenant("dev-dnaonly")
	assert.False(t, ok, "lookupDurableTenant must not fall back to dna_history for tenant resolution")
}

// TestUpdateStewardTenant_MoveSurvivesRestart is the tenant-move reversion
// regression test for Issue #3324. device_tenant is authoritative — EnsureSteward
// lets the durable tenant win unconditionally — so a move that updates only the
// registry would be undone by the next reconnect or controller restart. The move
// must rewrite device_tenant, and both warm-load and the connect path must then
// report the NEW tenant.
func TestUpdateStewardTenant_MoveSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	ctx := context.Background()

	mgr1 := openFleetStorageAt(t, dataDir)
	svc1 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr1)
	require.NoError(t, svc1.RegisterSteward("dev-move", "tenant-a", "addr-1", "registered"))
	require.NoError(t, svc1.UpdateStewardTenant("dev-move", "tenant-b"))
	require.NoError(t, mgr1.Close())

	mgr2 := openFleetStorageAt(t, dataDir)
	t.Cleanup(func() { _ = mgr2.Close() })

	// The durable mapping itself names the destination tenant.
	tid, found, err := mgr2.GetDeviceTenant(ctx, "dev-move")
	require.NoError(t, err)
	require.True(t, found, "tenant move must write the durable device_tenant mapping")
	assert.Equal(t, "tenant-b", tid, "durable mapping must name the destination tenant after a move")

	// Warm-load after restart must report the destination tenant.
	svc2 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr2)
	require.NoError(t, svc2.LoadFromStorage(ctx))
	info, ok := svc2.GetStewardInfo("dev-move")
	require.True(t, ok, "warm-load must restore the moved steward")
	assert.Equal(t, "tenant-b", info.TenantID, "warm-load must not revert the device to its pre-move tenant")

	// The connect path (EnsureSteward) must not revert it either.
	svc3 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr2)
	svc3.EnsureSteward("dev-move", "", "active")
	info, ok = svc3.GetStewardInfo("dev-move")
	require.True(t, ok, "EnsureSteward must add the reconnecting steward")
	assert.Equal(t, "tenant-b", info.TenantID, "reconnect must not revert the device to its pre-move tenant")
}

// TestUpdateStewardTenant_OfflineStewardPersistsMapping covers the exact shape the
// move handler tolerates: the steward is absent from the live registry (moved while
// disconnected, or after a controller restart with no warm-load). The durable
// mapping must still be rewritten, and the returned error must be identifiable as
// ErrStewardNotInRegistry so callers can tell it apart from a failed persist
// (Issue #3324).
func TestUpdateStewardTenant_OfflineStewardPersistsMapping(t *testing.T) {
	dataDir := t.TempDir()
	ctx := context.Background()

	mgr1 := openFleetStorageAt(t, dataDir)
	svc1 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr1)
	require.NoError(t, svc1.RegisterSteward("dev-offline", "tenant-a", "addr-1", "registered"))
	require.NoError(t, mgr1.Close())

	mgr2 := openFleetStorageAt(t, dataDir)
	t.Cleanup(func() { _ = mgr2.Close() })
	svc2 := NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr2)
	_, ok := svc2.GetStewardInfo("dev-offline")
	require.False(t, ok, "precondition: steward must be absent from the fresh registry")

	err := svc2.UpdateStewardTenant("dev-offline", "tenant-b")
	require.Error(t, err, "an absent registry entry must be reported to the caller")
	require.ErrorIs(t, err, ErrStewardNotInRegistry,
		"registry miss must be distinguishable from a durable-write failure")

	tid, found, err := mgr2.GetDeviceTenant(ctx, "dev-offline")
	require.NoError(t, err)
	require.True(t, found, "durable mapping must be written even when the steward is offline")
	assert.Equal(t, "tenant-b", tid)

	// Reconnect resolves to the destination tenant, not the pre-move one.
	svc2.EnsureSteward("dev-offline", "", "active")
	info, ok := svc2.GetStewardInfo("dev-offline")
	require.True(t, ok)
	assert.Equal(t, "tenant-b", info.TenantID,
		"an offline steward moved between tenants must not revert on reconnect")
}

// TestLoadFromStorage_EnrolledNeverConnected: AC1 — a steward that received its
// cert via the quarantine→approve→claim path (StewardStore has a "registered"
// record) but never sent a gRPC check-in must appear in the registry after a
// controller restart. LoadFromStorage must enumerate StewardStore in addition to
// DNA storage so that enrolled-but-never-connected stewards survive the restart.
// Covers the cfg-lab incident where 3 HV-host stewards were invisible after the
// 2026-08-05 Postgres cutover (Issue #3403).
func TestLoadFromStorage_EnrolledNeverConnected(t *testing.T) {
	ctx := context.Background()
	sm := pkgtesting.SetupTestStorage(t)
	ss := sm.GetStewardStore()
	require.NotNil(t, ss)

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ss.RegisterSteward(ctx, &business.StewardRecord{
		ID:           "dev-enrolled",
		TenantID:     "tenant-a",
		Status:       business.StewardStatusRegistered,
		RegisteredAt: now,
	}))

	// Simulate controller restart: fresh service, no DNA storage, same StewardStore.
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetStewardStore(ss)
	require.NoError(t, svc.LoadFromStorage(ctx))

	assert.Equal(t, 1, svc.GetStewardCount(),
		"enrolled steward must appear in registry after restart even without DNA history")

	info, ok := svc.GetStewardInfo("dev-enrolled")
	require.True(t, ok, "enrolled steward must be retrievable by ID after restart")
	assert.Equal(t, "tenant-a", info.TenantID)
	assert.Equal(t, string(business.StewardStatusRegistered), info.Status,
		"status must remain 'registered' until first check-in")
}

// TestEnsureSteward_FirstCheckin_PromotesRegisteredSteward: AC2 — when a steward
// enrolled via any creation path (direct approval or claim) makes its first gRPC
// check-in, EnsureSteward must promote its status from "registered" to "active"
// in both the in-memory registry and the durable StewardStore, without creating
// a duplicate record (Issue #3403).
func TestEnsureSteward_FirstCheckin_PromotesRegisteredSteward(t *testing.T) {
	ctx := context.Background()
	sm := pkgtesting.SetupTestStorage(t)
	ss := sm.GetStewardStore()
	require.NotNil(t, ss)

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ss.RegisterSteward(ctx, &business.StewardRecord{
		ID:           "dev-checkin",
		TenantID:     "tenant-a",
		Status:       business.StewardStatusRegistered,
		RegisteredAt: now,
	}))

	// Warm-load so the steward is in the in-memory registry (as after a restart).
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetStewardStore(ss)
	require.NoError(t, svc.LoadFromStorage(ctx))
	require.Equal(t, 1, svc.GetStewardCount(), "precondition: steward loaded from StewardStore")

	// First check-in via EnsureSteward (mirrors the gRPC connect hook path).
	svc.EnsureSteward("dev-checkin", "", "active")

	// In-memory registry must show "active".
	info, ok := svc.GetStewardInfo("dev-checkin")
	require.True(t, ok)
	assert.Equal(t, "active", info.Status, "in-memory status must be 'active' after first check-in")

	// Durable store must also reflect the promotion without a round-trip restart.
	rec, err := ss.GetSteward(ctx, "dev-checkin")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusActive, rec.Status,
		"StewardStore must be updated to 'active' on first check-in")

	// Exactly one record — no duplicate created by EnsureSteward.
	all, err := ss.ListStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1, "first check-in must not create a duplicate StewardStore entry")
}

// TestLoadFromStorage_UnapprovedStewardNotIncluded: AC3 — a steward whose
// registration is pending (quarantined, awaiting operator approval) must NOT
// appear in the in-memory registry. Only the claim step (buildClaimResponse)
// writes a StewardStore record; until the steward claims its cert it is absent
// from StewardStore and therefore absent from the registry after LoadFromStorage.
// A pending steward cannot receive config pushes or participate in convergence.
// (Issue #3403)
func TestLoadFromStorage_UnapprovedStewardNotIncluded(t *testing.T) {
	ctx := context.Background()
	sm := pkgtesting.SetupTestStorage(t)
	ss := sm.GetStewardStore()
	require.NotNil(t, ss)

	// StewardStore is empty: the pending entry exists only in PendingRegistrationStore
	// (not modeled here) and the claim step has not yet run.
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetStewardStore(ss)
	require.NoError(t, svc.LoadFromStorage(ctx))

	assert.Equal(t, 0, svc.GetStewardCount(),
		"unapproved (pending) steward must not appear in the registry or be eligible for convergence")
}

// TestLoadFromStorage_TenantScopingPreserved: AC4 — stewards from different
// tenants must each be loaded with their correct TenantID. Cross-tenant records
// must not be mixed or attributed to the wrong tenant during warm-load.
// (Issue #3403)
func TestLoadFromStorage_TenantScopingPreserved(t *testing.T) {
	ctx := context.Background()
	sm := pkgtesting.SetupTestStorage(t)
	ss := sm.GetStewardStore()
	require.NotNil(t, ss)

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ss.RegisterSteward(ctx, &business.StewardRecord{
		ID:           "dev-tenant-a",
		TenantID:     "tenant-a",
		Status:       business.StewardStatusRegistered,
		RegisteredAt: now,
	}))
	require.NoError(t, ss.RegisterSteward(ctx, &business.StewardRecord{
		ID:           "dev-tenant-b",
		TenantID:     "tenant-b",
		Status:       business.StewardStatusRegistered,
		RegisteredAt: now,
	}))

	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetStewardStore(ss)
	require.NoError(t, svc.LoadFromStorage(ctx))

	assert.Equal(t, 2, svc.GetStewardCount(), "both enrolled stewards must load")

	infoA, okA := svc.GetStewardInfo("dev-tenant-a")
	require.True(t, okA)
	assert.Equal(t, "tenant-a", infoA.TenantID,
		"dev-tenant-a must be attributed to tenant-a, not tenant-b")

	infoB, okB := svc.GetStewardInfo("dev-tenant-b")
	require.True(t, okB)
	assert.Equal(t, "tenant-b", infoB.TenantID,
		"dev-tenant-b must be attributed to tenant-b, not tenant-a")

	// Cross-tenant negative: the durable record for dev-tenant-a must not be
	// attributed to tenant-b (verifies buildClaimResponse set the correct TenantID).
	recA, err := ss.GetSteward(ctx, "dev-tenant-a")
	require.NoError(t, err)
	assert.NotEqual(t, "tenant-b", recA.TenantID,
		"durable record for dev-tenant-a must not be attributed to tenant-b")
}

// newReconnectService builds a service backed by real fleet storage plus a real
// durable StewardStore, which is the wiring AcceptRegistration's reconnection
// fallback depends on (Issue #3403).
func newReconnectService(t *testing.T) (*ControllerService, business.StewardStore) {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	ss := sm.GetStewardStore()
	require.NotNil(t, ss)

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), newTestFleetStorage(t))
	svc.SetStewardStore(ss)
	return svc, ss
}

// TestAcceptRegistration_ReconnectionResolvesFromStewardStore is the positive
// case of the durable fallback: an in-tenant steward whose in-memory entry was
// lost (controller restart after a backend migration that wiped DNA storage)
// keeps its original ID instead of being issued a fresh one.
func TestAcceptRegistration_ReconnectionResolvesFromStewardStore(t *testing.T) {
	ctx := context.Background()
	svc, ss := newReconnectService(t)

	require.NoError(t, ss.RegisterSteward(ctx, &business.StewardRecord{
		ID:           "dev-reconnect",
		TenantID:     "tenant-a",
		Status:       business.StewardStatusActive,
		RegisteredAt: time.Now().UTC().Truncate(time.Second),
	}))

	tenantCtx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-a")
	resp, err := svc.AcceptRegistration(tenantCtx, &controllerpb.RegisterRequest{
		IsReconnection: true,
		InitialDna:     &commonpb.DNA{Id: "dev-reconnect"},
	})
	require.NoError(t, err)
	assert.Equal(t, "dev-reconnect", resp.StewardId,
		"an in-tenant, admissible steward must keep its durable ID across the restart")
}

// TestAcceptRegistration_ReconnectionRejectsNonAdmissibleStatus proves the
// lifecycle gate: GetSteward returns records in every state, so a caller
// asserting the ID of a revoked ("permanently denied re-entry", ADR-010 §3) or
// otherwise terminal steward must not be rehydrated into the live registry with
// a fresh access token. Such a request falls through to a brand-new
// registration, exactly as an unknown ID does.
func TestAcceptRegistration_ReconnectionRejectsNonAdmissibleStatus(t *testing.T) {
	ctx := context.Background()

	for _, status := range []business.StewardStatus{
		business.StewardStatusRevoked,
		business.StewardStatusDeregistered,
		business.StewardStatusArchived,
		business.StewardStatusDormant,
	} {
		t.Run(string(status), func(t *testing.T) {
			svc, ss := newReconnectService(t)

			require.NoError(t, ss.RegisterSteward(ctx, &business.StewardRecord{
				ID:           "dev-terminal",
				TenantID:     "tenant-a",
				Status:       business.StewardStatusRegistered,
				RegisteredAt: time.Now().UTC().Truncate(time.Second),
			}))
			require.NoError(t, ss.UpdateStewardStatus(ctx, "dev-terminal", status))

			tenantCtx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-a")
			resp, err := svc.AcceptRegistration(tenantCtx, &controllerpb.RegisterRequest{
				IsReconnection: true,
				InitialDna:     &commonpb.DNA{Id: "dev-terminal"},
			})
			require.NoError(t, err)
			assert.NotEqual(t, "dev-terminal", resp.StewardId,
				"a %s steward must not be re-admitted under its own ID", status)

			_, inRegistry := svc.GetStewardInfo("dev-terminal")
			assert.False(t, inRegistry,
				"a %s steward must not be rehydrated into the live registry", status)

			rec, getErr := ss.GetSteward(ctx, "dev-terminal")
			require.NoError(t, getErr)
			assert.Equal(t, status, rec.Status,
				"the durable record must be left untouched by the refused reconnection")
		})
	}
}

// TestAcceptRegistration_ReconnectionRejectsCrossTenantID proves the tenant
// gate. AcceptRegistration writes the CALLER's context tenant into both the
// in-memory StewardInfo and the durable device_tenant mapping, so adopting a
// caller-asserted ID from another tenant would rebind that steward to the
// caller's tenant. The request must instead be treated as a new registration.
func TestAcceptRegistration_ReconnectionRejectsCrossTenantID(t *testing.T) {
	ctx := context.Background()
	svc, ss := newReconnectService(t)

	require.NoError(t, ss.RegisterSteward(ctx, &business.StewardRecord{
		ID:           "dev-of-tenant-b",
		TenantID:     "tenant-b",
		Status:       business.StewardStatusActive,
		RegisteredAt: time.Now().UTC().Truncate(time.Second),
	}))

	attackerCtx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-a")
	resp, err := svc.AcceptRegistration(attackerCtx, &controllerpb.RegisterRequest{
		IsReconnection: true,
		InitialDna:     &commonpb.DNA{Id: "dev-of-tenant-b"},
	})
	require.NoError(t, err)
	assert.NotEqual(t, "dev-of-tenant-b", resp.StewardId,
		"a caller in tenant-a must not adopt a tenant-b steward ID")

	info, inRegistry := svc.GetStewardInfo("dev-of-tenant-b")
	assert.False(t, inRegistry, "the tenant-b steward must not be rehydrated by a tenant-a caller: %+v", info)

	rec, getErr := ss.GetSteward(ctx, "dev-of-tenant-b")
	require.NoError(t, getErr)
	assert.Equal(t, "tenant-b", rec.TenantID,
		"the durable record must still belong to tenant-b after the refused reconnection")

	// The durable device_tenant mapping must not have been rebound either.
	mappedTenant, found, mapErr := svc.dnaStorage.GetDeviceTenant(ctx, "dev-of-tenant-b")
	require.NoError(t, mapErr)
	assert.False(t, found,
		"the refused reconnection must not write a device_tenant mapping for the foreign ID (got %q)", mappedTenant)
}
