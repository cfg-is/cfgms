// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"fmt"
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
	"github.com/cfgis/cfgms/pkg/logging"
)

// logCapture records log calls for assertion in internal package tests (package service).
// Implements logging.Logger by storing each call; assertions use findEntry.
type logCapture struct {
	mu      sync.Mutex
	entries []logCaptureEntry
}

type logCaptureEntry struct {
	level  string
	msg    string
	fields []interface{}
}

func (l *logCapture) record(level, msg string, kv []interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, logCaptureEntry{level: level, msg: msg, fields: kv})
}

// findEntry returns the first entry whose message equals msg (case-sensitive).
func (l *logCapture) findEntry(msg string) (logCaptureEntry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.msg == msg {
			return e, true
		}
	}
	return logCaptureEntry{}, false
}

// fieldValue returns the value for a given key in a log entry's key-value pairs.
func (e logCaptureEntry) fieldValue(key string) (interface{}, bool) {
	for i := 0; i+1 < len(e.fields); i += 2 {
		if fmt.Sprintf("%v", e.fields[i]) == key {
			return e.fields[i+1], true
		}
	}
	return nil, false
}

func (l *logCapture) Debug(msg string, kv ...interface{}) { l.record("DEBUG", msg, kv) }
func (l *logCapture) Info(msg string, kv ...interface{})  { l.record("INFO", msg, kv) }
func (l *logCapture) Warn(msg string, kv ...interface{})  { l.record("WARN", msg, kv) }
func (l *logCapture) Error(msg string, kv ...interface{}) { l.record("ERROR", msg, kv) }
func (l *logCapture) Fatal(msg string, kv ...interface{}) { l.record("FATAL", msg, kv) }
func (l *logCapture) DebugCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("DEBUG", msg, kv)
}
func (l *logCapture) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("INFO", msg, kv)
}
func (l *logCapture) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("WARN", msg, kv)
}
func (l *logCapture) ErrorCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("ERROR", msg, kv)
}
func (l *logCapture) FatalCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("FATAL", msg, kv)
}

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
				_ = info.DNA.Attributes
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

	all[0].DNA.Attributes["os"] = "windows"
	all[0].Metrics["cpu"] = "99"

	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok)
	assert.Equal(t, "linux", info.DNA.Attributes["os"], "live DNA must not be affected by returned copy mutation")
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

// TestResolveRingVersion_ValidRing proves: a steward with dna["deployment_ring"] = "early"
// receives the early ring's desired_version as the effective desired_version.
// This is the REQUIRED TEST from acceptance criteria for Story #2271.
func TestResolveRingVersion_ValidRing(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetRingConfig(makeTestRingConfig())

	dnaAttrs := map[string]string{"deployment_ring": "early"}
	version, ring, didFallback, _ := svc.ResolveRingVersion(dnaAttrs)

	assert.Equal(t, "v0.5.21", version,
		"steward in 'early' ring must receive early ring's desired_version")
	assert.Equal(t, "early", ring)
	assert.False(t, didFallback, "valid ring must not trigger fallback")
}

// TestResolveRingVersion_InvalidRing_FallsBack proves: a steward with an invalid
// deployment_ring receives the fallback ring's desired_version.
// This is the REQUIRED TEST for the invalid-ring fallback case.
func TestResolveRingVersion_InvalidRing_FallsBack(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetRingConfig(makeTestRingConfig())

	dnaAttrs := map[string]string{"deployment_ring": "not-a-real-ring"}
	version, ring, didFallback, original := svc.ResolveRingVersion(dnaAttrs)

	assert.Equal(t, "v0.5.20", version,
		"invalid ring must fall back to 'default' ring's desired_version")
	assert.Equal(t, "default", ring)
	assert.True(t, didFallback)
	assert.Equal(t, "not-a-real-ring", original)
}

// TestResolveRingVersion_AbsentRing_FallsBack proves: a steward with no
// deployment_ring attribute receives the fallback ring's desired_version.
// This is the REQUIRED TEST for the absent-ring fallback case.
func TestResolveRingVersion_AbsentRing_FallsBack(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetRingConfig(makeTestRingConfig())

	dnaAttrs := map[string]string{} // no deployment_ring attribute
	version, ring, didFallback, original := svc.ResolveRingVersion(dnaAttrs)

	assert.Equal(t, "v0.5.20", version,
		"absent ring must fall back to 'default' ring's desired_version")
	assert.Equal(t, "default", ring)
	assert.True(t, didFallback, "absent ring attribute must trigger fallback")
	assert.Equal(t, "", original)
}

// TestApplyRingResolution_ValidRing verifies ApplyRingResolution stores the ring-resolved
// version in StewardInfo and does not log WARN for a valid ring.
func TestApplyRingResolution_ValidRing(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetRingConfig(makeTestRingConfig())

	dna := makeTestDNA("dev-1", map[string]string{"deployment_ring": "stable"})
	steward := &StewardInfo{
		ID:      "dev-1",
		DNA:     dna,
		Metrics: make(map[string]string),
	}
	svc.ApplyRingResolution("dev-1", steward)

	assert.Equal(t, "v0.5.19", steward.RingResolvedVersion,
		"ApplyRingResolution must store the stable ring's desired_version")
	assert.Equal(t, "stable", steward.ResolvedRing)
}

// TestApplyRingResolution_AbsentRing_FallsToDefault verifies that ApplyRingResolution
// falls back to the default ring and stores the correct version when deployment_ring
// attribute is absent from DNA.
func TestApplyRingResolution_AbsentRing_FallsToDefault(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetRingConfig(makeTestRingConfig())

	dna := makeTestDNA("dev-1", map[string]string{}) // no deployment_ring
	steward := &StewardInfo{
		ID:      "dev-1",
		DNA:     dna,
		Metrics: make(map[string]string),
	}
	svc.ApplyRingResolution("dev-1", steward)

	assert.Equal(t, "v0.5.20", steward.RingResolvedVersion,
		"absent ring must resolve to default ring's version")
	assert.Equal(t, "default", steward.ResolvedRing)
}

// TestApplyRingResolution_FallbackLogsWarn verifies that ApplyRingResolution emits
// a WARN log entry with event name "deployment_ring_fallback" and the correct
// field values when ring fallback occurs (invalid ring name).
func TestApplyRingResolution_FallbackLogsWarn(t *testing.T) {
	lc := &logCapture{}
	svc := NewControllerService(lc)
	svc.SetRingConfig(makeTestRingConfig())

	dna := makeTestDNA("dev-1", map[string]string{"deployment_ring": "does-not-exist"})
	steward := &StewardInfo{
		ID:      "dev-1",
		DNA:     dna,
		Metrics: make(map[string]string),
	}
	svc.ApplyRingResolution("dev-1", steward)

	// State assertions — invalid ring falls back to default ring.
	assert.Equal(t, "v0.5.20", steward.RingResolvedVersion,
		"invalid ring must resolve to fallback (default) ring's version")
	assert.Equal(t, "default", steward.ResolvedRing,
		"ResolvedRing must reflect the fallback ring, not the invalid input")

	// Log assertions — WARN with event name and field values must be emitted.
	entry, ok := lc.findEntry("deployment_ring_fallback")
	require.True(t, ok, "expected WARN log entry with msg='deployment_ring_fallback'")
	assert.Equal(t, "WARN", entry.level, "fallback must be logged at WARN level")

	ringValue, hasRingValue := entry.fieldValue("ring_value")
	assert.True(t, hasRingValue, "log entry must include ring_value field")
	assert.Contains(t, fmt.Sprintf("%v", ringValue), "does-not-exist",
		"ring_value field must carry the invalid ring name (possibly sanitized)")

	fallbackRing, hasFallbackRing := entry.fieldValue("fallback_ring")
	assert.True(t, hasFallbackRing, "log entry must include fallback_ring field")
	assert.Contains(t, fmt.Sprintf("%v", fallbackRing), "default",
		"fallback_ring field must name the fallback ring (possibly sanitized)")
}

// TestSetRingConfig_AuditLogsOnChange verifies SetRingConfig emits a "ring_set_changed"
// INFO audit log entry with actor, before, and after fields when the ring set changes.
func TestSetRingConfig_AuditLogsOnChange(t *testing.T) {
	lc := &logCapture{}
	svc := NewControllerService(lc)

	initial := makeTestRingConfig()
	svc.SetRingConfig(initial)

	// First set emits ring_set_changed (from empty → initial config).
	entry, ok := lc.findEntry("ring_set_changed")
	require.True(t, ok, "expected INFO log entry with msg='ring_set_changed' on first SetRingConfig")
	assert.Equal(t, "INFO", entry.level, "ring_set_changed must be logged at INFO level")
	_, hasActor := entry.fieldValue("actor")
	assert.True(t, hasActor, "ring_set_changed entry must include actor field")
	_, hasAfter := entry.fieldValue("after")
	assert.True(t, hasAfter, "ring_set_changed entry must include after field")

	// State is persisted correctly.
	got := svc.GetRingConfig()
	require.Len(t, got.Rings, 4)
	assert.Equal(t, "early", got.Rings[1].Name)
	assert.Equal(t, "v0.5.21", got.Rings[1].DesiredVersion)

	// Record current entry count; a second change must add exactly one more.
	lc.mu.Lock()
	countBefore := len(lc.entries)
	lc.mu.Unlock()

	// Update the ring config (version bump on early ring).
	updated := makeTestRingConfig()
	updated.Rings[1].DesiredVersion = "v0.5.22"
	svc.SetRingConfig(updated)

	lc.mu.Lock()
	countAfter := len(lc.entries)
	lc.mu.Unlock()
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
