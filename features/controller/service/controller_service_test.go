// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
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
