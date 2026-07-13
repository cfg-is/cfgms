// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// makeValidDNA returns a DNA snapshot that satisfies the full-os-device required set.
func makeValidDNA(id string) *commonpb.DNA {
	return &commonpb.DNA{
		Id:              id,
		SyncFingerprint: "fp-" + id,
		Attributes: map[string]string{
			"hostname": "host-" + id,
			"os":       "linux",
		},
	}
}

// --- Unit tests for checkDNAIntegrity ---

func TestCheckDNAIntegrity_NilDNA(t *testing.T) {
	result := checkDNAIntegrity(nil, configTypeFullOSDevice)
	assert.False(t, result.valid)
	assert.NotEmpty(t, result.missingFields)
}

func TestCheckDNAIntegrity_EmptyAttributes(t *testing.T) {
	dna := &commonpb.DNA{Id: "dev-1", Attributes: map[string]string{}}
	result := checkDNAIntegrity(dna, configTypeFullOSDevice)
	assert.False(t, result.valid)
	assert.Contains(t, result.missingFields, "hostname")
	assert.Contains(t, result.missingFields, "os")
}

func TestCheckDNAIntegrity_MissingHostname(t *testing.T) {
	dna := &commonpb.DNA{
		Id:         "dev-1",
		Attributes: map[string]string{"os": "linux"},
	}
	result := checkDNAIntegrity(dna, configTypeFullOSDevice)
	assert.False(t, result.valid)
	assert.Contains(t, result.missingFields, "hostname")
	assert.NotContains(t, result.missingFields, "os")
}

func TestCheckDNAIntegrity_MissingOS(t *testing.T) {
	dna := &commonpb.DNA{
		Id:         "dev-1",
		Attributes: map[string]string{"hostname": "myhost"},
	}
	result := checkDNAIntegrity(dna, configTypeFullOSDevice)
	assert.False(t, result.valid)
	assert.Contains(t, result.missingFields, "os")
	assert.NotContains(t, result.missingFields, "hostname")
}

func TestCheckDNAIntegrity_EmptyHostnameValue(t *testing.T) {
	dna := &commonpb.DNA{
		Id:         "dev-1",
		Attributes: map[string]string{"hostname": "", "os": "linux"},
	}
	result := checkDNAIntegrity(dna, configTypeFullOSDevice)
	assert.False(t, result.valid)
	assert.Contains(t, result.missingFields, "hostname")
}

func TestCheckDNAIntegrity_EmptyOSValue(t *testing.T) {
	dna := &commonpb.DNA{
		Id:         "dev-1",
		Attributes: map[string]string{"hostname": "myhost", "os": ""},
	}
	result := checkDNAIntegrity(dna, configTypeFullOSDevice)
	assert.False(t, result.valid)
	assert.Contains(t, result.missingFields, "os")
}

func TestCheckDNAIntegrity_ValidCoreIdentity(t *testing.T) {
	dna := &commonpb.DNA{
		Id:         "dev-1",
		Attributes: map[string]string{"hostname": "myhost", "os": "linux"},
	}
	result := checkDNAIntegrity(dna, configTypeFullOSDevice)
	assert.True(t, result.valid)
	assert.Empty(t, result.missingFields)
}

// Optional fields (vm_count legitimately absent) must not block a valid write.
func TestCheckDNAIntegrity_ValidWithOptionalFieldsAbsent(t *testing.T) {
	dna := &commonpb.DNA{
		Id: "dev-1",
		Attributes: map[string]string{
			"hostname": "myhost",
			"os":       "windows",
			// vm_count intentionally omitted
		},
	}
	result := checkDNAIntegrity(dna, configTypeFullOSDevice)
	assert.True(t, result.valid)
	assert.Empty(t, result.missingFields)
}

// Unknown config type has no contract; conservative default is valid.
func TestCheckDNAIntegrity_UnknownConfigType(t *testing.T) {
	dna := &commonpb.DNA{Id: "dev-1", Attributes: map[string]string{}}
	result := checkDNAIntegrity(dna, configType("unknown-type"))
	assert.True(t, result.valid)
}

// --- Integration tests: SyncDNA write guard ---

// TestSyncDNA_RejectsDegenerateDNA verifies that a degenerate snapshot (missing
// hostname/os) is rejected: in-memory DNA and durable history stay at the prior
// good snapshot.
func TestSyncDNA_RejectsDegenerateDNA_PriorSnapshotUnchanged(t *testing.T) {
	storage := newTestFleetStorage(t)
	log := &logCapture{}
	svc := NewControllerServiceWithStorage(log, storage)
	ctx := context.Background()

	goodDNA := makeValidDNA("dev-1")
	svc.mu.Lock()
	svc.stewards["dev-1"] = &StewardInfo{
		ID:       "dev-1",
		TenantID: "tenant-a",
		DNA:      goodDNA,
		Status:   "active",
		Metrics:  make(map[string]string),
	}
	svc.mu.Unlock()
	require.NoError(t, storage.Store(ctx, "dev-1", goodDNA, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "active"}))

	// Sync degenerate snapshot (missing hostname and os).
	degenerateDNA := &commonpb.DNA{Id: "dev-1", Attributes: map[string]string{}}
	_, err := svc.SyncDNA(ctx, degenerateDNA)
	require.NoError(t, err)

	// In-memory DNA must still be the good snapshot.
	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok)
	assert.Equal(t, goodDNA.Attributes["hostname"], info.DNA.Attributes["hostname"])
	assert.Equal(t, goodDNA.Attributes["os"], info.DNA.Attributes["os"])

	// History must have exactly one entry — degenerate not appended.
	history, err := storage.GetHistory(ctx, "dev-1", &fleetStorage.QueryOptions{IncludeData: true})
	require.NoError(t, err)
	assert.EqualValues(t, 1, history.TotalCount, "degenerate snapshot must not be appended to history")

	// WARN log entry must have been emitted.
	entry, found := log.findEntry("dna_integrity_rejected")
	assert.True(t, found, "expected dna_integrity_rejected WARN log entry")
	assert.Equal(t, "WARN", entry.level)
}

// TestSyncDNA_RejectsNilAttributesDNA verifies that a nil-attributes DNA
// snapshot is also rejected by the SyncDNA path.
func TestSyncDNA_RejectsNilAttributesDNA(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	ctx := context.Background()

	goodDNA := makeValidDNA("dev-2")
	svc.mu.Lock()
	svc.stewards["dev-2"] = &StewardInfo{
		ID:       "dev-2",
		TenantID: "tenant-b",
		DNA:      goodDNA,
		Status:   "active",
		Metrics:  make(map[string]string),
	}
	svc.mu.Unlock()
	require.NoError(t, storage.Store(ctx, "dev-2", goodDNA, &fleetStorage.StoreOptions{TenantID: "tenant-b", Status: "active"}))

	emptyDNA := &commonpb.DNA{Id: "dev-2"} // nil Attributes map
	_, err := svc.SyncDNA(ctx, emptyDNA)
	require.NoError(t, err)

	info, ok := svc.GetStewardInfo("dev-2")
	require.True(t, ok)
	assert.NotNil(t, info.DNA)
	assert.Equal(t, "host-dev-2", info.DNA.Attributes["hostname"])

	history, err := storage.GetHistory(ctx, "dev-2", &fleetStorage.QueryOptions{IncludeData: true})
	require.NoError(t, err)
	assert.EqualValues(t, 1, history.TotalCount)
}

// TestSyncDNA_AcceptsValidDNA verifies a valid DNA snapshot persists and versions.
func TestSyncDNA_AcceptsValidDNA(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	ctx := context.Background()

	firstDNA := makeValidDNA("dev-3")
	svc.mu.Lock()
	svc.stewards["dev-3"] = &StewardInfo{
		ID:       "dev-3",
		TenantID: "tenant-c",
		DNA:      firstDNA,
		Status:   "active",
		Metrics:  make(map[string]string),
	}
	svc.mu.Unlock()
	require.NoError(t, storage.Store(ctx, "dev-3", firstDNA, &fleetStorage.StoreOptions{TenantID: "tenant-c", Status: "active"}))

	secondDNA := &commonpb.DNA{
		Id:         "dev-3",
		Attributes: map[string]string{"hostname": "host-dev-3-renamed", "os": "linux"},
	}
	status, err := svc.SyncDNA(ctx, secondDNA)
	require.NoError(t, err)
	assert.Equal(t, commonpb.Status_OK, status.Code)

	info, ok := svc.GetStewardInfo("dev-3")
	require.True(t, ok)
	assert.Equal(t, "host-dev-3-renamed", info.DNA.Attributes["hostname"])

	history, err := storage.GetHistory(ctx, "dev-3", &fleetStorage.QueryOptions{IncludeData: true})
	require.NoError(t, err)
	assert.EqualValues(t, 2, history.TotalCount)
}

// TestSyncDNA_AcceptsValidDNA_OptionalFieldsAbsent verifies that absent optional
// fields (vm_count etc.) do not trigger rejection.
func TestSyncDNA_AcceptsValidDNA_OptionalFieldsAbsent(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	ctx := context.Background()

	svc.mu.Lock()
	svc.stewards["dev-4"] = &StewardInfo{
		ID:      "dev-4",
		Status:  "active",
		Metrics: make(map[string]string),
	}
	svc.mu.Unlock()

	dna := &commonpb.DNA{
		Id: "dev-4",
		Attributes: map[string]string{
			"hostname": "myhost",
			"os":       "macos",
			// vm_count absent — must not block
		},
	}
	status, err := svc.SyncDNA(ctx, dna)
	require.NoError(t, err)
	assert.Equal(t, commonpb.Status_OK, status.Code)

	info, ok := svc.GetStewardInfo("dev-4")
	require.True(t, ok)
	assert.Equal(t, "macos", info.DNA.Attributes["os"])
}

// TestSyncDNA_PostHookNotFiredOnRejection verifies that postDNASyncHook is not
// invoked when a degenerate snapshot is rejected.
func TestSyncDNA_PostHookNotFiredOnRejection(t *testing.T) {
	svc := NewControllerService(logging.NewNoopLogger())
	ctx := context.Background()

	goodDNA := makeValidDNA("dev-5")
	svc.mu.Lock()
	svc.stewards["dev-5"] = &StewardInfo{
		ID:      "dev-5",
		DNA:     goodDNA,
		Status:  "active",
		Metrics: make(map[string]string),
	}
	svc.mu.Unlock()

	hookFired := false
	svc.SetPostDNASyncHook(func(id string, dna *commonpb.DNA) {
		hookFired = true
	})

	degenerateDNA := &commonpb.DNA{Id: "dev-5", Attributes: map[string]string{}}
	_, err := svc.SyncDNA(ctx, degenerateDNA)
	require.NoError(t, err)
	assert.False(t, hookFired, "postDNASyncHook must not fire on degenerate rejection")
}

// TestSyncDNA_WarnLogContainsStewardIDAndMissingFields verifies the WARN log
// entry names the steward id and the specific missing fields.
func TestSyncDNA_WarnLogContainsStewardIDAndMissingFields(t *testing.T) {
	log := &logCapture{}
	svc := NewControllerService(log)
	ctx := context.Background()

	svc.mu.Lock()
	svc.stewards["dev-6"] = &StewardInfo{
		ID:      "dev-6",
		DNA:     makeValidDNA("dev-6"),
		Status:  "active",
		Metrics: make(map[string]string),
	}
	svc.mu.Unlock()

	// DNA missing only "os".
	dna := &commonpb.DNA{
		Id:         "dev-6",
		Attributes: map[string]string{"hostname": "myhost"},
	}
	_, err := svc.SyncDNA(ctx, dna)
	require.NoError(t, err)

	entry, found := log.findEntry("dna_integrity_rejected")
	require.True(t, found, "expected dna_integrity_rejected WARN log entry")

	// steward_id field present.
	_, hasStewardID := entry.fieldValue("steward_id")
	assert.True(t, hasStewardID)

	// missing_fields value is a []string containing "os".
	val, ok := entry.fieldValue("missing_fields")
	require.True(t, ok)
	fields, isSlice := val.([]string)
	require.True(t, isSlice, "missing_fields should be []string")
	assert.Contains(t, fields, "os")
	assert.NotContains(t, fields, "hostname")
}

// --- Integration tests: AcceptRegistration write guard ---

// TestAcceptRegistration_RejectsDegenerateInitialDNA verifies that a registration
// with a degenerate initial DNA still creates the StewardInfo entry (registration
// structurally succeeds) but leaves the DNA field nil and stores no durable record.
func TestAcceptRegistration_RejectsDegenerateInitialDNA(t *testing.T) {
	storage := newTestFleetStorage(t)
	log := &logCapture{}
	svc := NewControllerServiceWithStorage(log, storage)
	ctx := context.Background()

	req := &controllerpb.RegisterRequest{
		Version:        "1.0.0",
		InitialDna:     &commonpb.DNA{Id: "dna-bad", Attributes: map[string]string{}},
		IsReconnection: false,
	}
	resp, err := svc.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	stewardID := resp.StewardId

	// StewardInfo created but DNA must be nil.
	info, ok := svc.GetStewardInfo(stewardID)
	require.True(t, ok, "steward entry should exist even when DNA rejected")
	assert.Nil(t, info.DNA, "DNA must be nil when initial snapshot is degenerate")

	// No durable DNA record stored.
	_, err = storage.GetLatestByDeviceID(ctx, stewardID)
	assert.Error(t, err, "no durable record should exist for degenerate initial DNA")

	// WARN log emitted.
	entry, found := log.findEntry("dna_integrity_rejected")
	assert.True(t, found, "expected dna_integrity_rejected WARN log entry")
	assert.Equal(t, "WARN", entry.level)
}

// TestAcceptRegistration_AcceptsValidInitialDNA verifies a registration with
// valid initial DNA persists the record normally.
func TestAcceptRegistration_AcceptsValidInitialDNA(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	ctx := context.Background()

	req := &controllerpb.RegisterRequest{
		Version:        "1.0.0",
		InitialDna:     makeValidDNA("dna-good"),
		IsReconnection: false,
	}
	resp, err := svc.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	stewardID := resp.StewardId

	info, ok := svc.GetStewardInfo(stewardID)
	require.True(t, ok)
	require.NotNil(t, info.DNA)
	assert.Equal(t, "linux", info.DNA.Attributes["os"])

	record, err := storage.GetLatestByDeviceID(ctx, stewardID)
	require.NoError(t, err)
	require.NotNil(t, record)
}

// TestAcceptRegistration_RejectsNilInitialDNA verifies a nil InitialDna is
// handled without panic; registration succeeds structurally, DNA is left nil.
func TestAcceptRegistration_RejectsNilInitialDNA(t *testing.T) {
	storage := newTestFleetStorage(t)
	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	ctx := context.Background()

	req := &controllerpb.RegisterRequest{
		Version:        "1.0.0",
		InitialDna:     nil,
		IsReconnection: false,
	}
	resp, err := svc.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	info, ok := svc.GetStewardInfo(resp.StewardId)
	require.True(t, ok)
	assert.Nil(t, info.DNA)
}
