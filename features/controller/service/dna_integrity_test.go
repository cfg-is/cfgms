// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"os"
	"path/filepath"
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
	log := logging.NewCapturingLogger()
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
	// CapturingLogger records only Warn/WarnCtx calls, so a hit here is itself
	// proof the event was emitted at WARN level.
	_, found := log.FindWarn("dna_integrity_rejected")
	assert.True(t, found, "expected dna_integrity_rejected WARN log entry")
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
	log := logging.NewCapturingLogger()
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

	entry, found := log.FindWarn("dna_integrity_rejected")
	require.True(t, found, "expected dna_integrity_rejected WARN log entry")

	// steward_id field present.
	_, hasStewardID := entry["steward_id"]
	assert.True(t, hasStewardID)

	// missing_fields value is a []string containing "os".
	val, ok := entry["missing_fields"]
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
	log := logging.NewCapturingLogger()
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
	// CapturingLogger records only Warn/WarnCtx calls, so a hit here is itself
	// proof the event was emitted at WARN level.
	_, found := log.FindWarn("dna_integrity_rejected")
	assert.True(t, found, "expected dna_integrity_rejected WARN log entry")
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

// --- Manifest-driven required-field loader tests (ADR-020 / Issue #2642) ---

// writeManifest creates a module.yaml in dir/moduleName/module.yaml with the
// given YAML content and returns the path to the file.
func writeManifest(t *testing.T, dir, moduleName, content string) string {
	t.Helper()
	modDir := filepath.Join(dir, moduleName)
	require.NoError(t, os.MkdirAll(modDir, 0750))
	path := filepath.Join(modDir, "module.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// TestBuildRequiredFields_FullOSDevice proves that buildRequiredFieldsFromManifests
// reads required_fields from a steward module's owns: entries and maps them to
// the full-os-device config type (ADR-020 Path A). This satisfies AC1: the
// guard's required-set table is built from module.yaml declarations, not a
// hardcoded Go literal.
func TestBuildRequiredFields_FullOSDevice(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "identity", `
name: identity
version: 0.1.0
publisher: cfgms
executors:
  - steward
owns:
  - kind: device
    required_fields:
      - hostname
      - os
`)

	table, err := buildRequiredFieldsFromManifests(dir)
	require.NoError(t, err)

	fields, ok := table[configTypeFullOSDevice]
	require.True(t, ok, "full-os-device must be present in the built table")
	assert.Contains(t, fields, "hostname")
	assert.Contains(t, fields, "os")

	// Confirm the guard rejects a DNA missing hostname.
	dnaNoHostname := &commonpb.DNA{
		Id:         "dev-manifest-1",
		Attributes: map[string]string{"os": "linux"},
	}
	result := checkDNAIntegrityWithTable(dnaNoHostname, configTypeFullOSDevice, table)
	assert.False(t, result.valid)
	assert.Contains(t, result.missingFields, "hostname")

	// Confirm the guard accepts a DNA with both fields.
	dnaFull := &commonpb.DNA{
		Id:         "dev-manifest-2",
		Attributes: map[string]string{"hostname": "myhost", "os": "linux"},
	}
	result = checkDNAIntegrityWithTable(dnaFull, configTypeFullOSDevice, table)
	assert.True(t, result.valid)
	assert.Empty(t, result.missingFields)
}

// TestBuildRequiredFields_UnionAcrossModules proves that required_fields from
// multiple steward modules are unioned into a single full-os-device contract.
func TestBuildRequiredFields_UnionAcrossModules(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "mod-a", `
name: mod-a
version: 0.1.0
publisher: cfgms
executors:
  - steward
owns:
  - kind: resource-a
    required_fields:
      - hostname
      - os
`)
	writeManifest(t, dir, "mod-b", `
name: mod-b
version: 0.1.0
publisher: cfgms
executors:
  - steward
owns:
  - kind: resource-b
    required_fields:
      - hostname
      - region
`)

	table, err := buildRequiredFieldsFromManifests(dir)
	require.NoError(t, err)

	fields := table[configTypeFullOSDevice]
	assert.Contains(t, fields, "hostname", "hostname should appear in union (declared by both modules)")
	assert.Contains(t, fields, "os")
	assert.Contains(t, fields, "region")

	// hostname must appear only once (deduplication)
	count := 0
	for _, f := range fields {
		if f == "hostname" {
			count++
		}
	}
	assert.Equal(t, 1, count, "hostname must appear exactly once after deduplication")
}

// TestBuildRequiredFields_NonStewardModulesSkipped proves that outpost and
// workflow (controller) modules do not contribute to the full-os-device table.
func TestBuildRequiredFields_NonStewardModulesSkipped(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "outpost-mod", `
name: outpost-mod
version: 0.1.0
publisher: cfgms
executors:
  - outpost
owns:
  - kind: printer
    required_fields:
      - printer_ip
`)

	table, err := buildRequiredFieldsFromManifests(dir)
	require.NoError(t, err)

	fields := table[configTypeFullOSDevice]
	assert.NotContains(t, fields, "printer_ip", "outpost module fields must not appear in full-os-device table")
}

// TestDNAIntegrityDrivenByManifestDeclaration proves that adding a required_fields
// entry to an existing module.yaml changes what the guard rejects — zero changes
// to dna_integrity.go's guard logic required. This satisfies AC2.
func TestDNAIntegrityDrivenByManifestDeclaration(t *testing.T) {
	dir := t.TempDir()

	// Step 1: module declares hostname and os as required.
	manifestPath := writeManifest(t, dir, "steward-mod", `
name: steward-mod
version: 0.1.0
publisher: cfgms
executors:
  - steward
owns:
  - kind: resource
    required_fields:
      - hostname
      - os
`)

	table, err := buildRequiredFieldsFromManifests(dir)
	require.NoError(t, err)

	dna := &commonpb.DNA{
		Id:         "dev-ac2",
		Attributes: map[string]string{"hostname": "myhost", "os": "linux"},
	}
	result := checkDNAIntegrityWithTable(dna, configTypeFullOSDevice, table)
	assert.True(t, result.valid, "DNA with hostname+os must pass before adding new required field")

	// Step 2: add region to the manifest's required_fields — no change to guard logic.
	require.NoError(t, os.WriteFile(manifestPath, []byte(`
name: steward-mod
version: 0.1.0
publisher: cfgms
executors:
  - steward
owns:
  - kind: resource
    required_fields:
      - hostname
      - os
      - region
`), 0600))

	tableAfter, err := buildRequiredFieldsFromManifests(dir)
	require.NoError(t, err)

	// Guard now rejects DNA that lacks region — no guard logic was changed.
	resultAfter := checkDNAIntegrityWithTable(dna, configTypeFullOSDevice, tableAfter)
	assert.False(t, resultAfter.valid, "guard must reject DNA missing region after manifest update")
	assert.Contains(t, resultAfter.missingFields, "region")

	// DNA with the new field passes.
	dnaFull := &commonpb.DNA{
		Id: "dev-ac2-full",
		Attributes: map[string]string{
			"hostname": "myhost",
			"os":       "linux",
			"region":   "us-east-1",
		},
	}
	resultFull := checkDNAIntegrityWithTable(dnaFull, configTypeFullOSDevice, tableAfter)
	assert.True(t, resultFull.valid)
}

// TestBuildRequiredFields_StdlibManifests proves that the real embedded stdlib
// manifests yield the full-os-device → {hostname, os} contract that the
// #2617 guard seeded, confirming the manifest declarations are consistent
// with the guard's expected behavior (AC1 against the live manifests).
func TestBuildRequiredFields_StdlibManifests(t *testing.T) {
	// dnaRequiredFields is populated from StdlibManifests by the package init.
	fields, ok := dnaRequiredFields[configTypeFullOSDevice]
	require.True(t, ok, "full-os-device entry must exist in the stdlib-manifest-driven table")
	assert.Contains(t, fields, "hostname")
	assert.Contains(t, fields, "os")

	// Guard behaves identically to the pre-manifest hardcoded seed.
	validDNA := &commonpb.DNA{
		Id:         "dev-stdlib-valid",
		Attributes: map[string]string{"hostname": "myhost", "os": "linux"},
	}
	assert.True(t, checkDNAIntegrity(validDNA, configTypeFullOSDevice).valid)

	emptyDNA := &commonpb.DNA{Id: "dev-stdlib-empty", Attributes: map[string]string{}}
	result := checkDNAIntegrity(emptyDNA, configTypeFullOSDevice)
	assert.False(t, result.valid)
	assert.Contains(t, result.missingFields, "hostname")
	assert.Contains(t, result.missingFields, "os")
}
