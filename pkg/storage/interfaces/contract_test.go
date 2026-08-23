// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package interfaces_test — provider capability completeness contract tests.
//
// These tests assert that each storage provider satisfies the union of required
// capabilities for every deployment shape it claims to serve. They encode the
// regression from issues #3401 and #3402, where the database provider declined
// CreatePendingRegistrationStore, CreateTriggerStore, and CreatePushStore with
// ErrNotSupported, leaving those slots nil in the cluster StorageManager and
// causing every affected endpoint to answer 503 on every request.
//
// # Contract test taxonomy (per CLAUDE.md)
//
// This file belongs at pkg/storage/interfaces/contract_test.go — the mandated
// location for storage interface contract tests. It carries no provider or
// protocol name in the filename.
//
// # Deployment shapes
//
// OSS single-node: flatfile (config/audit/steward/ip-trust/alerts) composed
// with SQLite (all business-data stores). Runs without Postgres — included in
// every test-fast / unit-tests run.
//
// Cluster: all stores supplied by the database (Postgres) provider. Requires a
// reachable Postgres instance and therefore skips when one is absent. The
// database provider's integration tests are not currently wired into any CI job
// that runs on PRs (the database provider's tests run only when Docker services
// are up, either locally via `make test-integration-setup` or in the merge
// queue's integration-tests job). Until that gap is closed, the cluster
// contract tests skip in unit-tests and run in integration-tests. A test that
// silently skips when Postgres is absent is a known limitation documented here
// rather than disguised as a pass.
package interfaces_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// deploymentShape identifies a named CFGMS controller deployment topology.
type deploymentShape string

const (
	// shapeOSS is the OSS single-node shape: flatfile + SQLite composite.
	shapeOSS deploymentShape = "oss"
	// shapeCluster is the HA cluster shape: all stores from the database (Postgres) provider.
	shapeCluster deploymentShape = "cluster"
)

// capabilityEntry is one row in the per-shape capability matrix: the subsystem
// that consumes the store, the store name, and whether absence blocks the shape.
type capabilityEntry struct {
	subsystem string
	store     interfaces.StoreName
	required  bool
}

// shapeCapabilityMatrix declares for each deployment shape which stores are
// required by which consuming subsystems. The contract tests derive from this
// matrix: a store marked required that is absent from the real composed
// StorageManager fails the test, naming the provider, store, subsystem, and
// deployment shape.
//
// This is the single place a new store must be declared required for a given
// shape. Forgetting to add a store here while implementing it in the provider
// produces no failure. Forgetting to implement it in the provider while it is
// declared required here produces a red test naming the exact gap — that is the
// invariant this matrix maintains.
//
// Subsystem labels name the feature whose code calls into the store, giving
// operators and developers enough context to diagnose a gap without reading
// source. Multiple rows may share a subsystem name when one subsystem uses more
// than one store.
var shapeCapabilityMatrix = map[deploymentShape][]capabilityEntry{
	// OSS single-node: flatfile supplies config/audit/steward/ip-trust/alerts;
	// SQLite (via BusinessStoreBundle) supplies all business-data stores.
	shapeOSS: {
		{subsystem: "config", store: interfaces.StoreNameConfig, required: true},
		{subsystem: "audit", store: interfaces.StoreNameAudit, required: true},
		{subsystem: "steward", store: interfaces.StoreNameSteward, required: true},
		{subsystem: "ip-trust", store: interfaces.StoreNameIPTrust, required: true},
		{subsystem: "alerts", store: interfaces.StoreNameAlert, required: true},
		{subsystem: "rbac", store: interfaces.StoreNameRBAC, required: true},
		{subsystem: "tenants", store: interfaces.StoreNameTenant, required: true},
		{subsystem: "client-tenants", store: interfaces.StoreNameClientTenant, required: true},
		{subsystem: "registration", store: interfaces.StoreNameRegistrationToken, required: true},
		{subsystem: "registration", store: interfaces.StoreNamePendingRegistration, required: true},
		{subsystem: "sessions", store: interfaces.StoreNameSession, required: true},
		{subsystem: "commands", store: interfaces.StoreNameCommand, required: true},
		{subsystem: "triggers", store: interfaces.StoreNameTrigger, required: true},
		{subsystem: "push", store: interfaces.StoreNamePush, required: true},
		{subsystem: "refresh", store: interfaces.StoreNamePendingRefresh, required: true},
		{subsystem: "refresh", store: interfaces.StoreNameRefreshPolicy, required: true},
		{subsystem: "assurance", store: interfaces.StoreNameAssurancePolicy, required: true},
		{subsystem: "tenant-crossing", store: interfaces.StoreNameTenantCrossing, required: true},
	},

	// Cluster: the database (Postgres) provider is the sole supplier for all
	// business-data and infrastructure stores.
	//
	// ConfigStore is marked optional because the server nil-checks it
	// (server.go: `if cs := storageManager.GetConfigStore(); cs != nil`) — the
	// git-backed config tree remains the authoritative source in cluster mode.
	// All other stores are required: their callers do not nil-check, and a nil
	// store causes a 503 or a nil-pointer panic at request time.
	//
	// StoreNamePendingRegistration: absent before #3401 (returned ErrNotSupported
	// from CreatePendingRegistrationStore). Every cluster-mode registration
	// endpoint answered 503. If this row is removed or the database provider
	// regresses, TestCapabilityCompleteness_Cluster turns red here.
	//
	// StoreNameTrigger and StoreNamePush: absent before #3402. Same consequence
	// for the trigger and push subsystems.
	shapeCluster: {
		{subsystem: "config", store: interfaces.StoreNameConfig, required: false},
		{subsystem: "audit", store: interfaces.StoreNameAudit, required: true},
		{subsystem: "steward", store: interfaces.StoreNameSteward, required: true},
		{subsystem: "ip-trust", store: interfaces.StoreNameIPTrust, required: true},
		{subsystem: "alerts", store: interfaces.StoreNameAlert, required: true},
		{subsystem: "rbac", store: interfaces.StoreNameRBAC, required: true},
		{subsystem: "tenants", store: interfaces.StoreNameTenant, required: true},
		{subsystem: "client-tenants", store: interfaces.StoreNameClientTenant, required: true},
		{subsystem: "registration", store: interfaces.StoreNameRegistrationToken, required: true},
		{subsystem: "registration", store: interfaces.StoreNamePendingRegistration, required: true},
		{subsystem: "sessions", store: interfaces.StoreNameSession, required: true},
		{subsystem: "commands", store: interfaces.StoreNameCommand, required: true},
		{subsystem: "triggers", store: interfaces.StoreNameTrigger, required: true},
		{subsystem: "push", store: interfaces.StoreNamePush, required: true},
		{subsystem: "refresh", store: interfaces.StoreNamePendingRefresh, required: true},
		{subsystem: "refresh", store: interfaces.StoreNameRefreshPolicy, required: true},
		{subsystem: "assurance", store: interfaces.StoreNameAssurancePolicy, required: true},
		{subsystem: "tenant-crossing", store: interfaces.StoreNameTenantCrossing, required: true},
	},
}

// checkProviderSatisfiesShape inspects sm for every required store in
// shapeCapabilityMatrix[shape] and returns a descriptive error message for each
// gap — never for optional stores.
//
// The function never treats an absent store as acceptable when it is marked
// required, regardless of whether the provider returned ErrNotSupported during
// construction. That tolerance is what allowed the #3401 and #3402 gaps to
// survive: the manager-building code accepted ErrNotSupported and left the slot
// nil; this function ensures the slot cannot be nil for a required store.
func checkProviderSatisfiesShape(sm *interfaces.StorageManager, shape deploymentShape, providerLabel string) []string {
	entries, ok := shapeCapabilityMatrix[shape]
	if !ok {
		return []string{fmt.Sprintf("no capability matrix entry for deployment shape %q — update shapeCapabilityMatrix in contract_test.go", shape)}
	}

	var gaps []string
	for _, entry := range entries {
		if !entry.required {
			continue
		}
		if !sm.HasStore(entry.store) {
			gaps = append(gaps, fmt.Sprintf(
				"provider %q does not supply %s, required by subsystem %q in deployment shape %q",
				providerLabel, entry.store, entry.subsystem, shape,
			))
		}
	}
	return gaps
}

// TestCapabilityCompleteness_OSS asserts that the OSS composite storage manager
// (flatfile + SQLite) satisfies the required capability set for the OSS
// single-node deployment shape.
//
// This test runs without Postgres and is included in every test-fast /
// unit-tests run. It will fail if any store in shapeCapabilityMatrix[shapeOSS]
// that is marked required is absent from the composed manager.
func TestCapabilityCompleteness_OSS(t *testing.T) {
	withEmptyRegistry(t)
	interfaces.RegistryReplace(map[string]interfaces.StorageProvider{
		"flatfile": newFlatFileProvider(),
		"sqlite":   newSQLiteProvider(),
	})

	sm, err := interfaces.CreateOSSStorageManager(
		t.TempDir(),
		filepath.Join(t.TempDir(), "contract-test.db"),
	)
	require.NoError(t, err, "CreateOSSStorageManager must succeed for the contract test to run")
	t.Cleanup(func() { _ = sm.Close() })

	gaps := checkProviderSatisfiesShape(sm, shapeOSS, "composite (flatfile+sqlite)")
	if len(gaps) > 0 {
		t.Errorf("OSS composite storage manager fails capability check for shape %q:\n%s",
			shapeOSS, strings.Join(gaps, "\n"))
	}
}

// TestCapabilityCompleteness_Cluster asserts that the cluster storage manager
// (database / Postgres provider) satisfies the required capability set for the
// cluster deployment shape.
//
// This is the primary regression guard for issues #3401 and #3402. Reverting
// either fix causes the database provider to return ErrNotSupported for
// PendingRegistrationStore, TriggerStore, or PushStore, leaving the slot nil in
// the manager. This test catches that, naming the exact store, subsystem, and
// deployment shape.
//
// This test skips when Postgres is not reachable (same pattern as every other
// cluster-facing test in this package). See the package-level doc comment for
// the CI execution note.
func TestCapabilityCompleteness_Cluster(t *testing.T) {
	pgDSN := skipIfNoPostgres(t)

	sm, err := interfaces.CreateClusterStorageManager(pgDSN, testSessionHMACKey(), nil)
	require.NoError(t, err, "CreateClusterStorageManager must succeed for the contract test to run")
	t.Cleanup(func() { _ = sm.Close() })

	gaps := checkProviderSatisfiesShape(sm, shapeCluster, "database")
	if len(gaps) > 0 {
		t.Errorf("cluster storage manager (database provider) fails capability check for shape %q:\n%s",
			shapeCluster, strings.Join(gaps, "\n"))
	}
}

// TestCapabilityCompleteness_ClusterRegression_Issue3401 verifies that the
// contract check catches the specific gap introduced before issue #3401 was
// fixed: the database provider declining CreatePendingRegistrationStore with
// ErrNotSupported, leaving the registration subsystem without its required store
// in cluster mode.
//
// The test temporarily replaces the registered "database" provider with one that
// declines PendingRegistrationStore, builds the cluster manager through the real
// CreateClusterStorageManager path, and confirms checkProviderSatisfiesShape
// reports the gap with the correct provider, store, subsystem, and shape labels.
// A test that passes with the declining provider would not be testing anything.
func TestCapabilityCompleteness_ClusterRegression_Issue3401(t *testing.T) {
	pgDSN := skipIfNoPostgres(t)

	original, err := interfaces.GetStorageProvider("database")
	require.NoError(t, err)
	interfaces.RegisterStorageProvider(newDecliningRegistrationDatabaseProvider())
	defer interfaces.RegisterStorageProvider(original)

	sm, err := interfaces.CreateClusterStorageManager(pgDSN, testSessionHMACKey(), nil)
	require.NoError(t, err, "CreateClusterStorageManager must tolerate a declined optional-at-construction store (nil field), so the factory itself does not error")
	t.Cleanup(func() { _ = sm.Close() })

	assert.False(t, sm.HasStore(interfaces.StoreNamePendingRegistration),
		"the declining provider must leave PendingRegistrationStore absent from the composed manager")

	gaps := checkProviderSatisfiesShape(sm, shapeCluster, "database")
	require.NotEmpty(t, gaps, "checkProviderSatisfiesShape must report a gap when PendingRegistrationStore is absent")

	joined := strings.Join(gaps, "\n")
	assert.Contains(t, joined, "database", "error must name the provider")
	assert.Contains(t, joined, string(interfaces.StoreNamePendingRegistration), "error must name the missing store")
	assert.Contains(t, joined, "registration", "error must name the requiring subsystem")
	assert.Contains(t, joined, string(shapeCluster), "error must name the deployment shape")
}

// TestCapabilityCompleteness_ClusterRegression_Issue3402 verifies that the
// contract check catches the specific gaps present before issue #3402 was fixed:
// the database provider declining CreateTriggerStore and CreatePushStore with
// ErrNotSupported. Both stores are required by their respective subsystems in
// cluster mode.
func TestCapabilityCompleteness_ClusterRegression_Issue3402(t *testing.T) {
	pgDSN := skipIfNoPostgres(t)

	original, err := interfaces.GetStorageProvider("database")
	require.NoError(t, err)
	interfaces.RegisterStorageProvider(newDecliningTriggerPushDatabaseProvider())
	defer interfaces.RegisterStorageProvider(original)

	sm, err := interfaces.CreateClusterStorageManager(pgDSN, testSessionHMACKey(), nil)
	require.NoError(t, err, "CreateClusterStorageManager must tolerate declined optional-at-construction stores (nil fields)")
	t.Cleanup(func() { _ = sm.Close() })

	assert.False(t, sm.HasStore(interfaces.StoreNameTrigger),
		"the declining provider must leave TriggerStore absent from the composed manager")
	assert.False(t, sm.HasStore(interfaces.StoreNamePush),
		"the declining provider must leave PushStore absent from the composed manager")

	gaps := checkProviderSatisfiesShape(sm, shapeCluster, "database")
	require.NotEmpty(t, gaps, "checkProviderSatisfiesShape must report gaps when TriggerStore and PushStore are absent")

	joined := strings.Join(gaps, "\n")
	assert.Contains(t, joined, string(interfaces.StoreNameTrigger), "error must name TriggerStore")
	assert.Contains(t, joined, string(interfaces.StoreNamePush), "error must name PushStore")
	assert.Contains(t, joined, "triggers", "error must name the triggers subsystem")
	assert.Contains(t, joined, "push", "error must name the push subsystem")
	assert.Contains(t, joined, string(shapeCluster), "error must name the deployment shape")
}

// TestCapabilityMatrix_AllShapesCovered verifies that every store listed in
// allStores has at least one entry in shapeCapabilityMatrix. A store in
// allStores that has no matrix entry fails here, forcing the author to make an
// explicit decision about where the store is required.
//
// allStores must be kept in sync with the StoreName constants in
// requirements.go. Go has no runtime enum reflection, so this is a two-place
// update: when adding a new StoreName to requirements.go, also add it to
// allStores below. The comment here states the required action explicitly so
// that a missed update is visible as soon as the reader looks at the test.
func TestCapabilityMatrix_AllShapesCovered(t *testing.T) {
	allStores := []interfaces.StoreName{
		interfaces.StoreNameClientTenant,
		interfaces.StoreNameConfig,
		interfaces.StoreNameAudit,
		interfaces.StoreNameRBAC,
		interfaces.StoreNameTenant,
		interfaces.StoreNameRegistrationToken,
		interfaces.StoreNameSession,
		interfaces.StoreNameSteward,
		interfaces.StoreNameCommand,
		interfaces.StoreNameTrigger,
		interfaces.StoreNamePush,
		interfaces.StoreNamePendingRegistration,
		interfaces.StoreNameIPTrust,
		interfaces.StoreNameAlert,
		interfaces.StoreNamePendingRefresh,
		interfaces.StoreNameRefreshPolicy,
		interfaces.StoreNameAssurancePolicy,
		interfaces.StoreNameTenantCrossing,
	}

	for _, storeName := range allStores {
		t.Run(string(storeName), func(t *testing.T) {
			var found bool
			for _, entries := range shapeCapabilityMatrix {
				for _, entry := range entries {
					if entry.store == storeName {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			assert.True(t, found,
				"store %q is declared in requirements.go but has no entry in shapeCapabilityMatrix — add it to at least one deployment shape in contract_test.go",
				storeName)
		})
	}
}
