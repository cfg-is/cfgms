// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// newEmptySM returns a StorageManager with no stores — providerName is "composite"
// because NewStorageManagerFromStores always sets that value.
func newEmptySM() *interfaces.StorageManager {
	return interfaces.NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
}

// TestValidateStorageRequirements_RequiredMissingFails verifies that a missing
// required store returns an error that names the declaring subsystem, the store,
// and the provider — satisfying the three-part naming rule in #3407.
func TestValidateStorageRequirements_RequiredMissingFails(t *testing.T) {
	sm := newEmptySM()

	// test-registration is a test-only stand-in for a real subsystem.
	// It declares PendingRegistrationStore as required — the store that was absent
	// when issue #3400 was filed and that this mechanism is designed to catch early.
	reqs := []interfaces.StoreRequirement{
		{
			Subsystem: "test-registration",
			Store:     interfaces.StoreNamePendingRegistration,
			Severity:  interfaces.RequirementRequired,
		},
	}

	err := interfaces.ValidateStorageRequirements(sm, reqs)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "test-registration", "error must name the declaring subsystem")
	assert.Contains(t, err.Error(), string(interfaces.StoreNamePendingRegistration), "error must name the missing store")
	assert.Contains(t, err.Error(), "composite", "error must name the provider")
}

// TestValidateStorageRequirements_OptionalMissingPasses verifies that a missing
// optional store does NOT block startup — only required stores do.
func TestValidateStorageRequirements_OptionalMissingPasses(t *testing.T) {
	sm := newEmptySM()

	reqs := []interfaces.StoreRequirement{
		{Subsystem: "test-push", Store: interfaces.StoreNamePush, Severity: interfaces.RequirementOptional},
	}

	require.NoError(t, interfaces.ValidateStorageRequirements(sm, reqs),
		"an optional missing store must not block startup")
}

// TestValidateStorageRequirements_EmptyPassesAlways covers the no-subsystems-enabled
// case: an empty or nil requirements slice must always succeed.
func TestValidateStorageRequirements_EmptyPassesAlways(t *testing.T) {
	sm := newEmptySM()
	require.NoError(t, interfaces.ValidateStorageRequirements(sm, nil))
	require.NoError(t, interfaces.ValidateStorageRequirements(sm, []interfaces.StoreRequirement{}))
}

// testSubsystemRequirements mirrors the shape collectActiveStorageRequirements
// (features/controller/server/server.go) will take once #3491/#3492/#3493 wire
// real subsystem declarations: a subsystem's requirement is only contributed to
// the collection when the subsystem is enabled in this deployment.
func testSubsystemRequirements(enabled bool) []interfaces.StoreRequirement {
	if !enabled {
		return nil
	}
	return []interfaces.StoreRequirement{
		{
			Subsystem: "test-registration",
			Store:     interfaces.StoreNamePendingRegistration,
			Severity:  interfaces.RequirementRequired,
		},
	}
}

// TestValidateStorageRequirements_DisabledSubsystemIgnored demonstrates actual
// enablement gating: the same subsystem's requirement blocks startup when the
// subsystem is enabled and is never collected — so cannot block startup — when
// it is disabled. Both branches run against the same store-less manager, so the
// only variable is the enablement gate itself.
func TestValidateStorageRequirements_DisabledSubsystemIgnored(t *testing.T) {
	sm := newEmptySM()

	t.Run("enabled subsystem's missing required store blocks startup", func(t *testing.T) {
		err := interfaces.ValidateStorageRequirements(sm, testSubsystemRequirements(true))
		require.Error(t, err, "an enabled subsystem's missing required store must block startup")
		assert.Contains(t, err.Error(), "test-registration")
	})

	t.Run("disabled subsystem's requirement is never collected and cannot block startup", func(t *testing.T) {
		err := interfaces.ValidateStorageRequirements(sm, testSubsystemRequirements(false))
		require.NoError(t, err, "a disabled subsystem's requirement must not be collected, so it cannot block startup")
	})
}

// TestValidateStorageRequirements_OSSStartsClean verifies that the real OSS
// composite storage manager satisfies an empty requirement set (the current
// state before #3491/#3492/#3493 wire real subsystem declarations under epic
// #3406).
func TestValidateStorageRequirements_OSSStartsClean(t *testing.T) {
	ffCfg, sqCfg := ossConfigs(t)
	sm, err := interfaces.CreateOSSStorageManager(ffCfg["root"].(string), sqCfg["path"].(string))
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	require.NoError(t, interfaces.ValidateStorageRequirements(sm, nil),
		"OSS composite storage manager must pass an empty requirements set")
}

// TestValidateStorageRequirements_ClusterStartsClean verifies that the real
// cluster (database-provider-backed) storage manager satisfies an empty
// requirement set — the cluster-deployment counterpart to
// TestValidateStorageRequirements_OSSStartsClean. #3407's acceptance criteria
// name both OSS and cluster deployments explicitly.
func TestValidateStorageRequirements_ClusterStartsClean(t *testing.T) {
	pgDSN := skipIfNoPostgres(t)

	sm, err := interfaces.CreateClusterStorageManager(pgDSN, testSessionHMACKey(), nil)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	require.NoError(t, interfaces.ValidateStorageRequirements(sm, nil),
		"cluster storage manager must pass an empty requirements set")
}

// TestValidateStorageRequirements_RegressionIssue3400_RealProvider reproduces the
// #3400 condition against an actual declining provider implementation — not the
// synthetic store-less StorageManager used by
// TestValidateStorageRequirements_RegressionIssue3400 — by temporarily swapping
// the registered "database" provider for one that declines
// CreatePendingRegistrationStore exactly as the real provider did before #3401
// fixed it, then running the composed manager through the real
// CreateClusterStorageManager path before validating it.
func TestValidateStorageRequirements_RegressionIssue3400_RealProvider(t *testing.T) {
	pgDSN := skipIfNoPostgres(t)

	original, err := interfaces.GetStorageProvider("database")
	require.NoError(t, err)
	interfaces.RegisterStorageProvider(newDecliningRegistrationDatabaseProvider())
	defer interfaces.RegisterStorageProvider(original)

	sm, err := interfaces.CreateClusterStorageManager(pgDSN, testSessionHMACKey(), nil)
	require.NoError(t, err, "CreateClusterStorageManager must tolerate a declined optional-at-construction store as a nil field — the downstream nil-check defense in depth this story does not remove")
	defer func() { _ = sm.Close() }()
	require.False(t, sm.HasStore(interfaces.StoreNamePendingRegistration),
		"a declining provider must leave PendingRegistrationStore absent from the composed manager")

	reqs := []interfaces.StoreRequirement{
		{Subsystem: "registration", Store: interfaces.StoreNamePendingRegistration, Severity: interfaces.RequirementRequired},
	}
	err = interfaces.ValidateStorageRequirements(sm, reqs)

	require.Error(t, err, "a real provider declining a required store must fail closed at composition time")
	assert.Contains(t, err.Error(), "registration", "error must name the declaring subsystem")
	assert.Contains(t, err.Error(), string(interfaces.StoreNamePendingRegistration), "error must name the missing store")
	assert.Contains(t, err.Error(), "database", "error must name the provider")
}

// TestValidateStorageRequirements_RegressionIssue3400 is the regression guard for
// issue #3400. It reintroduces the #3400 condition — a StorageManager where the
// provider has declined PendingRegistrationStore (the store is nil) — and confirms
// that ValidateStorageRequirements now catches this at composition time, producing
// an error that names the requiring subsystem, the store, and the provider, rather
// than propagating a silent nil that causes a 503 at request time.
//
// In production this scenario would arise if the database provider regressed and
// returned ErrNotSupported for CreatePendingRegistrationStore, leaving the cluster
// manager's pendingRegistrationStore field nil.
func TestValidateStorageRequirements_RegressionIssue3400(t *testing.T) {
	// Build a manager where PendingRegistrationStore is absent — mirrors what
	// CreateClusterStorageManager would produce under the #3400 regression.
	sm := newEmptySM()

	reqs := []interfaces.StoreRequirement{
		{
			Subsystem: "registration",
			Store:     interfaces.StoreNamePendingRegistration,
			Severity:  interfaces.RequirementRequired,
		},
	}

	err := interfaces.ValidateStorageRequirements(sm, reqs)

	require.Error(t, err, "missing required store must block startup")
	assert.Contains(t, err.Error(), "registration")
	assert.Contains(t, err.Error(), "PendingRegistrationStore")
	assert.Contains(t, err.Error(), "composite")
}

// TestValidateStorageRequirements_MultipleErrors verifies that all missing required
// stores are named in a single error, not just the first one.
func TestValidateStorageRequirements_MultipleErrors(t *testing.T) {
	sm := newEmptySM()

	reqs := []interfaces.StoreRequirement{
		{Subsystem: "registration", Store: interfaces.StoreNamePendingRegistration, Severity: interfaces.RequirementRequired},
		{Subsystem: "push", Store: interfaces.StoreNamePush, Severity: interfaces.RequirementRequired},
	}

	err := interfaces.ValidateStorageRequirements(sm, reqs)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration")
	assert.Contains(t, err.Error(), "push")
	assert.Contains(t, err.Error(), "PendingRegistrationStore")
	assert.Contains(t, err.Error(), "PushStore")
}

// TestStorageManager_HasStore verifies HasStore for every known StoreName constant
// against a manager with no stores (all should return false) and spot-checks a few
// stores against the real OSS provider (should return true when the provider
// supplies them).
func TestStorageManager_HasStore(t *testing.T) {
	allNames := []interfaces.StoreName{
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

	t.Run("empty manager returns false for all stores", func(t *testing.T) {
		sm := newEmptySM()
		for _, name := range allNames {
			assert.False(t, sm.HasStore(name), "HasStore(%q) should be false on an empty manager", name)
		}
	})

	t.Run("unknown store name returns false", func(t *testing.T) {
		sm := newEmptySM()
		assert.False(t, sm.HasStore("NonexistentStore"))
	})

	t.Run("OSS composite manager has expected stores", func(t *testing.T) {
		ffCfg, sqCfg := ossConfigs(t)
		sm, err := interfaces.CreateOSSStorageManager(ffCfg["root"].(string), sqCfg["path"].(string))
		require.NoError(t, err)
		defer func() { _ = sm.Close() }()

		// These stores are always present in the OSS composite provider.
		alwaysPresent := []interfaces.StoreName{
			interfaces.StoreNameConfig,
			interfaces.StoreNameAudit,
			interfaces.StoreNameSteward,
			interfaces.StoreNameIPTrust,
			interfaces.StoreNameAlert,
			interfaces.StoreNameRBAC,
			interfaces.StoreNameTenant,
			interfaces.StoreNameClientTenant,
			interfaces.StoreNameRegistrationToken,
			interfaces.StoreNamePendingRegistration,
			interfaces.StoreNamePendingRefresh,
			interfaces.StoreNameRefreshPolicy,
			interfaces.StoreNameAssurancePolicy,
			interfaces.StoreNameTenantCrossing,
		}
		for _, name := range alwaysPresent {
			assert.True(t, sm.HasStore(name), "HasStore(%q) should be true for OSS composite manager", name)
		}
	})
}
