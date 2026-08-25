// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ---- in-memory test doubles (real implementations, no mocks) ----

// testAssurancePolicyStore is a real in-memory AssurancePolicyStore.
type testAssurancePolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*business.AssurancePolicy
}

func newTestAssurancePolicyStore() *testAssurancePolicyStore {
	return &testAssurancePolicyStore{policies: make(map[string]*business.AssurancePolicy)}
}

func (s *testAssurancePolicyStore) GetPolicy(_ context.Context, tenantID string) (*business.AssurancePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.policies[tenantID]; ok {
		cp := *p
		return &cp, nil
	}
	return &business.AssurancePolicy{TenantID: tenantID, Overrides: nil}, nil
}

func (s *testAssurancePolicyStore) SetPolicy(_ context.Context, p *business.AssurancePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *p
	s.policies[p.TenantID] = &cp
	return nil
}

// errorAssurancePolicyStore always returns an error from GetPolicy.
type errorAssurancePolicyStore struct{}

func (errorAssurancePolicyStore) GetPolicy(_ context.Context, _ string) (*business.AssurancePolicy, error) {
	return nil, errors.New("storage unavailable")
}
func (errorAssurancePolicyStore) SetPolicy(_ context.Context, _ *business.AssurancePolicy) error {
	return errors.New("storage unavailable")
}

// testTenantStoreWithPath is a real in-memory TenantStore that returns a
// pre-configured path for GetTenantPath. Unrecognised IDs return an error.
type testTenantStoreWithPath struct {
	business.TenantStore // embed for unimplemented methods
	paths                map[string][]string
}

func newTestTenantStoreWithPath(paths map[string][]string) *testTenantStoreWithPath {
	return &testTenantStoreWithPath{paths: paths}
}

func (s *testTenantStoreWithPath) GetTenantPath(_ context.Context, tenantID string) ([]string, error) {
	if p, ok := s.paths[tenantID]; ok {
		return p, nil
	}
	return nil, errors.New("tenant not found: " + tenantID)
}

// errorTenantStore always returns an error from GetTenantPath.
type errorTenantStore struct {
	business.TenantStore
}

func (errorTenantStore) GetTenantPath(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("tenant store unavailable")
}

// ---- tests for resolveAssuranceRequirement ----

// TestResolveAssurance_NilStores verifies that when assurancePolicyStore or
// tenantStore is nil the resolver returns the global permissionAssurance floor
// unchanged — preserving backward compatibility for bare Server instances.
func TestResolveAssurance_NilStores(t *testing.T) {
	srv := &Server{} // no stores

	// certificate:provision is AssuranceStrong in the global map.
	req, found := srv.resolveAssuranceRequirement(context.Background(), "some-tenant", "certificate:provision")
	require.True(t, found)
	assert.Equal(t, session.AssuranceStrong, req.Min)
	assert.False(t, req.RequireUserPresence)

	// A permission absent from the global map must return found=false.
	req2, found2 := srv.resolveAssuranceRequirement(context.Background(), "some-tenant", "nonexistent:perm")
	assert.False(t, found2)
	assert.Equal(t, session.AssuranceLevel(0), req2.Min)
}

// TestResolveAssurance_EmptyTenantID verifies that an empty tenantID causes the
// resolver to return the global floor (no store lookup).
func TestResolveAssurance_EmptyTenantID(t *testing.T) {
	srv := &Server{
		assurancePolicyStore: newTestAssurancePolicyStore(),
		tenantStore:          newTestTenantStoreWithPath(map[string][]string{}),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "", "certificate:provision")
	require.True(t, found)
	assert.Equal(t, session.AssuranceStrong, req.Min)
}

// TestResolveAssurance_NoOverride verifies that when no tenant in the path has
// an override the global floor is returned unchanged.
func TestResolveAssurance_NoOverride(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "root/child", "certificate:provision")
	require.True(t, found)
	assert.Equal(t, session.AssuranceStrong, req.Min)
	assert.False(t, req.RequireUserPresence)
}

// TestResolveAssurance_TenantRaisesMin verifies that a tenant override with a
// matching permissionID and MinOverride raises the effective Min.
func TestResolveAssurance_TenantRaisesMin(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	// certificate:provision global floor is AssuranceStrong (the max), so test with
	// a synthetic low-floor permission injected temporarily into the global map.
	const testPerm = "test-resolve:low-floor"
	permissionAssurance[testPerm] = Requirement{Min: session.AssuranceBasic}
	t.Cleanup(func() { delete(permissionAssurance, testPerm) })

	strongInt := int(session.AssuranceStrong)
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root/child",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: testPerm, MinOverride: &strongInt},
		},
	}))

	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "root/child", testPerm)
	require.True(t, found)
	assert.Equal(t, session.AssuranceStrong, req.Min, "child override must raise Min to Strong")
	assert.False(t, req.RequireUserPresence)
}

// TestResolveAssurance_TenantAddsPresence verifies that a tenant override with
// RequireUserPresence: true adds the presence requirement regardless of Min.
func TestResolveAssurance_TenantAddsPresence(t *testing.T) {
	apStore := newTestAssurancePolicyStore()

	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root/child",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "certificate:provision", RequireUserPresence: true},
		},
	}))

	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "root/child", "certificate:provision")
	require.True(t, found)
	assert.Equal(t, session.AssuranceStrong, req.Min, "global floor Min must be preserved")
	assert.True(t, req.RequireUserPresence, "tenant override must add RequireUserPresence")
}

// TestResolveAssurance_ParentOverrideInherited verifies that a parent tenant's
// override is inherited by a child tenant that has no override of its own.
func TestResolveAssurance_ParentOverrideInherited(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	const testPerm = "test-resolve:inherit"
	permissionAssurance[testPerm] = Requirement{Min: session.AssuranceBasic}
	t.Cleanup(func() { delete(permissionAssurance, testPerm) })

	strongInt := int(session.AssuranceStrong)
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: testPerm, MinOverride: &strongInt},
		},
	}))

	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "root/child", testPerm)
	require.True(t, found, "parent override must be found for child")
	assert.Equal(t, session.AssuranceStrong, req.Min, "child must inherit parent's raised Min")
}

// TestResolveAssurance_ChildCanFurtherTighten verifies that a child tenant can raise
// Min beyond what a parent already set.
func TestResolveAssurance_ChildCanFurtherTighten(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	const testPerm = "test-resolve:further-tighten"
	permissionAssurance[testPerm] = Requirement{Min: session.AssuranceBasic}
	t.Cleanup(func() { delete(permissionAssurance, testPerm) })

	// Parent sets Basic-floor -> Strong; child additionally sets RequireUserPresence.
	strongInt := int(session.AssuranceStrong)
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: testPerm, MinOverride: &strongInt},
		},
	}))
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root/child",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: testPerm, RequireUserPresence: true},
		},
	}))

	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "root/child", testPerm)
	require.True(t, found)
	assert.Equal(t, session.AssuranceStrong, req.Min, "parent Min must carry through")
	assert.True(t, req.RequireUserPresence, "child RequireUserPresence must be applied on top of parent")
}

// TestResolveAssurance_SiblingTenantIndependent verifies that an override on one
// sibling tenant does not affect a sibling that has no override.
func TestResolveAssurance_SiblingTenantIndependent(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	const testPerm = "test-resolve:sibling"
	permissionAssurance[testPerm] = Requirement{Min: session.AssuranceBasic}
	t.Cleanup(func() { delete(permissionAssurance, testPerm) })

	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root/sibling-a",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: testPerm, RequireUserPresence: true},
		},
	}))

	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/sibling-a": {"root", "root/sibling-a"},
		"root/sibling-b": {"root", "root/sibling-b"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	// sibling-a: has override with RequireUserPresence.
	reqA, _ := srv.resolveAssuranceRequirement(context.Background(), "root/sibling-a", testPerm)
	assert.True(t, reqA.RequireUserPresence, "sibling-a must have RequireUserPresence from its own override")

	// sibling-b: no override — global floor only.
	reqB, _ := srv.resolveAssuranceRequirement(context.Background(), "root/sibling-b", testPerm)
	assert.False(t, reqB.RequireUserPresence, "sibling-b must NOT inherit sibling-a's override")
	assert.Equal(t, session.AssuranceBasic, reqB.Min, "sibling-b must see global floor only")
}

// TestResolveAssurance_GetTenantPathError_FallsBackToFloor verifies that a
// GetTenantPath error causes the resolver to log a warning and return the
// global floor (fail-safe, not fail-open).
func TestResolveAssurance_GetTenantPathError_FallsBackToFloor(t *testing.T) {
	srv := &Server{
		assurancePolicyStore: newTestAssurancePolicyStore(),
		tenantStore:          errorTenantStore{},
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "some-tenant", "certificate:provision")
	require.True(t, found, "floor must still be found even on error")
	assert.Equal(t, session.AssuranceStrong, req.Min, "must fall back to global floor on error")
	assert.False(t, req.RequireUserPresence)
}

// TestResolveAssurance_GetPolicyError_FallsBackToFloor verifies that a
// GetPolicy error causes the resolver to log a warning and return the
// global floor (fail-safe, not fail-open).
func TestResolveAssurance_GetPolicyError_FallsBackToFloor(t *testing.T) {
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := &Server{
		assurancePolicyStore: errorAssurancePolicyStore{},
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "root/child", "certificate:provision")
	require.True(t, found, "floor must still be found even on GetPolicy error")
	assert.Equal(t, session.AssuranceStrong, req.Min, "must fall back to global floor on error")
}

// TestResolveAssurance_UnknownPermission_FoundByOverride verifies that a permission
// absent from the global map but declared via a tenant override is reported as found.
func TestResolveAssurance_UnknownPermission_FoundByOverride(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	strongInt := int(session.AssuranceStrong)
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "new:custom-perm", MinOverride: &strongInt},
		},
	}))
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root": {"root"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "root", "new:custom-perm")
	require.True(t, found, "tenant-declared perm must be reported as found")
	assert.Equal(t, session.AssuranceStrong, req.Min)
}

// ---- pre-rename permission-ID overrides (Issue #3574) ----
//
// The web-account:* -> account:* rename moved the permission IDs that gate account
// creation, update, deletion and enrollment-link revocation. Per-tenant assurance-policy
// overrides are persisted keyed by the literal ID an admin wrote, so without alias-aware
// matching the rename would silently drop a deliberately raised bar — the fail-OPEN
// direction. These tests pin that behaviour.

// TestResolveAssurance_LegacyWebAccountOverride_PreservesPresence verifies that a stored
// override keyed by the pre-rename ID "web-account:delete" still applies its
// RequireUserPresence requirement to the renamed permission "account:delete".
func TestResolveAssurance_LegacyWebAccountOverride_PreservesPresence(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root/child",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "web-account:delete", RequireUserPresence: true},
		},
	}))
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirement(context.Background(), "root/child", "account:delete")
	require.True(t, found)
	assert.Equal(t, session.AssuranceStrong, req.Min, "global floor for account:delete must be preserved")
	assert.True(t, req.RequireUserPresence,
		"an override stored under the pre-rename ID web-account:delete must still require user presence "+
			"for account:delete — dropping it silently is the fail-open direction")
}

// TestResolveAssurance_LegacyOverride_DoesNotLeakAcrossPermissions verifies that the alias
// match is exact per operation: an override on web-account:list must not raise the bar for
// account:delete, and an unrelated legacy ID must not match at all.
func TestResolveAssurance_LegacyOverride_DoesNotLeakAcrossPermissions(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root/child",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "web-account:list", RequireUserPresence: true},
		},
	}))
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := &Server{
		assurancePolicyStore: apStore,
		tenantStore:          tsStore,
		logger:               logging.NewNoopLogger(),
	}

	req, _ := srv.resolveAssuranceRequirement(context.Background(), "root/child", "account:delete")
	assert.False(t, req.RequireUserPresence,
		"web-account:list must alias only to account:list, never to another account:* permission")

	reqList, foundList := srv.resolveAssuranceRequirement(context.Background(), "root/child", "account:list")
	require.True(t, foundList, "an override stored under a legacy ID must make the renamed permission found")
	assert.True(t, reqList.RequireUserPresence, "web-account:list must alias to account:list")
}

// TestResolveAssuranceForPath_LegacyOverride_CountsAsAncestorBar verifies that the
// tighten-only write validation in handleSetAssurancePolicy also honours a pre-rename
// ancestor override — otherwise a descendant could be told its lower bar is acceptable.
func TestResolveAssuranceForPath_LegacyOverride_CountsAsAncestorBar(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "web-account:update", RequireUserPresence: true},
		},
	}))
	srv := &Server{
		assurancePolicyStore: apStore,
		logger:               logging.NewNoopLogger(),
	}

	req, found := srv.resolveAssuranceRequirementForPath(context.Background(), []string{"root"}, "account:update")
	require.True(t, found)
	assert.True(t, req.RequireUserPresence,
		"the ancestor bar used for tighten-only validation must include pre-rename override IDs")
}

// TestOverrideAppliesTo verifies the alias predicate directly: exact matches, pre-rename
// matches, and non-matches.
func TestOverrideAppliesTo(t *testing.T) {
	assert.True(t, overrideAppliesTo("account:delete", "account:delete"), "exact match must apply")
	assert.True(t, overrideAppliesTo("web-account:delete", "account:delete"), "pre-rename ID must apply")
	assert.True(t, overrideAppliesTo("web-account:revoke-enrollment-link", "account:revoke-enrollment-link"))
	assert.False(t, overrideAppliesTo("account:delete", "account:create"), "different permissions must not match")
	assert.False(t, overrideAppliesTo("web-account:delete", "account:create"),
		"a pre-rename ID must not match a different operation")
	assert.False(t, overrideAppliesTo("account:delete", "web-account:delete"),
		"aliasing is one-way: the current ID must not satisfy a lookup of the retired ID")

	// Every legacy ID must alias to a permission that still exists in knownPermissions —
	// a mapping to a dead target would be silently inert.
	for current := range legacyPermissionIDs {
		assert.True(t, isKnownPermission(current),
			"legacyPermissionIDs target %q must be a live permission ID", current)
	}
}
