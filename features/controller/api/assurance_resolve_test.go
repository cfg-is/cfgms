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

