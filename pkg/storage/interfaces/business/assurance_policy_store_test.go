// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemAssurancePolicyStore is a minimal in-memory AssurancePolicyStore for
// contract tests.
type inMemAssurancePolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*business.AssurancePolicy
}

func newInMemAssurancePolicyStore() business.AssurancePolicyStore {
	return &inMemAssurancePolicyStore{policies: make(map[string]*business.AssurancePolicy)}
}

func (s *inMemAssurancePolicyStore) GetPolicy(_ context.Context, tenantID string) (*business.AssurancePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[tenantID]
	if !ok {
		return &business.AssurancePolicy{TenantID: tenantID, Overrides: nil}, nil
	}
	cp := business.AssurancePolicy{TenantID: p.TenantID}
	if len(p.Overrides) > 0 {
		cp.Overrides = make([]business.AssurancePolicyOverride, len(p.Overrides))
		for i, o := range p.Overrides {
			cp.Overrides[i] = o
			if o.MinOverride != nil {
				v := *o.MinOverride
				cp.Overrides[i].MinOverride = &v
			}
		}
	}
	return &cp, nil
}

func (s *inMemAssurancePolicyStore) SetPolicy(_ context.Context, policy *business.AssurancePolicy) error {
	if policy == nil {
		return errStr("nil policy")
	}
	if policy.TenantID == "" {
		return errStr("empty tenant_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := business.AssurancePolicy{TenantID: policy.TenantID}
	if len(policy.Overrides) > 0 {
		cp.Overrides = make([]business.AssurancePolicyOverride, len(policy.Overrides))
		for i, o := range policy.Overrides {
			cp.Overrides[i] = o
			if o.MinOverride != nil {
				v := *o.MinOverride
				cp.Overrides[i].MinOverride = &v
			}
		}
	}
	s.policies[policy.TenantID] = &cp
	return nil
}

// Compile-time assertion.
var _ business.AssurancePolicyStore = (*inMemAssurancePolicyStore)(nil)

// --- Contract tests ---

func TestAssurancePolicyStore_DefaultEmpty_Contract(t *testing.T) {
	store := newInMemAssurancePolicyStore()

	got, err := store.GetPolicy(context.Background(), "tenant-absent")
	require.NoError(t, err, "absent record must not be an error")
	require.NotNil(t, got)
	assert.Equal(t, "tenant-absent", got.TenantID)
	assert.Nil(t, got.Overrides, "Overrides must default to nil when no record exists")
}

func TestAssurancePolicyStore_SetAndGet_Contract(t *testing.T) {
	store := newInMemAssurancePolicyStore()
	ctx := context.Background()

	min1 := 2 // Strong
	require.NoError(t, store.SetPolicy(ctx, &business.AssurancePolicy{
		TenantID: "tenant-ap-1",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "perm:write", MinOverride: &min1, RequireUserPresence: true},
			{PermissionID: "perm:read"},
		},
	}))

	got, err := store.GetPolicy(ctx, "tenant-ap-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tenant-ap-1", got.TenantID)
	require.Len(t, got.Overrides, 2)
	assert.Equal(t, "perm:write", got.Overrides[0].PermissionID)
	require.NotNil(t, got.Overrides[0].MinOverride)
	assert.Equal(t, 2, *got.Overrides[0].MinOverride)
	assert.True(t, got.Overrides[0].RequireUserPresence)
	assert.Equal(t, "perm:read", got.Overrides[1].PermissionID)
}

func TestAssurancePolicyStore_SetReplacesExisting_Contract(t *testing.T) {
	store := newInMemAssurancePolicyStore()
	ctx := context.Background()

	min1 := 1
	require.NoError(t, store.SetPolicy(ctx, &business.AssurancePolicy{
		TenantID: "tenant-ap-upd",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "perm:admin", MinOverride: &min1},
			{PermissionID: "perm:read"},
		},
	}))

	// Second call drops perm:admin and perm:read, replaces with perm:write.
	min2 := 2
	require.NoError(t, store.SetPolicy(ctx, &business.AssurancePolicy{
		TenantID: "tenant-ap-upd",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "perm:write", MinOverride: &min2},
		},
	}))

	got, err := store.GetPolicy(ctx, "tenant-ap-upd")
	require.NoError(t, err)
	require.Len(t, got.Overrides, 1, "second SetPolicy must fully replace first")
	assert.Equal(t, "perm:write", got.Overrides[0].PermissionID)
	require.NotNil(t, got.Overrides[0].MinOverride)
	assert.Equal(t, 2, *got.Overrides[0].MinOverride)
}

func TestAssurancePolicyStore_SetNilPolicy_Contract(t *testing.T) {
	store := newInMemAssurancePolicyStore()
	err := store.SetPolicy(context.Background(), nil)
	require.Error(t, err)
}

func TestAssurancePolicyStore_SetEmptyTenantID_Contract(t *testing.T) {
	store := newInMemAssurancePolicyStore()
	err := store.SetPolicy(context.Background(), &business.AssurancePolicy{
		Overrides: []business.AssurancePolicyOverride{{PermissionID: "perm:read"}},
	})
	require.Error(t, err)
}
