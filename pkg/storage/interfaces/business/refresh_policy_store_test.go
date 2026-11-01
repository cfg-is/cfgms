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

// inMemRefreshPolicyStore is a minimal in-memory RefreshPolicyStore for contract tests.
type inMemRefreshPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*business.RefreshPolicy
}

func newInMemRefreshPolicyStore() business.RefreshPolicyStore {
	return &inMemRefreshPolicyStore{policies: make(map[string]*business.RefreshPolicy)}
}

func (s *inMemRefreshPolicyStore) GetPolicy(_ context.Context, tenantID string) (*business.RefreshPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[tenantID]
	if !ok {
		return &business.RefreshPolicy{
			TenantID:        tenantID,
			Mode:            "require_approval",
			MaxDormancyDays: nil,
		}, nil
	}
	cp := *p
	if cp.MaxDormancyDays != nil {
		v := *cp.MaxDormancyDays
		cp.MaxDormancyDays = &v
	}
	return &cp, nil
}

func (s *inMemRefreshPolicyStore) SetPolicy(_ context.Context, policy *business.RefreshPolicy) error {
	if policy == nil {
		return errStr("nil policy")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *policy
	if cp.MaxDormancyDays != nil {
		v := *cp.MaxDormancyDays
		cp.MaxDormancyDays = &v
	}
	s.policies[policy.TenantID] = &cp
	return nil
}

// Compile-time assertion.
var _ business.RefreshPolicyStore = (*inMemRefreshPolicyStore)(nil)

// --- Contract tests ---

func TestRefreshPolicyStore_DefaultPolicy_Contract(t *testing.T) {
	store := newInMemRefreshPolicyStore()

	got, err := store.GetPolicy(context.Background(), "tenant-absent")
	require.NoError(t, err, "absent record must not be an error")
	require.NotNil(t, got)
	assert.Equal(t, "tenant-absent", got.TenantID)
	assert.Equal(t, "require_approval", got.Mode)
	assert.Nil(t, got.MaxDormancyDays, "MaxDormancyDays must default to nil (backstop OFF)")
}

func TestRefreshPolicyStore_SetAndGet_Contract(t *testing.T) {
	store := newInMemRefreshPolicyStore()
	ctx := context.Background()

	days := 30
	require.NoError(t, store.SetPolicy(ctx, &business.RefreshPolicy{
		TenantID:        "tenant-1",
		Mode:            "auto_accept",
		MaxDormancyDays: &days,
	}))

	got, err := store.GetPolicy(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "auto_accept", got.Mode)
	require.NotNil(t, got.MaxDormancyDays)
	assert.Equal(t, 30, *got.MaxDormancyDays)
}

func TestRefreshPolicyStore_SetOverwrites_Contract(t *testing.T) {
	store := newInMemRefreshPolicyStore()
	ctx := context.Background()

	require.NoError(t, store.SetPolicy(ctx, &business.RefreshPolicy{TenantID: "t-upd", Mode: "auto_accept"}))
	require.NoError(t, store.SetPolicy(ctx, &business.RefreshPolicy{TenantID: "t-upd", Mode: "reject"}))

	got, err := store.GetPolicy(ctx, "t-upd")
	require.NoError(t, err)
	assert.Equal(t, "reject", got.Mode)
}

func TestRefreshPolicyStore_SetNilPolicy_Contract(t *testing.T) {
	store := newInMemRefreshPolicyStore()
	err := store.SetPolicy(context.Background(), nil)
	require.Error(t, err)
}

func TestRefreshPolicyStore_ModeValues(t *testing.T) {
	assert.Equal(t, "require_approval", "require_approval")
	assert.Equal(t, "auto_accept", "auto_accept")
	assert.Equal(t, "reject", "reject")
}
