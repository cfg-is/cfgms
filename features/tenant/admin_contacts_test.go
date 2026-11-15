// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestManager_ResolveOwningMSPID(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()
	for _, r := range []*TenantRequest{
		{ID: "msp-a", ParentID: testRootTenantID},
		{ID: "client-1", ParentID: "msp-a"},
		{ID: "site-1", ParentID: "client-1"},
		{ID: "msp-b", ParentID: testRootTenantID},
	} {
		_, err := m.CreateTenant(ctx, r)
		require.NoError(t, err)
	}

	assert.Equal(t, "msp-a", m.ResolveOwningMSPID(ctx, "msp-a"), "the MSP seam tenant owns itself")
	assert.Equal(t, "msp-a", m.ResolveOwningMSPID(ctx, "client-1"), "child resolves to its MSP")
	assert.Equal(t, "msp-a", m.ResolveOwningMSPID(ctx, "site-1"), "grandchild resolves to its MSP")
	assert.Equal(t, "msp-b", m.ResolveOwningMSPID(ctx, "msp-b"))
	assert.Empty(t, m.ResolveOwningMSPID(ctx, testRootTenantID), "the root has no owning MSP")
	assert.Empty(t, m.ResolveOwningMSPID(ctx, "missing"), "an unknown tenant has no owning MSP")
	assert.Empty(t, m.ResolveOwningMSPID(ctx, ""), "an empty id has no owning MSP")
}

func TestManager_ResolveOwningMSPID_DetachedAndRootless(t *testing.T) {
	ctx := context.Background()

	t.Run("detached tenant whose parent does not exist", func(t *testing.T) {
		m := newTestTenantManager(t)
		now := time.Now()
		require.NoError(t, m.store.CreateTenant(ctx, &business.TenantData{
			ID: "detached", Name: "detached", ParentID: "ghost-parent",
			Status: business.TenantStatusActive, CreatedAt: now, UpdatedAt: now}))
		assert.Empty(t, m.ResolveOwningMSPID(ctx, "detached"))
	})

	t.Run("no root tenant at all", func(t *testing.T) {
		m := newBareTestTenantManager(t)
		assert.Empty(t, m.ResolveOwningMSPID(ctx, "anything"))
	})
}

func TestManager_ResolveMSPAdminContacts_UsesOwningMSP(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()
	for _, r := range []*TenantRequest{
		{ID: "msp-a", ParentID: testRootTenantID},
		{ID: "client-1", ParentID: "msp-a"},
	} {
		_, err := m.CreateTenant(ctx, r)
		require.NoError(t, err)
	}
	_, err := m.SetAdminContacts(ctx, "msp-a", []string{"ops@example.com"})
	require.NoError(t, err)
	assert.Equal(t, []string{"ops@example.com"}, m.ResolveMSPAdminContacts(ctx, "client-1"))
	assert.Empty(t, m.ResolveMSPAdminContacts(ctx, "missing"))
}
