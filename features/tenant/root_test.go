// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// seedTenant writes a tenant straight to the store, bypassing CreateTenant's
// single-top-level check so tests can build any shape, including ambiguous ones.
func seedTenant(t *testing.T, m *Manager, id, parent string) {
	t.Helper()
	now := time.Now()
	require.NoError(t, m.store.CreateTenant(context.Background(), &business.TenantData{
		ID: id, Name: id, ParentID: parent, Status: business.TenantStatusActive, CreatedAt: now, UpdatedAt: now}))
}

// TestRootTenantID_Resolution guards Issue #4542: the root is the single tenant
// with no parent, whatever its ID; zero or several parentless tenants resolve to
// no root.
func TestRootTenantID_Resolution(t *testing.T) {
	ctx := context.Background()

	t.Run("no tenants", func(t *testing.T) {
		assert.Empty(t, newBareTestTenantManager(t).RootTenantID(ctx))
	})
	for _, name := range []string{"root", "default", "team-root"} {
		t.Run("single top-level tenant named "+name, func(t *testing.T) {
			m := newBareTestTenantManager(t)
			seedTenant(t, m, name, "")
			seedTenant(t, m, "child", name)
			assert.Equal(t, name, m.RootTenantID(ctx), "no tenant is moved or renamed")
		})
	}
	t.Run("several top-level tenants", func(t *testing.T) {
		m := newBareTestTenantManager(t)
		seedTenant(t, m, "root", "")
		seedTenant(t, m, "msp-b", "")
		assert.Empty(t, m.RootTenantID(ctx), "an ambiguous tree has no root, even with a tenant named root")
	})
}

// TestRootTenantID_ChildNamedRootIsOrdinary guards Issue #4542: a tenant whose ID
// is "root" but that has a parent is never resolved or protected as the root.
func TestRootTenantID_ChildNamedRootIsOrdinary(t *testing.T) {
	ctx := context.Background()
	m := newBareTestTenantManager(t)
	seedTenant(t, m, "team-root", "")
	seedTenant(t, m, "msp-a", "team-root")
	_, err := m.CreateTenant(ctx, &TenantRequest{ID: "root", ParentID: "msp-a"})
	require.NoError(t, err, "root is an ordinary ID for a child tenant")

	assert.Equal(t, "team-root", m.RootTenantID(ctx))
	_, err = m.SuspendTenant(ctx, "root")
	assert.NoError(t, err, "a child named root is not protected")
}

// TestRootTenantID_InvalidatedOnCreate verifies the cache does not hide a root
// created through the manager on this node.
func TestRootTenantID_InvalidatedOnCreate(t *testing.T) {
	ctx := context.Background()
	m := newBareTestTenantManager(t)
	require.Empty(t, m.RootTenantID(ctx))

	_, err := m.CreateTenant(ctx, &TenantRequest{ID: "acme-corp"})
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", m.RootTenantID(ctx), "the first top-level tenant is the root")
}

// TestCreateTenant_SecondTopLevelRefused guards Issue #4542: a deployment has
// exactly one tenant with no parent, so a second one is refused.
func TestCreateTenant_SecondTopLevelRefused(t *testing.T) {
	ctx := context.Background()
	m := newBareTestTenantManager(t)
	seedTenant(t, m, "team-root", "")

	_, err := m.CreateTenant(ctx, &TenantRequest{ID: "root"})
	require.ErrorIs(t, err, ErrTopLevelTenantExists)
	_, err = m.CreateTenant(ctx, &TenantRequest{ID: "msp-b"})
	require.ErrorIs(t, err, ErrTopLevelTenantExists)

	_, err = m.CreateTenant(ctx, &TenantRequest{ID: "msp-b", ParentID: "team-root"})
	require.NoError(t, err, "the same tenant under a parent is accepted")
	assert.Equal(t, "team-root", m.RootTenantID(ctx))
}

// TestCreateTenant_ConcurrentTopLevelCreatesLeaveOne guards Issue #4542: two
// top-level creates racing on one node leave exactly one top-level tenant.
func TestCreateTenant_ConcurrentTopLevelCreatesLeaveOne(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		m := newBareTestTenantManager(t)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for j, id := range []string{"root", "team-root"} {
			wg.Add(1)
			go func(j int, id string) {
				defer wg.Done()
				_, errs[j] = m.CreateTenant(ctx, &TenantRequest{ID: id})
			}(j, id)
		}
		wg.Wait()

		var succeeded, refused int
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrTopLevelTenantExists):
				refused++
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		require.Equal(t, 1, succeeded)
		require.Equal(t, 1, refused)
		topLevel, err := m.topLevelTenantIDs(ctx)
		require.NoError(t, err)
		require.Len(t, topLevel, 1)
		assert.Equal(t, topLevel[0], m.RootTenantID(ctx))
	}
}

// TestRootTenantGuards_ProtectResolvedRoot guards Issue #4542: suspend, delete,
// deletion request and deletion approval protect the resolved root whatever it
// is named.
func TestRootTenantGuards_ProtectResolvedRoot(t *testing.T) {
	ctx := context.Background()

	for _, root := range []string{"root", "team-root", "default"} {
		t.Run(root, func(t *testing.T) {
			m := newBareTestTenantManager(t)
			seedTenant(t, m, root, "")
			seedTenant(t, m, "child", root)

			_, err := m.SuspendTenant(ctx, root)
			assert.ErrorIs(t, err, ErrCannotSuspendRoot)
			err = m.DeleteTenant(ctx, root)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cannot delete root tenant")
			_, err = m.RequestTenantDeletion(ctx, root, "alice", 0)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cannot delete root tenant")
			_, err = m.ApproveTenantDeletion(ctx, root, "bob", false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cannot delete root tenant")

			_, err = m.SuspendTenant(ctx, "child")
			assert.NoError(t, err, "only the root is protected")
		})
	}
}

// TestRootTenantGuards_AmbiguousRootFailsClosed verifies that with several
// parentless tenants every one of them is protected — any may be the intended
// root — while tenants below them are not.
func TestRootTenantGuards_AmbiguousRootFailsClosed(t *testing.T) {
	ctx := context.Background()
	m := newBareTestTenantManager(t)
	seedTenant(t, m, "msp-a", "")
	seedTenant(t, m, "msp-b", "")
	seedTenant(t, m, "client-1", "msp-a")
	require.Empty(t, m.RootTenantID(ctx))

	_, err := m.SuspendTenant(ctx, "msp-a")
	assert.ErrorIs(t, err, ErrCannotSuspendRoot)
	_, err = m.SuspendTenant(ctx, "msp-b")
	assert.ErrorIs(t, err, ErrCannotSuspendRoot)
	_, err = m.SuspendTenant(ctx, "client-1")
	assert.NoError(t, err, "a tenant with a parent is never the root")
}

// TestCreateTenant_TwoManagersRacingTopLevelLeaveOne guards Issue #4547: two
// managers — standing in for two controller nodes, sharing no in-process lock —
// over one real store racing top-level creates leave exactly one parentless
// tenant. The store, not the managers' pre-check, is the guarantee.
func TestCreateTenant_TwoManagersRacingTopLevelLeaveOne(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		m1 := newBareTestTenantManager(t)
		m2 := NewManager(m1.store, nil)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for j, c := range []struct {
			m  *Manager
			id string
		}{{m1, "root"}, {m2, "team-root"}} {
			wg.Add(1)
			go func(j int, m *Manager, id string) {
				defer wg.Done()
				<-start
				_, errs[j] = m.CreateTenant(ctx, &TenantRequest{ID: id})
			}(j, c.m, c.id)
		}
		close(start)
		wg.Wait()

		var succeeded int
		for _, err := range errs {
			if err == nil {
				succeeded++
			} else {
				require.ErrorIs(t, err, ErrTopLevelTenantExists)
			}
		}
		require.Equal(t, 1, succeeded)
		topLevel, err := m1.topLevelTenantIDs(ctx)
		require.NoError(t, err)
		require.Len(t, topLevel, 1)
	}
}

// topLevelFaultStore returns scripted errors from CreateTopLevelTenant before
// delegating to the real store, and counts the calls.
type topLevelFaultStore struct {
	Store
	faults []error
	calls  int
}

func (s *topLevelFaultStore) CreateTopLevelTenant(ctx context.Context, td *business.TenantData) error {
	s.calls++
	if len(s.faults) > 0 {
		err := s.faults[0]
		s.faults = s.faults[1:]
		return err
	}
	return s.Store.CreateTopLevelTenant(ctx, td)
}

// TestCreateTenant_TopLevelBillingLabelCollisionRetries guards Issue #4547: a
// billing-label collision on the top-level path retries with a new label, and an
// ErrTopLevelTenantExists result is not retried.
func TestCreateTenant_TopLevelBillingLabelCollisionRetries(t *testing.T) {
	ctx := context.Background()

	t.Run("label collision retries with a new label", func(t *testing.T) {
		m := newBareTestTenantManager(t)
		fs := &topLevelFaultStore{Store: m.store, faults: []error{
			fmt.Errorf("create tenant: %w", business.ErrTenantAlreadyExists)}}
		m.store = fs
		td, err := m.CreateTenant(ctx, &TenantRequest{ID: "root"})
		require.NoError(t, err)
		assert.Equal(t, 2, fs.calls, "one collision, one successful retry")
		got, err := fs.GetTenant(ctx, td.ID)
		require.NoError(t, err)
		assert.Equal(t, td.BillingLabel, got.BillingLabel)
	})

	t.Run("top-level exists is not retried", func(t *testing.T) {
		m := newBareTestTenantManager(t)
		fs := &topLevelFaultStore{Store: m.store, faults: []error{business.ErrTopLevelTenantExists}}
		m.store = fs
		_, err := m.CreateTenant(ctx, &TenantRequest{ID: "root"})
		require.ErrorIs(t, err, ErrTopLevelTenantExists)
		assert.Equal(t, 1, fs.calls)
	})
}
