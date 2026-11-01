// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// dbStaticTenantResolver is a test interfaces.TenantResolver mapping fixed peer
// identities to their registered tenant, mirroring how the controller-side
// steward registry would answer in production. Mirrors
// sqlite/tenant_binding_test.go:staticTenantResolver.
type dbStaticTenantResolver map[string]string

func (m dbStaticTenantResolver) TenantForDevice(peerIdentity string) (string, bool) {
	t, ok := m[peerIdentity]
	return t, ok
}

func newTestDBProviderWithResolver(t *testing.T, dsn string, resolver interfaces.TenantResolver) *DatabaseEntityGraphProvider {
	t.Helper()
	p, err := NewDatabaseEntityGraphProvider(dsn, WithTenantResolver(resolver))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// TestTenantBinding_ForeignAssertionOverridden_Database is a REQUIRED test
// (Issue #4319) on the PostgreSQL provider: an observation whose payload
// asserts a foreign tenant must be stored under the authenticated peer's
// real, resolver-derived tenant. Mirrors
// sqlite/tenant_binding_test.go:TestTenantBinding_ForeignAssertionOverridden.
func TestTenantBinding_ForeignAssertionOverridden_Database(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	resolver := dbStaticTenantResolver{"steward-real-db": "root/real-tenant-db"}
	p := newTestDBProviderWithResolver(t, dsn, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := dbMustEID(t, "host:steward-real-db/file:etc-hosts")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:            "steward-real-db",
		AuthenticatedPeer: "steward-real-db",
		Observations: []types.Observation{
			dbObs(eid.String(), "steward-real-db", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind":   "host",
				"owning_tenant": "root/evil-tenant-db",
				"hostname":      "victim-host-db",
			}),
		},
	}))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/real-tenant-db"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.Equal(t, "root/real-tenant-db", view.Entity.OwningTenant,
		"the peer's resolved tenant must win, not the payload's claim")

	viewEvil, errEvil := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/evil-tenant-db"})
	if errEvil == nil {
		require.Nil(t, viewEvil, "the fragment's claimed tenant must never become visible")
	}
}

// TestTenantBinding_NoAssertionUsesRealTenant_Database is a REQUIRED test
// (Issue #4319) on the PostgreSQL provider: an observation whose payload
// asserts no tenant at all must still be stored under the peer's real
// tenant. Mirrors
// sqlite/tenant_binding_test.go:TestTenantBinding_NoAssertionUsesRealTenant.
func TestTenantBinding_NoAssertionUsesRealTenant_Database(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	resolver := dbStaticTenantResolver{"steward-quiet-db": "root/quiet-tenant-db"}
	p := newTestDBProviderWithResolver(t, dsn, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := dbMustEID(t, "host:steward-quiet-db/service:sshd")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:            "steward-quiet-db",
		AuthenticatedPeer: "steward-quiet-db",
		Observations: []types.Observation{
			dbObs(eid.String(), "steward-quiet-db", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host",
				"hostname":    "quiet-host-db",
			}),
		},
	}))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/quiet-tenant-db"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.NotEmpty(t, view.Entity.OwningTenant, "owning_tenant must never be empty for a known, resolvable peer")
	require.Equal(t, "root/quiet-tenant-db", view.Entity.OwningTenant,
		"an observation with no tenant assertion must still be bound to the peer's real tenant")
}

// TestTenantBinding_RebuildProjectionsPreservesResolvedTenant_Database
// verifies that RebuildProjections on the PostgreSQL provider reconstructs
// the resolver-derived owning_tenant, not the discarded payload assertion.
// Mirrors
// sqlite/tenant_binding_test.go:TestTenantBinding_RebuildProjectionsPreservesResolvedTenant.
func TestTenantBinding_RebuildProjectionsPreservesResolvedTenant_Database(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	resolver := dbStaticTenantResolver{"steward-rb-db": "root/rebuild-tenant-db"}
	p := newTestDBProviderWithResolver(t, dsn, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := dbMustEID(t, "host:steward-rb-db/file:etc-hosts")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:            "steward-rb-db",
		AuthenticatedPeer: "steward-rb-db",
		Observations: []types.Observation{
			dbObs(eid.String(), "steward-rb-db", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind":   "host",
				"owning_tenant": "root/evil-tenant-db",
				"hostname":      "rb-host-db",
			}),
		},
	}))

	require.NoError(t, p.RebuildProjections(ctx))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/rebuild-tenant-db"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.Equal(t, "root/rebuild-tenant-db", view.Entity.OwningTenant,
		"rebuild must re-derive the resolver-bound tenant, not the discarded claim")
}

// TestTenantBinding_UnauthenticatedBatchUnaffected_Database verifies that a
// batch with no AuthenticatedPeer (internal/trusted writers) keeps today's
// payload-supplied-tenant contract on the PostgreSQL provider. Mirrors
// sqlite/tenant_binding_test.go:TestTenantBinding_UnauthenticatedBatchUnaffected.
func TestTenantBinding_UnauthenticatedBatchUnaffected_Database(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	resolver := dbStaticTenantResolver{"steward-real-db2": "root/real-tenant-db2"}
	p := newTestDBProviderWithResolver(t, dsn, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := dbMustEID(t, "cfgms:tenant/msp-a-db")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "tenantstore",
		Observations: []types.Observation{
			dbObs(eid.String(), "tenantstore", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "tenant",
			}),
		},
	}))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.Empty(t, view.Entity.OwningTenant, "an unauthenticated batch's payload contract is unchanged")
}
