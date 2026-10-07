// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// staticTenantResolver is a test interfaces.TenantResolver mapping fixed peer
// identities to their registered tenant, mirroring how the controller-side
// steward registry would answer in production.
type staticTenantResolver map[string]string

func (m staticTenantResolver) TenantForDevice(peerIdentity string) (string, bool) {
	t, ok := m[peerIdentity]
	return t, ok
}

func newTestProviderWithResolver(t *testing.T, resolver interfaces.TenantResolver) *SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := NewSQLiteEntityGraphProvider(path, WithTenantResolver(resolver))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// TestTenantBinding_ForeignAssertionOverridden is a REQUIRED test (Issue
// #4319): an observation whose payload asserts a foreign tenant must be
// stored under the authenticated peer's real, resolver-derived tenant — the
// assertion is overridden, not merely ignored.
func TestTenantBinding_ForeignAssertionOverridden(t *testing.T) {
	resolver := staticTenantResolver{"steward-real": "root/real-tenant"}
	p := newTestProviderWithResolver(t, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:steward-real/file:etc-hosts")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:            "steward-real",
		AuthenticatedPeer: "steward-real",
		Observations: []types.Observation{
			obs(eid.String(), "steward-real", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind":   "host",
				"owning_tenant": "root/evil-tenant",
				"hostname":      "victim-host",
			}),
		},
	}))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/real-tenant"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.Equal(t, "root/real-tenant", view.Entity.OwningTenant,
		"the peer's resolved tenant must win, not the payload's claim")

	// The claimed tenant must never be honored: a read scoped to it must not
	// see this entity at all.
	viewEvil, errEvil := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/evil-tenant"})
	if errEvil == nil {
		require.Nil(t, viewEvil, "the fragment's claimed tenant must never become visible")
	}
}

// TestTenantBinding_NoAssertionUsesRealTenant is a REQUIRED test (Issue
// #4319): an observation whose payload asserts no tenant at all must still be
// stored under the peer's real tenant, never an empty (cross-tenant-visible)
// one.
func TestTenantBinding_NoAssertionUsesRealTenant(t *testing.T) {
	resolver := staticTenantResolver{"steward-quiet": "root/quiet-tenant"}
	p := newTestProviderWithResolver(t, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:steward-quiet/service:sshd")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:            "steward-quiet",
		AuthenticatedPeer: "steward-quiet",
		Observations: []types.Observation{
			obs(eid.String(), "steward-quiet", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "host",
				"hostname":    "quiet-host",
				// no tenant_path / owning_tenant key at all
			}),
		},
	}))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/quiet-tenant"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.NotEmpty(t, view.Entity.OwningTenant, "owning_tenant must never be empty for a known, resolvable peer")
	require.Equal(t, "root/quiet-tenant", view.Entity.OwningTenant,
		"an observation with no tenant assertion must still be bound to the peer's real tenant")
}

// TestTenantBinding_UnresolvedPeerYieldsEmptyNotInvented verifies the
// fail-closed default: a peer the resolver does not know gets an empty
// owning_tenant rather than a fabricated one.
func TestTenantBinding_UnresolvedPeerYieldsEmptyNotInvented(t *testing.T) {
	resolver := staticTenantResolver{} // knows nobody
	p := newTestProviderWithResolver(t, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:steward-unknown/service:sshd")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:            "steward-unknown",
		AuthenticatedPeer: "steward-unknown",
		Observations: []types.Observation{
			obs(eid.String(), "steward-unknown", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind":   "host",
				"owning_tenant": "root/claimed-tenant",
				"hostname":      "unknown-host",
			}),
		},
	}))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/claimed-tenant"})
	if err == nil {
		require.Nil(t, view, "an unresolvable peer must never be granted the tenant it claims")
	}

	// Read without a tenant filter to confirm the row exists with an empty
	// owning_tenant, rather than the claimed one.
	unfiltered, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, unfiltered)
	require.Empty(t, unfiltered.Entity.OwningTenant,
		"an unresolvable peer's claimed tenant must never be honored, even as a fallback")
}

// TestTenantBinding_RebuildProjectionsPreservesResolvedTenant verifies that
// RebuildProjections (replaying from the observation log) reconstructs the
// same resolver-derived owning_tenant, not the discarded payload assertion —
// the projection rebuild path is covered, not just the live ingest path.
func TestTenantBinding_RebuildProjectionsPreservesResolvedTenant(t *testing.T) {
	resolver := staticTenantResolver{"steward-rb": "root/rebuild-tenant"}
	p := newTestProviderWithResolver(t, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "host:steward-rb/file:etc-hosts")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:            "steward-rb",
		AuthenticatedPeer: "steward-rb",
		Observations: []types.Observation{
			obs(eid.String(), "steward-rb", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind":   "host",
				"owning_tenant": "root/evil-tenant",
				"hostname":      "rb-host",
			}),
		},
	}))

	require.NoError(t, p.RebuildProjections(ctx))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/rebuild-tenant"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.Equal(t, "root/rebuild-tenant", view.Entity.OwningTenant,
		"rebuild must re-derive the resolver-bound tenant, not the discarded claim")
}

// TestTenantBinding_UnauthenticatedBatchUnaffected verifies that a batch with
// no AuthenticatedPeer (internal/trusted writers) keeps today's
// payload-supplied-tenant contract — this story does not change their
// behavior.
func TestTenantBinding_UnauthenticatedBatchUnaffected(t *testing.T) {
	resolver := staticTenantResolver{"steward-real": "root/real-tenant"}
	p := newTestProviderWithResolver(t, resolver)
	ctx := context.Background()
	now := time.Now().UTC()
	eid := mustEID(t, "cfgms:tenant/msp-a")

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "tenantstore",
		Observations: []types.Observation{
			obs(eid.String(), "tenantstore", types.ObservationKindState, now, map[string]interface{}{
				"entity_kind": "tenant",
			}),
		},
	}))

	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.Empty(t, view.Entity.OwningTenant, "an unauthenticated batch's payload contract is unchanged")
}
