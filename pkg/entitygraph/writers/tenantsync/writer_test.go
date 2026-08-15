// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenantsync_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	sqliteeg "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/tenantsync"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newEGProvider creates an in-process SQLite entity-graph provider for tests.
func newEGProvider(t *testing.T) *sqliteeg.SQLiteEntityGraphProvider {
	t.Helper()
	p, err := sqliteeg.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// mustCreateTenant inserts a tenant, failing the test on error.
func mustCreateTenant(t *testing.T, store business.TenantStore, id, name, parentID string) {
	t.Helper()
	require.NoError(t, store.CreateTenant(context.Background(), &business.TenantData{
		ID:        id,
		Name:      name,
		ParentID:  parentID,
		Status:    business.TenantStatusActive,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))
}

// mustEID parses an EID string, failing the test on error.
func mustEID(t *testing.T, s string) types.EID {
	t.Helper()
	eid, err := types.ParseEID(s)
	require.NoError(t, err)
	return eid
}

// tenantEID returns the mirrored EID for a tenant ID (cfgms:tenant/<id>).
func tenantEID(t *testing.T, tenantID string) types.EID {
	t.Helper()
	return mustEID(t, "cfgms:tenant/"+tenantID)
}

// outboundContainsFilter returns an EdgeFilter for outbound contains edges from eid.
func outboundContainsFilter(eid types.EID) interfaces.EdgeFilter {
	return interfaces.EdgeFilter{
		FromEID: &eid,
		Types:   []string{"contains"},
	}
}

// inboundContainsFilter returns an EdgeFilter for inbound contains edges into eid.
func inboundContainsFilter(eid types.EID) interfaces.EdgeFilter {
	return interfaces.EdgeFilter{
		ToEID: &eid,
		Types: []string{"contains"},
	}
}

// mirroredTenantEIDs returns the set of tenant-kind entity EIDs currently in the graph.
func mirroredTenantEIDs(t *testing.T, eg *sqliteeg.SQLiteEntityGraphProvider) map[string]bool {
	t.Helper()
	page, err := eg.QueryEntities(context.Background(),
		interfaces.EntityFilter{Kind: "tenant"}, interfaces.PageToken{})
	require.NoError(t, err)
	require.NotNil(t, page)
	found := make(map[string]bool, len(page.Entities))
	for _, e := range page.Entities {
		found[e.Entity.EID.String()] = true
	}
	return found
}

// TestNewWriterNilProvider verifies that New rejects a nil provider.
func TestNewWriterNilProvider(t *testing.T) {
	_, err := tenantsync.New(nil)
	require.Error(t, err)
}

// TestAC1_EntityObservationPerTenant verifies that Ingest writes one entity
// observation per TenantStore row, and that GetEntity returns non-nil for each.
func TestAC1_EntityObservationPerTenant(t *testing.T) {
	eg := newEGProvider(t)
	store := newTenantStore(t)
	ctx := context.Background()

	mustCreateTenant(t, store, "root", "Root", "")
	mustCreateTenant(t, store, "child", "Child", "root")
	mustCreateTenant(t, store, "grandchild", "Grandchild", "child")

	w, err := tenantsync.New(eg)
	require.NoError(t, err)
	require.NoError(t, w.Ingest(ctx, store))

	for _, id := range []string{"root", "child", "grandchild"} {
		eid := tenantEID(t, id)
		view, err := eg.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
		require.NoError(t, err, "tenant %q must have a mirrored entity", id)
		require.NotNil(t, view)
		require.Equal(t, "tenant", view.Entity.Kind,
			"entity_kind must be tenant for %q", id)
	}
}

// TestAC2_ContainsEdgePerNonRootTenant verifies that each non-root tenant
// produces a contains edge from its parent.
func TestAC2_ContainsEdgePerNonRootTenant(t *testing.T) {
	eg := newEGProvider(t)
	store := newTenantStore(t)
	ctx := context.Background()

	mustCreateTenant(t, store, "root", "Root", "")
	mustCreateTenant(t, store, "child", "Child", "root")
	mustCreateTenant(t, store, "grandchild", "Grandchild", "child")

	w, err := tenantsync.New(eg)
	require.NoError(t, err)
	require.NoError(t, w.Ingest(ctx, store))

	rootEID := tenantEID(t, "root")
	childEID := tenantEID(t, "child")
	grandchildEID := tenantEID(t, "grandchild")

	// root → child edge
	rootToChild, err := eg.GetEdges(ctx, outboundContainsFilter(rootEID))
	require.NoError(t, err)
	require.Len(t, rootToChild, 1, "root must have exactly one outbound contains edge")
	require.Equal(t, "contains", rootToChild[0].Edge.Type)
	require.Equal(t, childEID.String(), rootToChild[0].Edge.To.String())

	// child → grandchild edge
	childToGrandchild, err := eg.GetEdges(ctx, outboundContainsFilter(childEID))
	require.NoError(t, err)
	require.Len(t, childToGrandchild, 1, "child must have exactly one outbound contains edge")
	require.Equal(t, "contains", childToGrandchild[0].Edge.Type)
	require.Equal(t, grandchildEID.String(), childToGrandchild[0].Edge.To.String())
}

// TestAC3_MultiLevelTraversal verifies that a three-level tenant hierarchy
// round-trips into GetNeighborhood correctly (parent→child→grandchild traversal).
// This is a REQUIRED test per the story acceptance criteria.
func TestAC3_MultiLevelTraversal(t *testing.T) {
	eg := newEGProvider(t)
	store := newTenantStore(t)
	ctx := context.Background()

	mustCreateTenant(t, store, "root", "Root", "")
	mustCreateTenant(t, store, "child", "Child", "root")
	mustCreateTenant(t, store, "grandchild", "Grandchild", "child")

	w, err := tenantsync.New(eg)
	require.NoError(t, err)
	require.NoError(t, w.Ingest(ctx, store))

	rootEID := tenantEID(t, "root")
	childEID := tenantEID(t, "child")
	grandchildEID := tenantEID(t, "grandchild")

	// Traverse from root with depth 3 to reach grandchild.
	hood, err := eg.GetNeighborhood(ctx, rootEID, []string{"contains"}, types.TraversalOutbound, 3)
	require.NoError(t, err)
	require.NotNil(t, hood)

	// Collect all node EIDs reachable from root.
	reachable := make(map[string]bool)
	for _, n := range hood.Nodes {
		reachable[n.EID.String()] = true
	}
	require.True(t, reachable[rootEID.String()], "root must be in neighborhood")
	require.True(t, reachable[childEID.String()], "child must be reachable from root")
	require.True(t, reachable[grandchildEID.String()], "grandchild must be reachable from root")

	// Both edges must be present.
	edgePairs := make(map[string]bool)
	edgeTypes := make(map[string]bool)
	for _, e := range hood.Edges {
		edgeTypes[e.Type] = true
		edgePairs[e.From.String()+"->"+e.To.String()] = true
	}
	require.True(t, edgePairs[rootEID.String()+"->"+childEID.String()],
		"root→child edge must be in neighborhood")
	require.True(t, edgePairs[childEID.String()+"->"+grandchildEID.String()],
		"child→grandchild edge must be in neighborhood")
	require.True(t, edgeTypes["contains"], "edge type must be contains")
}

// TestAC4_RetractAfterTenantRemoved verifies that a re-sync after a tenant is
// removed from TenantStore retracts both its mirrored entity and its incoming
// contains edge (claim-scope retraction case).
// This is a REQUIRED test per the story acceptance criteria.
func TestAC4_RetractAfterTenantRemoved(t *testing.T) {
	eg := newEGProvider(t)
	store := newTenantStore(t)
	ctx := context.Background()

	mustCreateTenant(t, store, "root", "Root", "")
	mustCreateTenant(t, store, "child", "Child", "root")
	mustCreateTenant(t, store, "grandchild", "Grandchild", "child")

	w, err := tenantsync.New(eg)
	require.NoError(t, err)

	// First sync: all three tenants are in the graph.
	require.NoError(t, w.Ingest(ctx, store))

	grandchildEID := tenantEID(t, "grandchild")
	childEID := tenantEID(t, "child")

	// Verify initial state: grandchild entity and edge exist.
	view, err := eg.GetEntity(ctx, grandchildEID, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, view, "grandchild entity must exist before removal")

	edges, err := eg.GetEdges(ctx, outboundContainsFilter(childEID))
	require.NoError(t, err)
	require.Len(t, edges, 1, "child→grandchild edge must exist before removal")

	// Remove grandchild from TenantStore.
	require.NoError(t, store.DeleteTenant(ctx, "grandchild"))

	// Second sync: grandchild is gone from the store, so it should be retracted.
	require.NoError(t, w.Ingest(ctx, store))

	// Entity must be retracted: GetEntity returns not-found.
	view, err = eg.GetEntity(ctx, grandchildEID, interfaces.GetEntityOpts{})
	require.Error(t, err, "grandchild entity must be retracted after removal")
	require.Nil(t, view)

	// Contains edge from child to grandchild must also be retracted.
	edges, err = eg.GetEdges(ctx, outboundContainsFilter(childEID))
	require.NoError(t, err)
	require.Empty(t, edges, "child→grandchild contains edge must be retracted after removal")
}

// TestAC5_HierarchicalTenantIDs verifies that path-based tenant IDs — the CFGMS
// tenant naming convention (root/msp-a/client-1) — are mirrored like any other
// tenant. Path IDs are unrepresentable as an EID authority name, so they are
// carried in the EID local_id instead.
func TestAC5_HierarchicalTenantIDs(t *testing.T) {
	eg := newEGProvider(t)
	store := newTenantStore(t)
	ctx := context.Background()

	mustCreateTenant(t, store, "root", "Root", "")
	mustCreateTenant(t, store, "root/msp-a", "MSP A", "root")
	mustCreateTenant(t, store, "root/msp-a/client-1", "Client 1", "root/msp-a")

	w, err := tenantsync.New(eg)
	require.NoError(t, err)
	require.NoError(t, w.Ingest(ctx, store),
		"a hierarchical tenant ID must not abort the snapshot")

	rootEID := tenantEID(t, "root")
	mspEID := tenantEID(t, "root/msp-a")
	clientEID := tenantEID(t, "root/msp-a/client-1")

	for _, eid := range []types.EID{rootEID, mspEID, clientEID} {
		view, err := eg.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
		require.NoError(t, err, "tenant %q must have a mirrored entity", eid.String())
		require.NotNil(t, view)
		require.Equal(t, "tenant", view.Entity.Kind)
	}

	// Contains edges follow the hierarchy.
	rootEdges, err := eg.GetEdges(ctx, outboundContainsFilter(rootEID))
	require.NoError(t, err)
	require.Len(t, rootEdges, 1)
	require.Equal(t, mspEID.String(), rootEdges[0].Edge.To.String())

	mspEdges, err := eg.GetEdges(ctx, outboundContainsFilter(mspEID))
	require.NoError(t, err)
	require.Len(t, mspEdges, 1)
	require.Equal(t, clientEID.String(), mspEdges[0].Edge.To.String())

	// The full path is traversable.
	hood, err := eg.GetNeighborhood(ctx, rootEID, []string{"contains"}, types.TraversalOutbound, 3)
	require.NoError(t, err)
	reachable := make(map[string]bool)
	for _, n := range hood.Nodes {
		reachable[n.EID.String()] = true
	}
	require.True(t, reachable[clientEID.String()],
		"root/msp-a/client-1 must be reachable from root")
}

// TestIngestEmptyStore verifies that Ingest with an empty TenantStore succeeds
// and produces no entities.
func TestIngestEmptyStore(t *testing.T) {
	eg := newEGProvider(t)
	store := newTenantStore(t)
	ctx := context.Background()

	w, err := tenantsync.New(eg)
	require.NoError(t, err)
	require.NoError(t, w.Ingest(ctx, store))

	require.Empty(t, mirroredTenantEIDs(t, eg),
		"ingesting an empty TenantStore must leave the graph empty")
}

// TestIngestIdempotent verifies that calling Ingest twice with the same tenant
// set produces the same graph state — no duplicate edges or extra entity rows.
func TestIngestIdempotent(t *testing.T) {
	eg := newEGProvider(t)
	store := newTenantStore(t)
	ctx := context.Background()

	mustCreateTenant(t, store, "root", "Root", "")
	mustCreateTenant(t, store, "child", "Child", "root")

	w, err := tenantsync.New(eg)
	require.NoError(t, err)

	require.NoError(t, w.Ingest(ctx, store))
	require.NoError(t, w.Ingest(ctx, store)) // second call must be idempotent

	rootEID := tenantEID(t, "root")
	childEID := tenantEID(t, "child")

	// Only one contains edge from root to child.
	edges, err := eg.GetEdges(ctx, outboundContainsFilter(rootEID))
	require.NoError(t, err)
	hasRootChild := false
	for _, e := range edges {
		if e.Edge.To.String() == childEID.String() {
			hasRootChild = true
		}
	}
	require.True(t, hasRootChild, "root→child edge must exist after idempotent sync")
	require.Len(t, edges, 1,
		"idempotent sync must not produce duplicate edge rows")
}

// TestIngestListTenantsError verifies that a TenantStore read failure aborts the
// sync with an error and writes nothing — in particular, it must not retract the
// tenants mirrored by the previous successful sync.
func TestIngestListTenantsError(t *testing.T) {
	eg := newEGProvider(t)
	store := newTenantStore(t)
	ctx := context.Background()

	mustCreateTenant(t, store, "root", "Root", "")
	mustCreateTenant(t, store, "child", "Child", "root")

	w, err := tenantsync.New(eg)
	require.NoError(t, err)
	require.NoError(t, w.Ingest(ctx, store))

	before := mirroredTenantEIDs(t, eg)
	require.Len(t, before, 2, "both tenants must be mirrored by the first sync")

	// A cancelled context makes the store's ListTenants query fail for real.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err = w.Ingest(cancelledCtx, store)
	require.Error(t, err, "a ListTenants failure must propagate")

	// Nothing was written and nothing was retracted.
	require.Equal(t, before, mirroredTenantEIDs(t, eg),
		"a failed sync must leave the previous snapshot untouched")
	edges, err := eg.GetEdges(ctx, outboundContainsFilter(tenantEID(t, "root")))
	require.NoError(t, err)
	require.Len(t, edges, 1, "a failed sync must not retract existing edges")
}

// TestIngestQuarantinesUnrepresentableTenantID verifies that a tenant row that
// cannot be represented in the mirror is skipped with a warning instead of
// aborting the fleet-wide snapshot.
func TestIngestQuarantinesUnrepresentableTenantID(t *testing.T) {
	t.Run("delimiter in tenant id", func(t *testing.T) {
		eg := newEGProvider(t)
		store := newTenantStore(t)
		ctx := context.Background()

		mustCreateTenant(t, store, "root", "Root", "")
		mustCreateTenant(t, store, "bad|id", "Bad", "root")
		mustCreateTenant(t, store, "good", "Good", "root")

		capture := logging.NewCapturingLogger()
		w, err := tenantsync.New(eg)
		require.NoError(t, err)
		w = w.WithLogger(capture)

		require.NoError(t, w.Ingest(ctx, store),
			"one unrepresentable tenant must not abort the snapshot")

		mirrored := mirroredTenantEIDs(t, eg)
		require.True(t, mirrored[tenantEID(t, "root").String()], "root must still be mirrored")
		require.True(t, mirrored[tenantEID(t, "good").String()], "good must still be mirrored")
		require.False(t, mirrored["cfgms:tenant/bad|id"],
			"the unrepresentable tenant must be quarantined, not mirrored")

		edges, err := eg.GetEdges(ctx, outboundContainsFilter(tenantEID(t, "root")))
		require.NoError(t, err)
		require.Len(t, edges, 1, "only the representable child edge must be written")
		require.Equal(t, tenantEID(t, "good").String(), edges[0].Edge.To.String())

		entry, ok := capture.FindWarn("tenantsync: skipping tenant with unrepresentable id")
		require.True(t, ok, "the quarantined row must be logged")
		require.Equal(t, "bad|id", entry["tenant_id"])
	})

	t.Run("delimiter in parent id", func(t *testing.T) {
		eg := newEGProvider(t)
		store := newTenantStore(t)
		ctx := context.Background()

		mustCreateTenant(t, store, "root", "Root", "")
		mustCreateTenant(t, store, "orphan", "Orphan", "weird|parent")

		capture := logging.NewCapturingLogger()
		w, err := tenantsync.New(eg)
		require.NoError(t, err)
		w = w.WithLogger(capture)

		require.NoError(t, w.Ingest(ctx, store),
			"an unrepresentable ParentID must not abort the snapshot")

		// The tenant itself is still mirrored; only its parent edge is dropped.
		orphanEID := tenantEID(t, "orphan")
		view, err := eg.GetEntity(ctx, orphanEID, interfaces.GetEntityOpts{})
		require.NoError(t, err)
		require.NotNil(t, view)

		edges, err := eg.GetEdges(ctx, inboundContainsFilter(orphanEID))
		require.NoError(t, err)
		require.Empty(t, edges, "no contains edge may be written for an unrepresentable parent")

		entry, ok := capture.FindWarn("tenantsync: skipping contains edge with unrepresentable parent id")
		require.True(t, ok, "the dropped edge must be logged")
		require.Equal(t, "orphan", entry["tenant_id"])
		require.Equal(t, "weird|parent", entry["parent_id"])
	})
}
