// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package interfaces_test contains contract tests for the EntityGraphProvider.
//
// RunEntityGraphContractTests is the shared harness; each round story adds
// subtests here. Parallel stories may produce rebase conflicts on this file —
// resolve by merging both diffs, never by re-serializing the rounds.
//
// Usage:
//
//	func TestMyProvider_ContractSuite(t *testing.T) {
//		interfaces.RunEntityGraphContractTests(t, func(t *testing.T) interfaces.EntityGraphProvider {
//			return myProvider
//		})
//	}
package interfaces_test

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EntityGraphProviderFactory creates an EntityGraphProvider under test.
type EntityGraphProviderFactory func(t *testing.T) interfaces.EntityGraphProvider

// RunEntityGraphContractTests runs the full EntityGraphProvider contract test suite.
// Each contract is a subtest for granular reporting. Grown incrementally as each
// round story lands.
func RunEntityGraphContractTests(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()

	t.Run("ProviderIdentity", func(t *testing.T) {
		testEGProviderIdentity(t, factory)
	})
	t.Run("ProviderAvailable", func(t *testing.T) {
		testEGProviderAvailable(t, factory)
	})
	t.Run("RoundTrip", func(t *testing.T) { testEGRoundTrip(t, factory) })                    // AC 1
	t.Run("ContentHashDedup", func(t *testing.T) { testEGContentHashDedup(t, factory) })      // AC 2
	t.Run("PrecedenceResolution", func(t *testing.T) { testEGPrecedence(t, factory) })        // AC 3
	t.Run("QueryEntities", func(t *testing.T) { testEGQueryEntities(t, factory) })            // AC 4
	t.Run("CrossTenantNotFound", func(t *testing.T) { testEGCrossTenant(t, factory) })        // AC 5
	t.Run("MovedEntityVisibility", func(t *testing.T) { testEGMovedEntity(t, factory) })      // AC 6
	t.Run("ProjectionRebuild", func(t *testing.T) { testEGRebuild(t, factory) })              // AC 7
	t.Run("ResolveIdentity", func(t *testing.T) { testEGResolveIdentity(t, factory) })        // AC 8
	t.Run("EmptyProjectionTables", func(t *testing.T) { testEGEmptyProjections(t, factory) }) // AC 9
	t.Run("GetEntityOptsNoOp", func(t *testing.T) { testEGOptsNoOp(t, factory) })             // opts pass-through
	// Story-3: edges, placeholder nodes, depth-bounded neighborhood (Issue #2873)
	t.Run("EdgeRoundTrip", func(t *testing.T) { testEGEdgeRoundTrip(t, factory) })                       // AC 1
	t.Run("PlaceholderNode", func(t *testing.T) { testEGPlaceholderNode(t, factory) })                   // AC 2
	t.Run("NeighborhoodDepthCap", func(t *testing.T) { testEGNeighborhoodDepthCap(t, factory) })         // AC 3
	t.Run("NeighborhoodTenantPerHop", func(t *testing.T) { testEGNeighborhoodTenantPerHop(t, factory) }) // AC 4
	t.Run("GetEdgesTenantFilter", func(t *testing.T) { testEGGetEdgesTenantFilter(t, factory) })         // AC 5
	// Story-4: claim-scoped ingest + source-closure retraction (Issue #2874)
	t.Run("ClaimScopeEntityReplace", func(t *testing.T) { testEGClaimScopeEntityReplace(t, factory) })     // AC 1
	t.Run("ClaimScopeEdgeReplace", func(t *testing.T) { testEGClaimScopeEdgeReplace(t, factory) })         // AC 2
	t.Run("ClaimScopeOverlapRejected", func(t *testing.T) { testEGClaimScopeOverlapRejected(t, factory) }) // AC 3
	t.Run("SourceClosure", func(t *testing.T) { testEGSourceClosure(t, factory) })                         // AC 4
	// Story-5: drift, desired-state, drift-lifecycle (Issue #2875)
	t.Run("DriftNotFoundBehavior", func(t *testing.T) { testEGDriftNotFound(t, factory) })                 // AC 1
	t.Run("DriftStateRoundTrip", func(t *testing.T) { testEGDriftStateRoundTrip(t, factory) })             // AC 2+3
	t.Run("DriftLifecycleTransition", func(t *testing.T) { testEGDriftLifecycle(t, factory) })             // AC 4
	t.Run("DriftProjectionRebuildRecovery", func(t *testing.T) { testEGDriftRebuildRecovery(t, factory) }) // AC 4 + AC 7
	t.Run("DesiredStateIsolation", func(t *testing.T) { testEGDesiredStateIsolation(t, factory) })         // AC 5 (isolation)
}

// --- Contract test helpers ---

// egEID parses a canonical EID string, failing the test on error.
func egEID(t *testing.T, s string) interfaces.EIDRef {
	t.Helper()
	eid, err := types.ParseEID(s)
	require.NoError(t, err, "parse eid %q", s)
	return eid
}

// egObservation builds a single state observation with a fixed timestamp so that
// repeated calls with the same arguments are bit-identical (content-hash dedup).
func egObservation(subject, source string, observedAt time.Time, payload map[string]interface{}) types.Observation {
	return types.Observation{
		Source:     source,
		ObservedAt: observedAt,
		RecordedAt: observedAt,
		Subject:    subject,
		Kind:       types.ObservationKindState,
		Confidence: types.ConfidenceHigh,
		Payload:    payload,
	}
}

// egReport ingests a single-observation batch from source, failing on error.
func egReport(ctx context.Context, t *testing.T, p interfaces.EntityGraphProvider, source, subject string, payload map[string]interface{}) {
	t.Helper()
	batch := interfaces.ObservationBatch{
		Source:       source,
		Observations: []types.Observation{egObservation(subject, source, time.Now().UTC(), payload)},
	}
	require.NoError(t, p.ReportObservations(ctx, batch), "report observation for %q", subject)
}

// testEGRoundTrip verifies a reported observation is retrievable via GetEntity
// and QueryEntities under the owning tenant (AC 1).
func testEGRoundTrip(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const subject = "host:test-host/server1"
	egReport(ctx, t, p, "observer:test", subject, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "server1",
		"owning_tenant": "root/test-tenant",
	})

	view, err := p.GetEntity(ctx, egEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/test-tenant"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.NotNil(t, view.Entity)
	assert.Equal(t, "server1", view.Entity.Attributes["hostname"])

	page, err := p.QueryEntities(ctx, interfaces.EntityFilter{Kind: "host", TenantFilter: "root/test-tenant"}, interfaces.PageToken{})
	require.NoError(t, err)
	require.NotNil(t, page)
	assert.GreaterOrEqual(t, len(page.Entities), 1)
}

// testEGContentHashDedup verifies that reporting a bit-identical observation
// twice is idempotent: no error, and the entity view stays consistent (AC 2).
// The provider-level test asserts the underlying log-row count.
func testEGContentHashDedup(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const subject = "host:dedup-auth/dedup1"
	payload := map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "dedup-host",
		"owning_tenant": "root/dedup-tenant",
	}
	// Build one observation and report it twice — bit-identical (same timestamp).
	obs := egObservation(subject, "observer:test", time.Now().UTC(), payload)
	batch := interfaces.ObservationBatch{Source: "observer:test", Observations: []types.Observation{obs}}

	require.NoError(t, p.ReportObservations(ctx, batch))
	view1, err := p.GetEntity(ctx, egEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/dedup-tenant"})
	require.NoError(t, err)
	require.NotNil(t, view1)
	require.NotNil(t, view1.Entity)

	// Second identical report must not error and must not change the view.
	require.NoError(t, p.ReportObservations(ctx, batch))
	view2, err := p.GetEntity(ctx, egEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/dedup-tenant"})
	require.NoError(t, err)
	require.NotNil(t, view2)
	require.NotNil(t, view2.Entity)
	assert.Equal(t, view1.Entity.Attributes["hostname"], view2.Entity.Attributes["hostname"])
}

// testEGPrecedence verifies that the higher-precedence source class wins when
// two sources assert conflicting values for the same subject (AC 3).
func testEGPrecedence(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const subject = "host:precedence-auth/host1"

	// Report the lower-precedence source (correlator inference) first.
	egReport(ctx, t, p, "correlator-inference:ml", subject, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "wrong-name",
		"owning_tenant": "root/t1",
	})
	// Then the higher-precedence source (enforcing module).
	egReport(ctx, t, p, "enforcing-module:hyperv", subject, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "correct-name",
		"owning_tenant": "root/t1",
	})

	view, err := p.GetEntity(ctx, egEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/t1"})
	require.NoError(t, err)
	require.NotNil(t, view)
	require.NotNil(t, view.Entity)
	assert.Equal(t, "correct-name", view.Entity.Attributes["hostname"], "enforcing-module must win over correlator-inference")
}

// testEGQueryEntities verifies kind and tenant filtering in QueryEntities (AC 4).
func testEGQueryEntities(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const hostSubject = "host:provider-qe/host1"
	const userSubject = "m365:provider-qe/user1"

	egReport(ctx, t, p, "observer:test", hostSubject, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "test-host",
		"owning_tenant": "root/msp-a",
	})
	egReport(ctx, t, p, "observer:test", userSubject, map[string]interface{}{
		"entity_kind":   "user",
		"hostname":      "",
		"owning_tenant": "root/msp-b",
	})

	hostPage, err := p.QueryEntities(ctx, interfaces.EntityFilter{Kind: "host", TenantFilter: "root/msp-a"}, interfaces.PageToken{})
	require.NoError(t, err)
	require.NotNil(t, hostPage)
	require.Len(t, hostPage.Entities, 1)
	require.NotNil(t, hostPage.Entities[0].Entity)
	assert.Equal(t, "host", hostPage.Entities[0].Entity.Kind)

	userPage, err := p.QueryEntities(ctx, interfaces.EntityFilter{TenantFilter: "root/msp-b"}, interfaces.PageToken{})
	require.NoError(t, err)
	require.NotNil(t, userPage)
	require.Len(t, userPage.Entities, 1)
	require.NotNil(t, userPage.Entities[0].Entity)
	assert.Equal(t, "user", userPage.Entities[0].Entity.Kind)

	emptyPage, err := p.QueryEntities(ctx, interfaces.EntityFilter{TenantFilter: "root/msp-c"}, interfaces.PageToken{})
	require.NoError(t, err)
	require.NotNil(t, emptyPage)
	assert.Empty(t, emptyPage.Entities)
}

// testEGCrossTenant verifies that a read scoped to a non-owning tenant returns
// not-found (nil entity or ErrNotFound), never another tenant's data (AC 5).
func testEGCrossTenant(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const subject = "host:xtenant-auth/host1"
	egReport(ctx, t, p, "observer:test", subject, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "tenant-a-secret",
		"owning_tenant": "root/tenant-a",
	})

	view, err := p.GetEntity(ctx, egEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/tenant-b"})
	// The AC accepts either an error or a nil entity — but never tenant-a's data.
	if err == nil {
		assert.Nil(t, view, "cross-tenant read must not return the owning tenant's entity")
	}
}

// testEGMovedEntity verifies current-ownership semantics in both directions when
// an entity's owning_tenant changes (AC 6).
func testEGMovedEntity(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const subject = "host:moved-auth/host1"

	// Initial ownership: tenant-a.
	egReport(ctx, t, p, "enforcing-module:mover", subject, map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/tenant-a",
		"hostname":      "moved-host",
	})
	// Same subject, same source, moved to tenant-b.
	egReport(ctx, t, p, "enforcing-module:mover", subject, map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/tenant-b",
		"hostname":      "moved-host",
	})

	// Now visible under the new owning tenant.
	viewB, err := p.GetEntity(ctx, egEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/tenant-b"})
	require.NoError(t, err)
	require.NotNil(t, viewB)
	require.NotNil(t, viewB.Entity)
	assert.Equal(t, "moved-host", viewB.Entity.Attributes["hostname"])

	// No longer visible under the old owning tenant.
	viewA, errA := p.GetEntity(ctx, egEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/tenant-a"})
	if errA == nil {
		assert.Nil(t, viewA, "moved entity must not remain visible to its former owning tenant")
	}
}

// corruptibleProvider is satisfied by providers that expose a test-only
// corruption hook. The interface is used by testEGRebuild to verify the
// corruption-recovery path of RebuildProjections (AC 7, tested directly).
type corruptibleProvider interface {
	CorruptProjectionsForTesting(ctx context.Context) error
}

// testEGRebuild verifies that RebuildProjections reconstructs projections from
// the observation log (AC 7). When the provider implements corruptibleProvider,
// the test verifies the full corruption-recovery path: delete both projection
// tables and confirm that reads recover after rebuild. When the provider does
// not expose a corruption hook, the test verifies idempotency instead.
func testEGRebuild(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const subject1 = "host:rebuild-auth/host1"
	const subject2 = "host:rebuild-auth/host2"
	egReport(ctx, t, p, "observer:test", subject1, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "rebuild-1",
		"owning_tenant": "root/rb-tenant",
	})
	egReport(ctx, t, p, "observer:test", subject2, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "rebuild-2",
		"owning_tenant": "root/rb-tenant",
	})

	opts := interfaces.GetEntityOpts{TenantFilter: "root/rb-tenant"}

	if c, ok := p.(corruptibleProvider); ok {
		// Corruption-recovery path: delete both projection tables, confirm reads
		// fail, rebuild, confirm reads recover with the correct values.
		require.NoError(t, c.CorruptProjectionsForTesting(ctx))

		_, err := p.GetEntity(ctx, egEID(t, subject1), opts)
		require.Error(t, err, "entity must be unreachable after projection corruption")

		require.NoError(t, p.RebuildProjections(ctx))

		after1, err := p.GetEntity(ctx, egEID(t, subject1), opts)
		require.NoError(t, err, "entity must be readable after rebuild")
		require.NotNil(t, after1)
		after2, err := p.GetEntity(ctx, egEID(t, subject2), opts)
		require.NoError(t, err, "entity must be readable after rebuild")
		require.NotNil(t, after2)
		assert.Equal(t, "rebuild-1", after1.Entity.Attributes["hostname"])
		assert.Equal(t, "rebuild-2", after2.Entity.Attributes["hostname"])
	} else {
		// Idempotency path: rebuild leaves entity reads unchanged.
		before1, err := p.GetEntity(ctx, egEID(t, subject1), opts)
		require.NoError(t, err)
		require.NotNil(t, before1)
		before2, err := p.GetEntity(ctx, egEID(t, subject2), opts)
		require.NoError(t, err)
		require.NotNil(t, before2)

		require.NoError(t, p.RebuildProjections(ctx))

		after1, err := p.GetEntity(ctx, egEID(t, subject1), opts)
		require.NoError(t, err)
		require.NotNil(t, after1)
		after2, err := p.GetEntity(ctx, egEID(t, subject2), opts)
		require.NoError(t, err)
		require.NotNil(t, after2)

		assert.Equal(t, before1.Entity.Attributes["hostname"], after1.Entity.Attributes["hostname"])
		assert.Equal(t, before2.Entity.Attributes["hostname"], after2.Entity.Attributes["hostname"])
	}
}

// testEGDriftRebuildRecovery verifies that RebuildProjections reconstructs the
// eg_drift_projection table from the observation log, not just the entity/index
// projections. Drift-diff and lifecycle rows follow an independent replay path in
// RebuildProjections (loading payloads and dispatching to the drift/lifecycle
// helpers), so this test seeds a drift-diff observation plus a lifecycle
// transition, corrupts the drift projection, rebuilds, and confirms GetDriftState
// recovers the config revision, drift fields, and lifecycle status. Without a
// corruption hook the drift projection cannot be cleared, so the test instead
// asserts rebuild is a no-op for drift state (idempotency).
func testEGDriftRebuildRecovery(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	eid := egEID(t, "host:drift-rebuild-auth/ent1")
	now := time.Now().UTC().Truncate(time.Second)

	// Seed a drift-diff observation so eg_drift_projection has a record.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:drift-reporter",
		Observations: []types.Observation{
			{
				Source:     "enforcing-module:drift-reporter",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    eid.String(),
				Kind:       types.ObservationKindDriftDiff,
				Confidence: types.ConfidenceHigh,
				Payload: map[string]interface{}{
					"config_revision": "rev-rebuild",
					"fields": []interface{}{
						map[string]interface{}{"attribute": "state", "desired": "running", "actual": "stopped", "matching": false},
					},
				},
			},
		},
	}))

	// Drive a lifecycle transition so the independent lifecycle-replay branch of
	// RebuildProjections is also exercised.
	require.NoError(t, p.UpdateDriftLifecycle(ctx, interfaces.DriftLifecycleUpdate{
		EID:        eid,
		Transition: "acknowledge",
		Actor:      "ops-bot",
		At:         now.Add(time.Minute),
		Note:       "tracked in ticket #99",
	}))

	// Baseline: drift state reflects both the diff and the lifecycle transition.
	before, err := p.GetDriftState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, before)
	require.Equal(t, "rev-rebuild", before.ConfigRevision)
	require.Equal(t, "acknowledged", before.LifecycleStatus)
	require.Len(t, before.Fields, 1)

	c, ok := p.(corruptibleProvider)
	if ok {
		// Corruption-recovery path: wipe the drift projection and confirm the
		// state is unreachable, then rebuild from the log and confirm recovery.
		require.NoError(t, c.CorruptProjectionsForTesting(ctx))
		_, err = p.GetDriftState(ctx, eid)
		require.Error(t, err, "drift state must be unreachable after projection corruption")
	}

	require.NoError(t, p.RebuildProjections(ctx))

	after, err := p.GetDriftState(ctx, eid)
	require.NoError(t, err, "drift state must be readable after rebuild")
	require.NotNil(t, after)
	assert.Equal(t, "rev-rebuild", after.ConfigRevision, "config revision must survive rebuild")
	assert.Equal(t, "acknowledged", after.LifecycleStatus, "lifecycle status must survive rebuild")
	require.Len(t, after.Fields, 1, "drift fields must survive rebuild")
	assert.Equal(t, "state", after.Fields[0].Attribute)
	assert.False(t, after.Fields[0].Matching)
}

// testEGDesiredStateIsolation verifies that desired-state observations are fully
// isolated from the entity view and entity index and that the isolation survives
// a projection rebuild. This locks down four provider code paths that would
// otherwise be untested:
//
//  1. the GetEntity current-row query filter that excludes kind='desired-state'
//     rows (queryCurrentRows / eg_entity_current read);
//  2. the updateEntityProjection early return that folds a desired-state row into
//     eg_entity_current for dedup but skips the entity-index rebuild;
//  3. the rebuildEntityIndex query filter (kind != 'desired-state') — exercised
//     because the desired-state row is ingested *before* the state observation,
//     so it is already present in eg_entity_current when the later state
//     observation triggers an index rebuild;
//  4. the RebuildProjections desired-state replay branch — after corruption the
//     log is replayed and the desired-state row must fold into current without
//     polluting the rebuilt index.
//
// GetDesiredState (which reads the log directly) must continue to surface the
// record throughout. ADR-022 §6 / ADR-023 §3.
func testEGDesiredStateIsolation(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	eid := egEID(t, "host:ds-iso-auth/ent1")
	now := time.Now().UTC().Truncate(time.Second)

	// 1. Ingest a desired-state observation FIRST, before any state observation.
	//    This forces the ordering where a desired-state row is already resident in
	//    eg_entity_current when the later state observation rebuilds the index —
	//    the exact scenario the rebuildEntityIndex filter must survive.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "config:rev-ds-1",
		Observations: []types.Observation{{
			Source:     "config:rev-ds-1",
			ObservedAt: now,
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       types.ObservationKindDesiredState,
			Confidence: types.ConfidenceHigh,
			Payload: map[string]interface{}{
				"config_revision": "rev-ds-1",
				"poison_key":      "must-not-appear",
				"hostname":        "desired-not-actual",
				"policies":        map[string]interface{}{"enforce_firewall": true},
			},
		}},
	}))

	// 2. Report a real state observation for the same subject. Its projection
	//    upsert is followed by an entity-index rebuild that reads every current
	//    row for the subject — including the desired-state row from step 1.
	egReport(ctx, t, p, "observer:test", eid.String(), map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "web01",
		"owning_tenant": "root/ds-iso",
	})

	// assertIsolated checks the invariants that must hold both before and after a
	// projection rebuild.
	assertIsolated := func(t *testing.T, phase string) {
		t.Helper()
		view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/ds-iso"})
		require.NoError(t, err, "%s: GetEntity", phase)
		require.NotNil(t, view)

		// The desired-state source must not appear in the entity view sources.
		for _, src := range view.Sources {
			assert.NotEqual(t, types.ObservationKindDesiredState, src.Kind,
				"%s: desired-state observation must not appear in entity Sources", phase)
		}
		// The desired-state-only payload key must not contaminate merged attributes
		// or the entity index, and the state observation's hostname must win.
		_, hasPoison := view.Entity.Attributes["poison_key"]
		assert.False(t, hasPoison,
			"%s: desired-state payload key must not appear in merged entity attributes", phase)
		assert.Equal(t, "web01", view.Entity.Attributes["hostname"],
			"%s: hostname must come from the state observation, not the desired-state row", phase)

		// GetDesiredState must still surface the desired-state record from the log.
		ds, err := p.GetDesiredState(ctx, eid)
		require.NoError(t, err, "%s: GetDesiredState", phase)
		require.NotNil(t, ds, "%s: GetDesiredState must return the desired-state record", phase)
		assert.Equal(t, "rev-ds-1", ds.ConfigRevision, "%s: ConfigRevision", phase)
		_, hasRev := ds.State["config_revision"]
		assert.False(t, hasRev, "%s: config_revision must be stripped from State", phase)
	}

	assertIsolated(t, "pre-rebuild")

	// 3. Corrupt the derived projections and rebuild from the log. The replay must
	//    fold the desired-state row into current without rebuilding the index from
	//    it, and the state row's index rebuild must again exclude the desired-state
	//    row. Providers without a corruption hook still validate rebuild idempotency.
	if c, ok := p.(corruptibleProvider); ok {
		require.NoError(t, c.CorruptProjectionsForTesting(ctx))
		_, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{TenantFilter: "root/ds-iso"})
		require.Error(t, err, "entity must be unreachable after projection corruption")
	}
	require.NoError(t, p.RebuildProjections(ctx))

	assertIsolated(t, "post-rebuild")
}

// testEGResolveIdentity verifies identity-claim resolution to EIDs (AC 8).
func testEGResolveIdentity(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const subject = "host:ri-auth/resolve1"
	egReport(ctx, t, p, "observer:test", subject, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "resolve-host",
		"machine_sid":   "S-1-5-21-xyz",
		"owning_tenant": "root/ri-tenant",
	})
	eid := egEID(t, subject)

	byHostname, err := p.ResolveIdentity(ctx, interfaces.IdentityClaims{Hostname: "resolve-host"})
	require.NoError(t, err)
	assert.Contains(t, byHostname, eid)

	byMissing, err := p.ResolveIdentity(ctx, interfaces.IdentityClaims{Hostname: "nonexistent"})
	require.NoError(t, err, "resolving an unknown identity must not error")
	assert.Empty(t, byMissing)

	bySID, err := p.ResolveIdentity(ctx, interfaces.IdentityClaims{MachineSID: "S-1-5-21-xyz"})
	require.NoError(t, err)
	assert.Contains(t, bySID, eid)
}

// testEGEmptyProjections verifies that the forward-declared edge and drift
// projections are queryable without panicking before their populating stories
// land (AC 9). The provider-level test asserts the schema tables exist.
func testEGEmptyProjections(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	// GetEdges over an empty projection returns either ErrNotImplemented or an
	// empty result — never a table-missing error and never a panic.
	edges, edgeErr := p.GetEdges(ctx, interfaces.EdgeFilter{})
	if edgeErr != nil {
		assert.ErrorIs(t, edgeErr, interfaces.ErrNotImplemented)
	} else {
		assert.Empty(t, edges)
	}

	// GetDriftState over an unmanaged entity returns an error (ErrNotImplemented
	// or not-found), never a panic.
	_, driftErr := p.GetDriftState(ctx, egEID(t, "host:empty-auth/host1"))
	assert.Error(t, driftErr)
}

// testEGOptsNoOp verifies that setting CollapseGroup on GetEntityOpts is a
// pass-through no-op: the read still succeeds and CollapseGroup is not populated.
func testEGOptsNoOp(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	const subject = "host:opts-auth/host1"
	egReport(ctx, t, p, "observer:test", subject, map[string]interface{}{
		"entity_kind":   "host",
		"hostname":      "opts-host",
		"owning_tenant": "root/opts-tenant",
	})

	view, err := p.GetEntity(ctx, egEID(t, subject), interfaces.GetEntityOpts{
		CollapseGroup: true,
		TenantFilter:  "root/opts-tenant",
	})
	require.NoError(t, err)
	require.NotNil(t, view)
	assert.Nil(t, view.CollapseGroup, "CollapseGroup opt is a pass-through no-op in this round")
}

// egReportEdge ingests a single-observation edge batch, failing on error.
// Subject format: "edge_type|from_eid|to_eid".
func egReportEdge(ctx context.Context, t *testing.T, p interfaces.EntityGraphProvider, source, fromEIDStr, toEIDStr, edgeType string) {
	t.Helper()
	subject := edgeType + "|" + fromEIDStr + "|" + toEIDStr
	batch := interfaces.ObservationBatch{
		Source: source,
		Observations: []types.Observation{
			egObservation(subject, source, time.Now().UTC(), map[string]interface{}{}),
		},
	}
	require.NoError(t, p.ReportObservations(ctx, batch), "report edge %s", subject)
}

// testEGEdgeRoundTrip verifies that an edge asserted via ReportObservations is
// readable via GetEdges by endpoint, type, and source (Story-3 AC 1).
func testEGEdgeRoundTrip(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	fromEID := egEID(t, "host:er-auth/from1")
	toEID := egEID(t, "host:er-auth/to1")
	egReport(ctx, t, p, "observer:scan", fromEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/er-tenant",
	})
	egReport(ctx, t, p, "observer:scan", toEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/er-tenant",
	})
	egReportEdge(ctx, t, p, "observer:scan", fromEID.String(), toEID.String(), "contains")

	// Filter by FromEID.
	fromRef := fromEID
	edges, err := p.GetEdges(ctx, interfaces.EdgeFilter{
		FromEID:      &fromRef,
		TenantFilter: "root/er-tenant",
	})
	require.NoError(t, err)
	require.Len(t, edges, 1, "edge must be readable by FromEID")
	assert.Equal(t, "contains", edges[0].Edge.Type)
	assert.Equal(t, fromEID.String(), edges[0].Edge.From.String())
	assert.Equal(t, toEID.String(), edges[0].Edge.To.String())

	// Filter by ToEID.
	toRef := toEID
	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{
		ToEID:        &toRef,
		TenantFilter: "root/er-tenant",
	})
	require.NoError(t, err)
	require.Len(t, edges, 1, "edge must be readable by ToEID")

	// Filter by source.
	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{
		FromEID:      &fromRef,
		Source:       "observer:scan",
		TenantFilter: "root/er-tenant",
	})
	require.NoError(t, err)
	require.Len(t, edges, 1, "edge must be readable by source")

	// Wrong source returns nothing.
	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{
		FromEID:      &fromRef,
		Source:       "observer:other",
		TenantFilter: "root/er-tenant",
	})
	require.NoError(t, err)
	assert.Empty(t, edges, "filter by wrong source must return nothing")

	// Filter by edge type.
	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{
		FromEID:      &fromRef,
		Types:        []string{"contains"},
		TenantFilter: "root/er-tenant",
	})
	require.NoError(t, err)
	require.Len(t, edges, 1, "edge must be readable by type")

	// Wrong type returns nothing.
	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{
		FromEID:      &fromRef,
		Types:        []string{"runs-on"},
		TenantFilter: "root/er-tenant",
	})
	require.NoError(t, err)
	assert.Empty(t, edges, "filter by wrong type must return nothing")
}

// testEGPlaceholderNode verifies that an edge referencing an unseen EID creates a
// placeholder node, and a later observation of that EID enriches it without
// creating a duplicate (Story-3 AC 2).
func testEGPlaceholderNode(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	fromEID := egEID(t, "host:ph-auth/from1")
	toEID := egEID(t, "host:ph-auth/to1") // not yet observed
	egReport(ctx, t, p, "observer:scan", fromEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/ph-tenant",
	})

	// Edge references toEID which has no prior observation — placeholder created.
	egReportEdge(ctx, t, p, "observer:scan", fromEID.String(), toEID.String(), "contains")

	// Edge is readable via GetEdges (no tenant filter so placeholder's empty owning_tenant passes).
	fromRef := fromEID
	edges, err := p.GetEdges(ctx, interfaces.EdgeFilter{FromEID: &fromRef})
	require.NoError(t, err)
	require.Len(t, edges, 1, "edge referencing placeholder node must be readable")
	assert.Equal(t, toEID.String(), edges[0].Edge.To.String())

	// Now enrich the placeholder with a real observation.
	egReport(ctx, t, p, "observer:scan", toEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/ph-tenant", "hostname": "enriched-host",
	})

	// Entity is retrievable and carries the enriched data.
	view, err := p.GetEntity(ctx, toEID, interfaces.GetEntityOpts{TenantFilter: "root/ph-tenant"})
	require.NoError(t, err)
	require.NotNil(t, view)
	assert.Equal(t, "enriched-host", view.Entity.Attributes["hostname"], "placeholder must be enriched, not duplicated")

	// Edge still has exactly one entry (no orphan or duplicate).
	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{FromEID: &fromRef})
	require.NoError(t, err)
	require.Len(t, edges, 1, "enriching placeholder must not duplicate the edge")
}

// testEGNeighborhoodDepthCap verifies that GetNeighborhood enforces the contract
// maximum depth of 3 and uses depth 2 when depth ≤ 0 (Story-3 AC 3).
func testEGNeighborhoodDepthCap(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	eid := egEID(t, "host:ndep-auth/root1")
	egReport(ctx, t, p, "observer:scan", eid.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/ndep-tenant",
	})

	// depth ≤ 0 → default depth 2: must not error.
	n, err := p.GetNeighborhood(ctx, eid, nil, types.TraversalBoth, 0)
	require.NoError(t, err, "depth=0 (default) must not error")
	require.NotNil(t, n)
	assert.Equal(t, eid.String(), n.Root.String())

	// depth=3 (maximum): must not error.
	n, err = p.GetNeighborhood(ctx, eid, nil, types.TraversalBoth, 3)
	require.NoError(t, err, "depth=3 (contract max) must not error")
	require.NotNil(t, n)

	// depth=4 (exceeds maximum): must be rejected with an error.
	_, err = p.GetNeighborhood(ctx, eid, nil, types.TraversalBoth, 4)
	require.Error(t, err, "depth=4 must be rejected")
}

// testEGNeighborhoodTenantPerHop verifies that GetNeighborhood excludes edges to
// out-of-subtree entities at every hop, resolved through current endpoint ownership,
// not any cached edge-row tenant field (Story-3 AC 4).
//
// Covers the static case (endpoint always out-of-subtree) and the moved-endpoint
// case (endpoint was in-subtree when the edge was first observed, then moved).
func testEGNeighborhoodTenantPerHop(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	rootEID := egEID(t, "host:nhop-auth/root1")
	inEID := egEID(t, "host:nhop-auth/in1")
	outEID := egEID(t, "host:nhop-auth/out1")

	egReport(ctx, t, p, "observer:scan", rootEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/nhop-tenant",
	})
	egReport(ctx, t, p, "observer:scan", inEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/nhop-tenant",
	})
	egReport(ctx, t, p, "observer:scan", outEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/other-tenant",
	})

	// Static cross-tenant edge: root → outEID (always out-of-subtree).
	egReportEdge(ctx, t, p, "observer:scan", rootEID.String(), outEID.String(), "contains")
	// Same-tenant edge: root → inEID.
	egReportEdge(ctx, t, p, "observer:scan", rootEID.String(), inEID.String(), "contains")

	n, err := p.GetNeighborhood(ctx, rootEID, nil, types.TraversalOutbound, 1)
	require.NoError(t, err)
	require.NotNil(t, n)

	// Cross-tenant edge must be absent.
	for _, e := range n.Edges {
		assert.NotEqual(t, outEID.String(), e.To.String(),
			"static cross-tenant edge endpoint must be excluded")
	}
	// Same-tenant edge must be present.
	var foundIn bool
	for _, e := range n.Edges {
		if e.To.String() == inEID.String() {
			foundIn = true
		}
	}
	assert.True(t, foundIn, "same-tenant edge must be included in neighborhood")

	// Moved-endpoint case: movedEID starts in nhop-tenant, then moves to other-tenant.
	movedEID := egEID(t, "host:nhop-auth/moved1")
	egReport(ctx, t, p, "enforcing-module:mover", movedEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/nhop-tenant",
	})
	egReportEdge(ctx, t, p, "observer:scan", rootEID.String(), movedEID.String(), "contains")

	// Before move: edge is visible (movedEID is in-subtree).
	n, err = p.GetNeighborhood(ctx, rootEID, nil, types.TraversalOutbound, 1)
	require.NoError(t, err)
	var movedVisible bool
	for _, e := range n.Edges {
		if e.To.String() == movedEID.String() {
			movedVisible = true
		}
	}
	assert.True(t, movedVisible, "edge to in-subtree entity must be visible before endpoint moves")

	// Move movedEID to other-tenant.
	egReport(ctx, t, p, "enforcing-module:mover", movedEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/other-tenant",
	})

	// After move: edge must be excluded via current-ownership check.
	n, err = p.GetNeighborhood(ctx, rootEID, nil, types.TraversalOutbound, 1)
	require.NoError(t, err)
	for _, e := range n.Edges {
		assert.NotEqual(t, movedEID.String(), e.To.String(),
			"moved-out endpoint must be excluded from neighborhood after move")
	}
}

// testEGGetEdgesTenantFilter verifies that GetEdges applies the same tenant-subtree
// filter as GetNeighborhood's hop-0 case, and that a cross-tenant edge query
// returns nothing (Story-3 AC 5).
func testEGGetEdgesTenantFilter(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	fromEID := egEID(t, "host:getef-auth/from1")
	toEID := egEID(t, "host:getef-auth/to1")
	egReport(ctx, t, p, "observer:scan", fromEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/tenant-a",
	})
	egReport(ctx, t, p, "observer:scan", toEID.String(), map[string]interface{}{
		"entity_kind": "host", "owning_tenant": "root/tenant-b",
	})
	egReportEdge(ctx, t, p, "observer:scan", fromEID.String(), toEID.String(), "contains")

	// Scoped to tenant-a: to-endpoint is in tenant-b → cross-tenant → excluded.
	fromRef := fromEID
	edges, err := p.GetEdges(ctx, interfaces.EdgeFilter{
		FromEID:      &fromRef,
		TenantFilter: "root/tenant-a",
	})
	require.NoError(t, err)
	assert.Empty(t, edges, "cross-tenant edge must not be returned when tenant filter is set")

	// Scoped to tenant-b: from-endpoint is in tenant-a → cross-tenant → excluded.
	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{
		ToEID:        &toEID,
		TenantFilter: "root/tenant-b",
	})
	require.NoError(t, err)
	assert.Empty(t, edges, "cross-tenant edge must not be returned from the other side's tenant filter")

	// No tenant filter: edge is returned.
	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{FromEID: &fromRef})
	require.NoError(t, err)
	assert.Len(t, edges, 1, "edge must be returned when no tenant filter is applied")
}

// testEGClaimScopeEntityReplace verifies that a re-enumeration under an entity
// claim scope retracts previously-asserted subjects that are absent from the new
// set, while leaving assertions from other sources untouched (Story-4 AC1).
func testEGClaimScopeEntityReplace(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	const (
		sub1 = "host:csent-auth/host1"
		sub2 = "host:csent-auth/host2"
		sub3 = "host:csent-auth/host3"
	)
	const srcA = "enforcing-module:scanner-a"
	const srcB = "enforcing-module:scanner-b"

	now := time.Now().UTC()
	scopePattern := types.ClaimScopePattern{
		Entity: &types.EntityScopePattern{EntityType: "host", AuthorityPrefix: "host:csent-auth/"},
	}

	// Initial batch from source A: asserts host1, host2, host3 under a claim scope.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: srcA,
		Observations: []types.Observation{
			egObservation(sub1, srcA, now, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root/csent-tenant", "hostname": "host1"}),
			egObservation(sub2, srcA, now, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root/csent-tenant", "hostname": "host2"}),
			egObservation(sub3, srcA, now, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root/csent-tenant", "hostname": "host3"}),
		},
		ClaimScopes: []types.ClaimScope{{Source: srcA, Pattern: scopePattern, AsOf: now}},
	}))

	// Source B also asserts host2 (different source, no claim scope).
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: srcB,
		Observations: []types.Observation{
			egObservation(sub2, srcB, now, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root/csent-tenant", "hostname": "host2-from-b"}),
		},
	}))

	// All three visible after initial assert.
	for _, sub := range []string{sub1, sub2, sub3} {
		_, err := p.GetEntity(ctx, egEID(t, sub), interfaces.GetEntityOpts{TenantFilter: "root/csent-tenant"})
		require.NoError(t, err, "entity %s must be visible after initial assert", sub)
	}

	now2 := now.Add(time.Second)

	// Re-enumeration from source A: only host1 now asserted.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: srcA,
		Observations: []types.Observation{
			egObservation(sub1, srcA, now2, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root/csent-tenant", "hostname": "host1"}),
		},
		ClaimScopes: []types.ClaimScope{{Source: srcA, Pattern: scopePattern, AsOf: now2}},
	}))

	// host1 is still visible (not retracted by source A).
	_, err := p.GetEntity(ctx, egEID(t, sub1), interfaces.GetEntityOpts{TenantFilter: "root/csent-tenant"})
	require.NoError(t, err, "host1 must remain visible after re-enumeration that includes it")

	// host3 must be retracted: source A no longer asserts it, no other source does.
	_, err = p.GetEntity(ctx, egEID(t, sub3), interfaces.GetEntityOpts{TenantFilter: "root/csent-tenant"})
	require.Error(t, err, "host3 must be retracted after source A omits it from re-enumeration")

	// host2: source A's assertion is retracted, but source B's assertion survives.
	view2, err := p.GetEntity(ctx, egEID(t, sub2), interfaces.GetEntityOpts{TenantFilter: "root/csent-tenant"})
	require.NoError(t, err, "host2 must remain visible because source B still asserts it")
	require.NotNil(t, view2)
	require.NotNil(t, view2.Entity)
	assert.Equal(t, "host2-from-b", view2.Entity.Attributes["hostname"],
		"host2 must be served from source B's assertion after source A retracts")
}

// testEGClaimScopeEdgeReplace verifies that a re-enumeration under an edge
// claim scope retracts edges that were present in the prior assertion set but
// absent from the new enumeration (Story-4 AC2).
func testEGClaimScopeEdgeReplace(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	anchor := egEID(t, "host:csedge-auth/anchor1")
	peer1 := egEID(t, "host:csedge-auth/peer1")
	peer2 := egEID(t, "host:csedge-auth/peer2")
	const src = "enforcing-module:edge-scanner"

	now := time.Now().UTC()
	edgeScope := types.ClaimScopePattern{
		Edge: &types.EdgeScopePattern{
			EdgeType:  "contains",
			AnchorEID: anchor,
			Direction: types.TraversalOutbound,
		},
	}

	mkEdgeObs := func(from, to interfaces.EIDRef, at time.Time) types.Observation {
		return egObservation("contains|"+from.String()+"|"+to.String(), src, at, map[string]interface{}{})
	}

	// Initial batch: anchor → peer1, anchor → peer2.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:       src,
		Observations: []types.Observation{mkEdgeObs(anchor, peer1, now), mkEdgeObs(anchor, peer2, now)},
		ClaimScopes:  []types.ClaimScope{{Source: src, Pattern: edgeScope, AsOf: now}},
	}))

	anchorRef := anchor
	edges, err := p.GetEdges(ctx, interfaces.EdgeFilter{FromEID: &anchorRef, Source: src})
	require.NoError(t, err)
	require.Len(t, edges, 2, "both edges must be visible after initial assert")

	now2 := now.Add(time.Second)

	// Re-enumeration: only anchor → peer1 remains.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:       src,
		Observations: []types.Observation{mkEdgeObs(anchor, peer1, now2)},
		ClaimScopes:  []types.ClaimScope{{Source: src, Pattern: edgeScope, AsOf: now2}},
	}))

	edges, err = p.GetEdges(ctx, interfaces.EdgeFilter{FromEID: &anchorRef, Source: src})
	require.NoError(t, err)
	require.Len(t, edges, 1, "edge to peer2 must be retracted after re-enumeration omits it")
	assert.Equal(t, peer1.String(), edges[0].Edge.To.String(), "remaining edge must point to peer1")
}

// testEGClaimScopeOverlapRejected verifies that two claim scopes with the same
// source and pattern key within a single batch are rejected (Story-4 AC3).
func testEGClaimScopeOverlapRejected(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	const src = "enforcing-module:overlap-scanner"
	now := time.Now().UTC()
	pattern := types.ClaimScopePattern{
		Entity: &types.EntityScopePattern{EntityType: "host", AuthorityPrefix: "host:csovlp-auth/"},
	}

	err := p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: src,
		Observations: []types.Observation{
			egObservation("host:csovlp-auth/host1", src, now, map[string]interface{}{
				"entity_kind": "host", "owning_tenant": "root/ovlp-tenant",
			}),
		},
		ClaimScopes: []types.ClaimScope{
			{Source: src, Pattern: pattern, AsOf: now},
			{Source: src, Pattern: pattern, AsOf: now.Add(time.Millisecond)},
		},
	})
	require.Error(t, err, "two claim scopes with the same source+pattern in one batch must be rejected")
}

// testEGSourceClosure verifies that an empty re-enumeration retracts all prior
// subjects under the scope and that the retraction is visible as an absence
// observation in GetHistory (Story-4 AC4).
func testEGSourceClosure(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()

	const (
		sub1 = "host:csclo-auth/host1"
		sub2 = "host:csclo-auth/host2"
	)
	const src = "enforcing-module:closure-scanner"

	t0 := time.Now().UTC().Add(-time.Millisecond)
	now := time.Now().UTC()
	scopePattern := types.ClaimScopePattern{
		Entity: &types.EntityScopePattern{EntityType: "host", AuthorityPrefix: "host:csclo-auth/"},
	}

	// Initial assertion: host1 and host2.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: src,
		Observations: []types.Observation{
			egObservation(sub1, src, now, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root/clo-tenant"}),
			egObservation(sub2, src, now, map[string]interface{}{"entity_kind": "host", "owning_tenant": "root/clo-tenant"}),
		},
		ClaimScopes: []types.ClaimScope{{Source: src, Pattern: scopePattern, AsOf: now}},
	}))

	for _, sub := range []string{sub1, sub2} {
		_, err := p.GetEntity(ctx, egEID(t, sub), interfaces.GetEntityOpts{TenantFilter: "root/clo-tenant"})
		require.NoError(t, err, "entity %s must be visible after initial assert", sub)
	}

	now2 := now.Add(time.Second)

	// Source closure: empty re-enumeration retracts everything in scope.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:       src,
		Observations: nil,
		ClaimScopes:  []types.ClaimScope{{Source: src, Pattern: scopePattern, AsOf: now2}},
	}))

	// Both entities must be gone.
	for _, sub := range []string{sub1, sub2} {
		_, err := p.GetEntity(ctx, egEID(t, sub), interfaces.GetEntityOpts{TenantFilter: "root/clo-tenant"})
		require.Error(t, err, "entity %s must be retracted after source closure", sub)
	}

	// Absence must be visible in GetHistory for sub1.
	t1 := now2.Add(time.Second)
	history, err := p.GetHistory(ctx, egEID(t, sub1), interfaces.TimeRange{From: t0, To: t1})
	require.NoError(t, err)
	var hasAbsence bool
	for _, rec := range history {
		if rec.Observation.Kind == types.ObservationKindAbsence && rec.Observation.Source == src {
			hasAbsence = true
			break
		}
	}
	assert.True(t, hasAbsence, "GetHistory must include an absence observation for the retracted entity")
}

func testEGProviderIdentity(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	assert.NotEmpty(t, p.Name(), "provider name must not be empty")
	assert.NotEmpty(t, p.Description(), "provider description must not be empty")
}

func testEGProviderAvailable(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	// Available must not error — the noop provider is always available.
	ok, err := p.Available()
	assert.NoError(t, err)
	assert.True(t, ok)
}

// --- Registry tests ---

func TestRegistry_RegisterAndLookup(t *testing.T) {
	// Use unique names to avoid collisions with other tests.
	p1 := &noopProvider{name: "reg-test-alpha"}
	p2 := &noopProvider{name: "reg-test-beta"}

	require.NoError(t, interfaces.RegisterEntityGraphProvider(p1))
	require.NoError(t, interfaces.RegisterEntityGraphProvider(p2))

	got1, err := interfaces.GetEntityGraphProvider("reg-test-alpha")
	require.NoError(t, err)
	assert.Equal(t, p1.Name(), got1.Name())

	got2, err := interfaces.GetEntityGraphProvider("reg-test-beta")
	require.NoError(t, err)
	assert.Equal(t, p2.Name(), got2.Name())

	t.Cleanup(func() {
		interfaces.UnregisterEntityGraphProvider("reg-test-alpha")
		interfaces.UnregisterEntityGraphProvider("reg-test-beta")
	})
}

func TestRegistry_DuplicateNameRejected(t *testing.T) {
	p := &noopProvider{name: "reg-test-dup"}
	require.NoError(t, interfaces.RegisterEntityGraphProvider(p))
	t.Cleanup(func() { interfaces.UnregisterEntityGraphProvider("reg-test-dup") })

	dup := &noopProvider{name: "reg-test-dup"}
	err := interfaces.RegisterEntityGraphProvider(dup)
	require.Error(t, err, "registering a duplicate name must return an error")
}

func TestRegistry_LookupMissing(t *testing.T) {
	_, err := interfaces.GetEntityGraphProvider("no-such-provider-xyzzy")
	require.Error(t, err)
}

// --- Story-5: drift, desired-state, drift-lifecycle (Issue #2875) ---

// testEGDriftNotFound verifies AC1: GetDesiredState returns (nil, nil) and
// GetDriftState returns a not-found error when no observations exist.
func testEGDriftNotFound(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	eid := egEID(t, "host:drift-nf-auth/ent1")

	// GetDesiredState with no observations must return (nil, nil).
	ds, err := p.GetDesiredState(ctx, eid)
	require.NoError(t, err, "GetDesiredState with no observations must succeed")
	assert.Nil(t, ds, "GetDesiredState must return nil when no desired-state records exist")

	// GetDriftState with no drift record must return a not-found error.
	_, err = p.GetDriftState(ctx, eid)
	require.Error(t, err, "GetDriftState must return an error when no drift record exists")
}

// testEGDriftStateRoundTrip verifies AC2+AC3: a drift-diff observation surfaces
// via GetDriftState and ListDrifted with the correct fields and matching flags.
func testEGDriftStateRoundTrip(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	eid := egEID(t, "host:drift-rt-auth/ent1")
	now := time.Now().UTC().Truncate(time.Second)

	driftFields := []interface{}{
		map[string]interface{}{"attribute": "hostname", "desired": "web01", "actual": "web99", "matching": false},
		map[string]interface{}{"attribute": "cpu_count", "desired": float64(4), "actual": float64(4), "matching": true},
	}

	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:drift-reporter",
		Observations: []types.Observation{
			{
				Source:     "enforcing-module:drift-reporter",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    eid.String(),
				Kind:       types.ObservationKindDriftDiff,
				Confidence: types.ConfidenceHigh,
				Payload: map[string]interface{}{
					"config_revision": "rev-abc",
					"fields":          driftFields,
				},
			},
		},
	}))

	// GetDriftState must return the drift record.
	state, err := p.GetDriftState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "rev-abc", state.ConfigRevision)
	assert.Equal(t, "detected", state.LifecycleStatus)
	require.Len(t, state.Fields, 2)

	// Verify the mismatching field.
	var hostnameField *interfaces.DriftField
	for i := range state.Fields {
		if state.Fields[i].Attribute == "hostname" {
			hostnameField = &state.Fields[i]
		}
	}
	require.NotNil(t, hostnameField, "hostname drift field must be present")
	assert.False(t, hostnameField.Matching)

	// ListDrifted must include this entity.
	all, err := p.ListDrifted(ctx, interfaces.DriftFilter{})
	require.NoError(t, err)
	found := false
	for _, s := range all {
		if s.EID.String() == eid.String() {
			found = true
			break
		}
	}
	assert.True(t, found, "ListDrifted must include the drifted entity")
}

// testEGDriftLifecycle verifies AC4: UpdateDriftLifecycle transitions are
// queryable, appear distinctly in GetHistory, and do not alter the drift fields.
func testEGDriftLifecycle(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	ctx := context.Background()
	eid := egEID(t, "host:drift-lc-auth/ent1")
	now := time.Now().UTC().Truncate(time.Second)

	// Seed a drift-diff observation.
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:drift-reporter",
		Observations: []types.Observation{
			{
				Source:     "enforcing-module:drift-reporter",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    eid.String(),
				Kind:       types.ObservationKindDriftDiff,
				Confidence: types.ConfidenceHigh,
				Payload: map[string]interface{}{
					"config_revision": "rev-lc",
					"fields": []interface{}{
						map[string]interface{}{"attribute": "state", "desired": "running", "actual": "stopped", "matching": false},
					},
				},
			},
		},
	}))

	// Acknowledge the drift.
	require.NoError(t, p.UpdateDriftLifecycle(ctx, interfaces.DriftLifecycleUpdate{
		EID:        eid,
		Transition: "acknowledge",
		Actor:      "ops-bot",
		At:         now.Add(time.Minute),
		Note:       "tracked in ticket #42",
	}))

	// Lifecycle status must be updated.
	state, err := p.GetDriftState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "acknowledged", state.LifecycleStatus, "lifecycle_status must be 'acknowledged' after acknowledge transition")

	// Drift fields must be unchanged after lifecycle transition (AC4).
	require.Len(t, state.Fields, 1, "drift fields must not be altered by lifecycle transition")
	assert.Equal(t, "state", state.Fields[0].Attribute)

	// GetHistory must include a lifecycle-kind entry tagged by actor (AC3).
	tr := interfaces.TimeRange{From: now.Add(-time.Second), To: now.Add(time.Hour)}
	history, err := p.GetHistory(ctx, eid, tr)
	require.NoError(t, err)
	lifecycleCount := 0
	for _, rec := range history {
		if rec.Observation.Kind == types.ObservationKindLifecycle {
			lifecycleCount++
			assert.Equal(t, "ops-bot", rec.Observation.Source,
				"lifecycle history entry must be tagged by actor, not source-provenance class")
		}
	}
	assert.Equal(t, 1, lifecycleCount, "exactly one lifecycle entry must appear in GetHistory")

	// UpdateDriftLifecycle with unknown transition must return an error.
	err = p.UpdateDriftLifecycle(ctx, interfaces.DriftLifecycleUpdate{
		EID:        eid,
		Transition: "vaporize",
		Actor:      "ops-bot",
	})
	require.Error(t, err, "unknown lifecycle transition must return an error")
}

// --- Compile-time assertion ---

// Verify that noopProvider satisfies the full EntityGraphProvider interface.
// This is not a real provider — house rule: no memory-only storage for durable
// features. It exists only to enforce the interface at compile time.
var _ interfaces.EntityGraphProvider = (*noopProvider)(nil)

// noopProvider is a minimal stub that satisfies EntityGraphProvider at compile
// time. All methods return zero values or ErrNotImplemented.
type noopProvider struct {
	name string
}

func (n *noopProvider) Name() string        { return n.name }
func (n *noopProvider) Description() string { return "noop provider for compile-time assertion" }
func (n *noopProvider) Available() (bool, error) {
	return true, nil
}

func (n *noopProvider) GetEntity(_ context.Context, _ interfaces.EIDRef, _ interfaces.GetEntityOpts) (*types.EntityView, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetDesiredState(_ context.Context, _ interfaces.EIDRef) (*types.DesiredStateView, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetDriftState(_ context.Context, _ interfaces.EIDRef) (*interfaces.DriftState, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) QueryEntities(_ context.Context, _ interfaces.EntityFilter, _ interfaces.PageToken) (*interfaces.EntityPage, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetEdges(_ context.Context, _ interfaces.EdgeFilter) ([]*interfaces.EdgeView, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetNeighborhood(_ context.Context, _ interfaces.EIDRef, _ []string, _ types.TraversalDirection, _ int) (*types.Neighborhood, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetHistory(_ context.Context, _ interfaces.EIDRef, _ interfaces.TimeRange) ([]*interfaces.ObservationRecord, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) Diff(_ context.Context, _ interfaces.EIDRef, _ interfaces.TimeRange) (*interfaces.StateDiff, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetTimeline(_ context.Context, _ []interfaces.EIDRef, _ interfaces.TimeRange) ([]*interfaces.TimelineEvent, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) ListDrifted(_ context.Context, _ interfaces.DriftFilter) ([]*interfaces.DriftState, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) Watch(_ context.Context, _ interfaces.WatchFilter, _ string) (<-chan interfaces.WatchEvent, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) ResolveIdentity(_ context.Context, _ interfaces.IdentityClaims) ([]interfaces.EIDRef, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) ReportObservations(_ context.Context, _ interfaces.ObservationBatch) error {
	return interfaces.ErrNotImplemented
}
func (n *noopProvider) UpdateDriftLifecycle(_ context.Context, _ interfaces.DriftLifecycleUpdate) error {
	return interfaces.ErrNotImplemented
}
func (n *noopProvider) RebuildProjections(_ context.Context) error {
	return interfaces.ErrNotImplemented
}
