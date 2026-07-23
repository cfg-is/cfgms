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

// testEGRebuild verifies that RebuildProjections leaves entity reads unchanged
// (AC 7). Providers that do not implement RebuildProjections are skipped via the
// type assertion so the shared harness stays provider-agnostic.
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
	before1, err := p.GetEntity(ctx, egEID(t, subject1), opts)
	require.NoError(t, err)
	require.NotNil(t, before1)
	before2, err := p.GetEntity(ctx, egEID(t, subject2), opts)
	require.NoError(t, err)
	require.NotNil(t, before2)

	rebuilder, ok := p.(interface {
		RebuildProjections(ctx context.Context) error
	})
	if !ok {
		t.Skip("provider does not implement RebuildProjections")
	}
	require.NoError(t, rebuilder.RebuildProjections(ctx))

	after1, err := p.GetEntity(ctx, egEID(t, subject1), opts)
	require.NoError(t, err)
	require.NotNil(t, after1)
	after2, err := p.GetEntity(ctx, egEID(t, subject2), opts)
	require.NoError(t, err)
	require.NotNil(t, after2)

	assert.Equal(t, before1.Entity.Attributes["hostname"], after1.Entity.Attributes["hostname"])
	assert.Equal(t, before2.Entity.Attributes["hostname"], after2.Entity.Attributes["hostname"])
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
