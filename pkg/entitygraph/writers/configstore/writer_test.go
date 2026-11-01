// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package configstore_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	sqliteprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/configstore"
)

func newTestProvider(t *testing.T) *sqliteprovider.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := sqliteprovider.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func mustEID(t *testing.T, s string) types.EID {
	t.Helper()
	eid, err := types.ParseEID(s)
	require.NoError(t, err)
	return eid
}

func baseRev() configstore.ConfigRevision {
	return configstore.ConfigRevision{
		ConfigID: "cfg-001",
		Revision: "v1.2.3",
		TenantID: "root/msp-a/client-1",
		DesiredState: map[string]interface{}{
			"policies": map[string]interface{}{"enforce_firewall": true},
			"modules":  []interface{}{"firewall", "patch"},
		},
	}
}

// TestAC1_DesiredStateObservationPerEID verifies that Ingest writes a
// desired-state observation to the entity graph for each targeted EID.
func TestAC1_DesiredStateObservationPerEID(t *testing.T) {
	p := newTestProvider(t)
	w, err := configstore.New(p)
	require.NoError(t, err)

	ctx := context.Background()
	eid1 := mustEID(t, "cfgms:controller/steward-aaa")
	eid2 := mustEID(t, "cfgms:controller/steward-bbb")
	rev := baseRev()

	require.NoError(t, w.Ingest(ctx, rev, []types.EID{eid1, eid2}))

	// Verify via GetHistory that both EIDs have exactly one desired-state record.
	wide := interfaces.TimeRange{
		From: time.Unix(0, 0).UTC(),
		To:   time.Now().UTC().Add(time.Hour),
	}
	for _, eid := range []types.EID{eid1, eid2} {
		records, err := p.GetHistory(ctx, eid, wide)
		require.NoError(t, err)
		var dsCount int
		for _, rec := range records {
			if rec.Observation.Kind == types.ObservationKindDesiredState {
				dsCount++
			}
		}
		require.Equal(t, 1, dsCount, "EID %s must have exactly one desired-state log row", eid)
	}
}

// TestAC2_GetDesiredStateReturnsCorrectRevision verifies that GetDesiredState
// returns the config-revision label and desired-state attributes after Ingest.
func TestAC2_GetDesiredStateReturnsCorrectRevision(t *testing.T) {
	p := newTestProvider(t)
	w, err := configstore.New(p)
	require.NoError(t, err)

	ctx := context.Background()
	eid := mustEID(t, "cfgms:controller/steward-ccc")
	rev := baseRev()

	require.NoError(t, w.Ingest(ctx, rev, []types.EID{eid}))

	ds, err := p.GetDesiredState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, ds, "GetDesiredState must return non-nil after Ingest")

	require.Equal(t, rev.Revision, ds.ConfigRevision,
		"ConfigRevision must match the ingested revision label")
	require.False(t, ds.ObservedAt.IsZero(), "ObservedAt must be set")

	// config_revision must be stripped from State (it is a reserved key).
	_, hasRev := ds.State["config_revision"]
	require.False(t, hasRev, "config_revision must not appear in State")

	// The custom desired-state attributes must be present.
	policies, ok := ds.State["policies"]
	require.True(t, ok, "policies attribute must be in State")
	require.NotNil(t, policies)
}

// TestAC3_EmptyEIDsIsNoop verifies that Ingest with an empty EID slice returns
// nil and writes no observations (sparse population — no panic or error).
func TestAC3_EmptyEIDsIsNoop(t *testing.T) {
	p := newTestProvider(t)
	w, err := configstore.New(p)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, w.Ingest(ctx, baseRev(), nil))
	require.NoError(t, w.Ingest(ctx, baseRev(), []types.EID{}))
}

// TestAC4_IdenticalRevisionProducesNoDuplicate verifies that re-ingesting the
// same (revision, EID) pair does not append a second log row (content-hash dedup).
func TestAC4_IdenticalRevisionProducesNoDuplicate(t *testing.T) {
	p := newTestProvider(t)
	w, err := configstore.New(p)
	require.NoError(t, err)

	ctx := context.Background()
	eid := mustEID(t, "cfgms:controller/steward-ddd")
	rev := baseRev()

	require.NoError(t, w.Ingest(ctx, rev, []types.EID{eid}))
	require.NoError(t, w.Ingest(ctx, rev, []types.EID{eid})) // bit-identical → dedup

	wide := interfaces.TimeRange{
		From: time.Unix(0, 0).UTC(),
		To:   time.Now().UTC().Add(time.Hour),
	}
	records, err := p.GetHistory(ctx, eid, wide)
	require.NoError(t, err)

	var dsCount int
	for _, rec := range records {
		if rec.Observation.Kind == types.ObservationKindDesiredState {
			dsCount++
		}
	}
	require.Equal(t, 1, dsCount,
		"bit-identical re-ingest must not append a second desired-state log row")
}

// TestDesiredStateDoesNotPollutEntityView verifies that after ingesting a
// desired-state observation for a steward that also has a state observation,
// GetEntity does not include the desired-state source in its view or attributes.
func TestDesiredStateDoesNotPollutEntityView(t *testing.T) {
	p := newTestProvider(t)
	w, err := configstore.New(p)
	require.NoError(t, err)

	ctx := context.Background()
	eid := mustEID(t, "cfgms:controller/steward-eee")
	now := time.Now().UTC()

	// Register the entity with a state observation.
	stateRev := configstore.ConfigRevision{
		ConfigID: "c1",
		Revision: "v1",
		TenantID: "root/t",
		DesiredState: map[string]interface{}{
			"poison_key": "must-not-appear",
		},
	}
	require.NoError(t, p.ReportObservations(ctx, interfaces.ObservationBatch{
		Source: "enforcing-module:test",
		Observations: []types.Observation{{
			Source:     "enforcing-module:test",
			ObservedAt: now,
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       types.ObservationKindState,
			Confidence: types.ConfidenceHigh,
			Payload: map[string]interface{}{
				"entity_kind":   "cfgms",
				"owning_tenant": "root/t",
				"hostname":      "ctrl-node",
			},
		}},
	}))

	// Ingest a desired-state observation with a poison key.
	require.NoError(t, w.Ingest(ctx, stateRev, []types.EID{eid}))

	// GetEntity must not expose the desired-state source or its attributes.
	view, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, view)

	for _, src := range view.Sources {
		require.NotEqual(t, types.ObservationKindDesiredState, src.Kind,
			"desired-state observation must not appear in entity Sources")
	}
	_, hasPoisonKey := view.Entity.Attributes["poison_key"]
	require.False(t, hasPoisonKey,
		"desired-state payload key must not appear in merged entity attributes")
}

// TestNewWriterNilProvider verifies that New rejects a nil provider.
func TestNewWriterNilProvider(t *testing.T) {
	_, err := configstore.New(nil)
	require.Error(t, err)
}

// TestIngest_BindsOwningTenantItself is a REQUIRED test (Issue #4348):
// Ingest must stamp owning_tenant onto every observation itself from
// rev.TenantID, even when the caller's DesiredState carries no tenant key at
// all. Before the fix, Ingest never referenced rev.TenantID, so an
// observation written this way had no owning_tenant — invisible to every
// tenant-scoped read (ADR-023 §7) — unless the caller happened to stuff the
// key into DesiredState manually (no production caller did).
func TestIngest_BindsOwningTenantItself(t *testing.T) {
	p := newTestProvider(t)
	w, err := configstore.New(p)
	require.NoError(t, err)

	ctx := context.Background()
	eid := mustEID(t, "cfgms:controller/steward-tenant-bind")
	rev := baseRev() // DesiredState has no owning_tenant/tenant_path key

	require.NoError(t, w.Ingest(ctx, rev, []types.EID{eid}))

	wide := interfaces.TimeRange{
		From: time.Unix(0, 0).UTC(),
		To:   time.Now().UTC().Add(time.Hour),
	}
	records, err := p.GetHistory(ctx, eid, wide)
	require.NoError(t, err)

	var found bool
	for _, rec := range records {
		if rec.Observation.Kind != types.ObservationKindDesiredState {
			continue
		}
		found = true
		require.Equal(t, rev.TenantID, rec.Observation.Payload["owning_tenant"],
			"Ingest must bind rev.TenantID as owning_tenant on the observation itself")
	}
	require.True(t, found, "expected a desired-state observation to inspect")
}

// TestIngest_OverridesCallerSuppliedTenant verifies that Ingest's own
// owning_tenant binding always wins over anything the caller placed in
// DesiredState — a caller must not be able to assert a different tenant than
// rev.TenantID by populating owning_tenant/tenant_path itself.
func TestIngest_OverridesCallerSuppliedTenant(t *testing.T) {
	p := newTestProvider(t)
	w, err := configstore.New(p)
	require.NoError(t, err)

	ctx := context.Background()
	eid := mustEID(t, "cfgms:controller/steward-tenant-override")
	rev := baseRev()
	rev.DesiredState["owning_tenant"] = "some-other-tenant"
	rev.DesiredState["tenant_path"] = "some-other-tenant"

	require.NoError(t, w.Ingest(ctx, rev, []types.EID{eid}))

	ds, err := p.GetDesiredState(ctx, eid)
	require.NoError(t, err)
	require.NotNil(t, ds)

	wide := interfaces.TimeRange{
		From: time.Unix(0, 0).UTC(),
		To:   time.Now().UTC().Add(time.Hour),
	}
	records, err := p.GetHistory(ctx, eid, wide)
	require.NoError(t, err)
	for _, rec := range records {
		if rec.Observation.Kind != types.ObservationKindDesiredState {
			continue
		}
		require.Equal(t, rev.TenantID, rec.Observation.Payload["owning_tenant"],
			"rev.TenantID must win over a caller-supplied owning_tenant")
	}
}

// TestIngest_RejectsEmptyTenantID verifies that Ingest refuses to write an
// observation for a ConfigRevision with no TenantID, rather than silently
// producing an untenanted record.
func TestIngest_RejectsEmptyTenantID(t *testing.T) {
	p := newTestProvider(t)
	w, err := configstore.New(p)
	require.NoError(t, err)

	ctx := context.Background()
	eid := mustEID(t, "cfgms:controller/steward-no-tenant")
	rev := baseRev()
	rev.TenantID = ""

	err = w.Ingest(ctx, rev, []types.EID{eid})
	require.Error(t, err)
}
