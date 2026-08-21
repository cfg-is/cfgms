// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Regression coverage for Issue #3480.
//
// GET /api/v1/stewards answered entirely from ControllerService's in-process
// map, which only holds stewards THIS node handled. In a cluster a steward
// actively heartbeating through one node was therefore invisible on every other
// node — including the elected leader — while its row sat in the shared backend
// the whole time (measured live, story #3096, runbook §6 finding F4).
//
// The fix composes the two sources rather than swapping one for the other, so
// these tests pin both halves: the durable store supplies existence
// cluster-wide, and the node-local view is not allowed to fabricate liveness for
// a steward attached elsewhere.

// fleetViewStore is a StewardStore returning a fixed record set.
type fleetViewStore struct {
	business.StewardStore
	records []*business.StewardRecord
	listErr error
	getErr  error
}

func (f *fleetViewStore) ListStewards(_ context.Context) ([]*business.StewardRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.records, nil
}

func (f *fleetViewStore) GetSteward(_ context.Context, id string) (*business.StewardRecord, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	for _, r := range f.records {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, business.ErrStewardNotFound
}

func fleetViewRecord(id, tenant string) *business.StewardRecord {
	return &business.StewardRecord{
		ID:       id,
		TenantID: tenant,
		Status:   business.StewardStatusActive,
		LastSeen: time.Now().UTC(),
	}
}

// TestFleetRecords_ReturnsClusterWideSet is the core guard: the durable store is
// consulted, so stewards this node never handled are still present.
func TestFleetRecords_ReturnsClusterWideSet(t *testing.T) {
	srv := &Server{stewardStore: &fleetViewStore{records: []*business.StewardRecord{
		fleetViewRecord("steward-local", "acme"),
		fleetViewRecord("steward-on-peer", "acme"),
	}}}
	srv.logger = logging.NewNoopLogger()

	got, ok := srv.fleetRecords(context.Background(), "")

	require.True(t, ok, "a wired durable store must be used")
	require.Len(t, got, 2,
		"stewards attached to peer nodes must appear; a node-local answer is the Issue #3480 defect")
	assert.Contains(t, got, "steward-on-peer")
}

// TestFleetRecords_ScopesToCallerTenant is the security half. This scoping is NEW
// to the unfiltered list path — it was previously safe to omit only because the
// in-process map was node-local. Reading the shared store without it would hand
// a tenant-scoped caller the entire cluster's fleet, so this must not regress.
func TestFleetRecords_ScopesToCallerTenant(t *testing.T) {
	srv := &Server{stewardStore: &fleetViewStore{records: []*business.StewardRecord{
		fleetViewRecord("steward-acme", "acme"),
		fleetViewRecord("steward-acme-child", "acme/child"),
		fleetViewRecord("steward-other", "othercorp"),
		// Deliberately adjacent: "acme-evil" shares a prefix with "acme" but is a
		// different tenant, and must not leak through a naive prefix match.
		fleetViewRecord("steward-lookalike", "acme-evil"),
	}}}
	srv.logger = logging.NewNoopLogger()

	got, ok := srv.fleetRecords(context.Background(), "acme")

	require.True(t, ok)
	assert.Contains(t, got, "steward-acme", "own tenant must be visible")
	assert.Contains(t, got, "steward-acme-child", "subtree descendants must be visible")
	assert.NotContains(t, got, "steward-other", "other tenants must not be visible")
	assert.NotContainsf(t, got, "steward-lookalike",
		"tenant %q must not match %q — subtree containment is on a path-segment boundary", "acme-evil", "acme")
}

// TestFleetRecords_UnscopedCallerSeesEverything pins the admin case: an mTLS
// admin principal carries no tenant and must still see the whole fleet.
func TestFleetRecords_UnscopedCallerSeesEverything(t *testing.T) {
	srv := &Server{stewardStore: &fleetViewStore{records: []*business.StewardRecord{
		fleetViewRecord("a", "acme"),
		fleetViewRecord("b", "othercorp"),
	}}}
	srv.logger = logging.NewNoopLogger()

	got, ok := srv.fleetRecords(context.Background(), "")

	require.True(t, ok)
	assert.Len(t, got, 2, "an unscoped caller must see every tenant's stewards")
}

// TestFleetRecords_NoStoreFallsBackToNodeLocal covers the OSS composite backend,
// which supplies no StewardStore. The caller must fall back to the node-local
// view rather than reporting an empty fleet.
func TestFleetRecords_NoStoreFallsBackToNodeLocal(t *testing.T) {
	srv := &Server{}
	srv.logger = logging.NewNoopLogger()

	got, ok := srv.fleetRecords(context.Background(), "")

	assert.False(t, ok, "an unwired store must signal fallback, not success")
	assert.Nil(t, got)
}

// TestFleetRecords_StoreErrorFallsBackRatherThanEmptying guards against the
// worst failure mode: a transient store error must not render the fleet as
// empty on a dashboard. Falling back to the node-local view degrades to a
// partial answer instead of a confident wrong one.
func TestFleetRecords_StoreErrorFallsBackRatherThanEmptying(t *testing.T) {
	srv := &Server{stewardStore: &fleetViewStore{listErr: assert.AnError}}
	srv.logger = logging.NewNoopLogger()

	got, ok := srv.fleetRecords(context.Background(), "")

	assert.False(t, ok, "a store failure must fall back, not report an empty fleet")
	assert.Nil(t, got)
}

// TestDurableStewardRecord_ResolvesStewardAttachedElsewhere backs the
// GET /stewards/{id} half: a steward attached to a peer node must resolve rather
// than 404, which is what made it look non-existent from the leader.
func TestDurableStewardRecord_ResolvesStewardAttachedElsewhere(t *testing.T) {
	srv := &Server{stewardStore: &fleetViewStore{records: []*business.StewardRecord{
		fleetViewRecord("steward-on-peer", "acme"),
	}}}
	srv.logger = logging.NewNoopLogger()

	got := srv.durableStewardRecord(context.Background(), "steward-on-peer")

	require.NotNil(t, got, "a steward in the shared backend must resolve from any node")
	assert.Equal(t, "acme", got.TenantID)
}

// TestDurableStewardRecord_UnknownIsNil keeps a genuinely absent steward a 404
// rather than turning every miss into a store error.
func TestDurableStewardRecord_UnknownIsNil(t *testing.T) {
	srv := &Server{stewardStore: &fleetViewStore{}}
	srv.logger = logging.NewNoopLogger()

	assert.Nil(t, srv.durableStewardRecord(context.Background(), "no-such-steward"))
}
