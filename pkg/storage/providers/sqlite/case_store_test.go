// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite provides unit tests for SQLiteCaseStore (ADR-022 §8, Issue #3602).
package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestCaseStore(t *testing.T) *SQLiteCaseStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteCaseStore{db: db}
}

func makeCase(id, tenantID string) *business.Case {
	now := time.Now().UTC().Truncate(time.Second)
	return &business.Case{
		ID:       id,
		TenantID: tenantID,
		Status:   business.CaseStatusOpen,
		Ticket: business.Ticket{
			Title:    business.TicketField{Value: "Endpoint outage", Source: business.TicketFieldSourceEmail, Filled: true},
			Client:   business.TicketField{Value: "acme-corp", Source: business.TicketFieldSourceCallerID, Filled: true},
			Contact:  business.TicketField{Value: "bob@acme-corp.example", Source: business.TicketFieldSourcePSA, Filled: true},
			Priority: business.TicketField{Value: "high", Source: business.TicketFieldSourceOperator, Filled: true},
			Category: business.TicketField{Value: "patch", Source: business.TicketFieldSourceInferred, Filled: false},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// TestCaseStore_RoundTrip creates a case with a ticket, two pins (one eid, one
// subject+time-range), and one content entry, then reads it back via GetCase and
// asserts every field survives including pin ref kind discrimination.
func TestCaseStore_RoundTrip(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeCase("case-rt-1", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	// Add two pins: one plain eid, one subject+time-range.
	pinEID := &business.Pin{
		ID:         "pin-eid-1",
		CaseID:     c.ID,
		Ref:        business.PinRef{Kind: business.PinRefKindEID, EID: "eid-abc-123"},
		Annotation: "suspicious process",
		Author:     "op@example.com",
		PinnedAt:   c.CreatedAt,
	}
	require.NoError(t, store.AddPin(ctx, c.ID, pinEID))

	rangeStart := c.CreatedAt.Add(-1 * time.Hour)
	rangeEnd := c.CreatedAt
	pinRange := &business.Pin{
		ID:     "pin-range-1",
		CaseID: c.ID,
		Ref: business.PinRef{
			Kind:           business.PinRefKindSubjectTimeRange,
			Subject:        "eid-subject-host",
			TimeRangeStart: rangeStart,
			TimeRangeEnd:   rangeEnd,
		},
		Annotation: "activity window",
		Author:     "op@example.com",
		PinnedAt:   c.CreatedAt,
	}
	require.NoError(t, store.AddPin(ctx, c.ID, pinRange))

	// Add one content entry.
	entry := &business.ContentEntry{
		ID:        "content-1",
		CaseID:    c.ID,
		Kind:      business.ContentKindFinding,
		Body:      "Process launched from unusual parent",
		Author:    "op@example.com",
		CreatedAt: c.CreatedAt,
	}
	require.NoError(t, store.AddContent(ctx, c.ID, entry))

	// Read back the full aggregate.
	got, err := store.GetCase(ctx, c.ID)
	require.NoError(t, err)

	assert.Equal(t, c.ID, got.ID)
	assert.Equal(t, c.TenantID, got.TenantID)
	assert.Equal(t, business.CaseStatusOpen, got.Status)

	// Ticket field round-trip.
	assert.Equal(t, "Endpoint outage", got.Ticket.Title.Value)
	assert.Equal(t, business.TicketFieldSourceEmail, got.Ticket.Title.Source)
	assert.True(t, got.Ticket.Title.Filled)
	assert.Equal(t, "acme-corp", got.Ticket.Client.Value)
	assert.Equal(t, business.TicketFieldSourceCallerID, got.Ticket.Client.Source)
	assert.Equal(t, "patch", got.Ticket.Category.Value)
	assert.Equal(t, business.TicketFieldSourceInferred, got.Ticket.Category.Source)
	assert.False(t, got.Ticket.Category.Filled)

	// Two pins in the aggregate.
	require.Len(t, got.Pins, 2)

	// Pin 1: eid kind.
	foundEID := false
	foundRange := false
	for _, p := range got.Pins {
		if p.ID == pinEID.ID {
			foundEID = true
			assert.Equal(t, business.PinRefKindEID, p.Ref.Kind)
			assert.Equal(t, "eid-abc-123", p.Ref.EID)
			assert.Empty(t, p.Ref.Subject)
			assert.True(t, p.Ref.TimeRangeStart.IsZero())
		}
		if p.ID == pinRange.ID {
			foundRange = true
			assert.Equal(t, business.PinRefKindSubjectTimeRange, p.Ref.Kind)
			assert.Equal(t, "eid-subject-host", p.Ref.Subject)
			assert.Empty(t, p.Ref.EID)
			assert.Equal(t, rangeStart.UTC(), p.Ref.TimeRangeStart.UTC())
			assert.Equal(t, rangeEnd.UTC(), p.Ref.TimeRangeEnd.UTC())
		}
	}
	assert.True(t, foundEID, "eid pin not found in aggregate")
	assert.True(t, foundRange, "subject+time-range pin not found in aggregate")

	// Content entry.
	require.Len(t, got.Content, 1)
	assert.Equal(t, entry.ID, got.Content[0].ID)
	assert.Equal(t, business.ContentKindFinding, got.Content[0].Kind)
	assert.Equal(t, "Process launched from unusual parent", got.Content[0].Body)
}

// TestCaseStore_ListCases_TenantIsolation proves a case in tenant B is absent
// from a ListCases call scoped to tenant A.
func TestCaseStore_ListCases_TenantIsolation(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	cA := makeCase("case-ta-1", "tenant-a")
	cB := makeCase("case-tb-1", "tenant-b")
	require.NoError(t, store.CreateCase(ctx, cA))
	require.NoError(t, store.CreateCase(ctx, cB))

	listA, err := store.ListCases(ctx, "tenant-a")
	require.NoError(t, err)
	require.Len(t, listA, 1)
	assert.Equal(t, cA.ID, listA[0].ID)

	listB, err := store.ListCases(ctx, "tenant-b")
	require.NoError(t, err)
	require.Len(t, listB, 1)
	assert.Equal(t, cB.ID, listB[0].ID)
}

// TestCaseStore_ListCases_Subtree proves a case in a descendant tenant
// (tenant-a/client-1) is included in a ListCases call scoped to the parent
// tenant (tenant-a), while a sibling tenant's case (tenant-ab) is not.
func TestCaseStore_ListCases_Subtree(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	cParent := makeCase("case-parent-1", "tenant-a")
	cChild := makeCase("case-child-1", "tenant-a/client-1")
	cSibling := makeCase("case-sibling-1", "tenant-ab")
	require.NoError(t, store.CreateCase(ctx, cParent))
	require.NoError(t, store.CreateCase(ctx, cChild))
	require.NoError(t, store.CreateCase(ctx, cSibling))

	list, err := store.ListCases(ctx, "tenant-a")
	require.NoError(t, err)
	ids := make([]string, 0, len(list))
	for _, c := range list {
		ids = append(ids, c.ID)
	}
	assert.ElementsMatch(t, []string{cParent.ID, cChild.ID}, ids,
		"parent-scoped list must include the descendant tenant's case and exclude the sibling tenant's case")
}

// TestCaseStore_GetCase_NotFound verifies ErrCaseNotFound is returned for missing IDs.
func TestCaseStore_GetCase_NotFound(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	_, err := store.GetCase(ctx, "does-not-exist")
	assert.ErrorIs(t, err, business.ErrCaseNotFound)
}

// TestCaseStore_UpdateCase updates case status and ticket, then verifies changes persist.
func TestCaseStore_UpdateCase(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeCase("case-upd-1", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	c.Status = business.CaseStatusClosed
	c.Ticket.Title = business.TicketField{
		Value:  "Updated title",
		Source: business.TicketFieldSourceOperator,
		Filled: true,
	}
	require.NoError(t, store.UpdateCase(ctx, c))

	got, err := store.GetCase(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, business.CaseStatusClosed, got.Status)
	assert.Equal(t, "Updated title", got.Ticket.Title.Value)
	assert.Equal(t, business.TicketFieldSourceOperator, got.Ticket.Title.Source)
}

// TestCaseStore_UpdateCase_NotFound verifies ErrCaseNotFound for a non-existent case.
func TestCaseStore_UpdateCase_NotFound(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeCase("no-such-case", "tenant-x")
	err := store.UpdateCase(ctx, c)
	assert.ErrorIs(t, err, business.ErrCaseNotFound)
}

// TestCaseStore_RemovePin verifies that removed pins are absent from ListPins.
func TestCaseStore_RemovePin(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeCase("case-rm-pin-1", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	pin := &business.Pin{
		ID:       "pin-to-remove",
		CaseID:   c.ID,
		Ref:      business.PinRef{Kind: business.PinRefKindEID, EID: "eid-xyz"},
		Author:   "op@example.com",
		PinnedAt: c.CreatedAt,
	}
	require.NoError(t, store.AddPin(ctx, c.ID, pin))

	pins, err := store.ListPins(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, pins, 1)

	require.NoError(t, store.RemovePin(ctx, c.ID, pin.ID))

	pins, err = store.ListPins(ctx, c.ID)
	require.NoError(t, err)
	assert.Empty(t, pins)
}

// TestCaseStore_RemovePin_NotFound verifies ErrPinNotFound for a non-existent pin.
func TestCaseStore_RemovePin_NotFound(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeCase("case-rm-pin-nf", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	err := store.RemovePin(ctx, c.ID, "no-such-pin")
	assert.ErrorIs(t, err, business.ErrPinNotFound)
}

// TestCaseStore_AllPinRefKinds verifies all five PinRefKinds round-trip correctly.
func TestCaseStore_AllPinRefKinds(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeCase("case-all-kinds", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	now := c.CreatedAt
	pins := []*business.Pin{
		{ID: "pk-eid", CaseID: c.ID, Ref: business.PinRef{Kind: business.PinRefKindEID, EID: "e1"}, Author: "a", PinnedAt: now},
		{ID: "pk-edge", CaseID: c.ID, Ref: business.PinRef{Kind: business.PinRefKindEdgeIdentity, EdgeIdentity: "edge-1"}, Author: "a", PinnedAt: now},
		{ID: "pk-obs", CaseID: c.ID, Ref: business.PinRef{Kind: business.PinRefKindObservationVersion, ObservationVersion: "obs-v1"}, Author: "a", PinnedAt: now},
		{ID: "pk-drift", CaseID: c.ID, Ref: business.PinRef{Kind: business.PinRefKindDriftRecord, DriftRecord: "drift-1"}, Author: "a", PinnedAt: now},
		{
			ID: "pk-range", CaseID: c.ID,
			Ref: business.PinRef{
				Kind:           business.PinRefKindSubjectTimeRange,
				Subject:        "subj-1",
				TimeRangeStart: now.Add(-time.Hour),
				TimeRangeEnd:   now,
			},
			Author: "a", PinnedAt: now,
		},
	}
	for _, p := range pins {
		require.NoError(t, store.AddPin(ctx, c.ID, p))
	}

	got, err := store.GetCase(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, got.Pins, 5)

	byID := make(map[string]*business.Pin, len(got.Pins))
	for _, p := range got.Pins {
		byID[p.ID] = p
	}

	assert.Equal(t, business.PinRefKindEID, byID["pk-eid"].Ref.Kind)
	assert.Equal(t, "e1", byID["pk-eid"].Ref.EID)

	assert.Equal(t, business.PinRefKindEdgeIdentity, byID["pk-edge"].Ref.Kind)
	assert.Equal(t, "edge-1", byID["pk-edge"].Ref.EdgeIdentity)

	assert.Equal(t, business.PinRefKindObservationVersion, byID["pk-obs"].Ref.Kind)
	assert.Equal(t, "obs-v1", byID["pk-obs"].Ref.ObservationVersion)

	assert.Equal(t, business.PinRefKindDriftRecord, byID["pk-drift"].Ref.Kind)
	assert.Equal(t, "drift-1", byID["pk-drift"].Ref.DriftRecord)

	assert.Equal(t, business.PinRefKindSubjectTimeRange, byID["pk-range"].Ref.Kind)
	assert.Equal(t, "subj-1", byID["pk-range"].Ref.Subject)
	assert.False(t, byID["pk-range"].Ref.TimeRangeStart.IsZero())
	assert.False(t, byID["pk-range"].Ref.TimeRangeEnd.IsZero())
}

// TestCaseStore_ContentKinds verifies all three ContentKinds round-trip correctly.
func TestCaseStore_ContentKinds(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeCase("case-content-kinds", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	entries := []*business.ContentEntry{
		{ID: "ce-finding", CaseID: c.ID, Kind: business.ContentKindFinding, Body: "finding body", Author: "a", CreatedAt: c.CreatedAt},
		{ID: "ce-transcript", CaseID: c.ID, Kind: business.ContentKindTranscriptEntry, Body: "transcript body", Author: "a", CreatedAt: c.CreatedAt},
		{ID: "ce-note", CaseID: c.ID, Kind: business.ContentKindNote, Body: "note body", Author: "a", CreatedAt: c.CreatedAt},
	}
	for _, e := range entries {
		require.NoError(t, store.AddContent(ctx, c.ID, e))
	}

	list, err := store.ListContent(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, list, 3)
	kindSet := make(map[business.ContentKind]bool)
	for _, e := range list {
		kindSet[e.Kind] = true
	}
	assert.True(t, kindSet[business.ContentKindFinding])
	assert.True(t, kindSet[business.ContentKindTranscriptEntry])
	assert.True(t, kindSet[business.ContentKindNote])
}

// TestCaseStore_ValidationErrors verifies nil/empty guard conditions.
func TestCaseStore_ValidationErrors(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	assert.Error(t, store.CreateCase(ctx, nil))
	assert.Error(t, store.CreateCase(ctx, &business.Case{TenantID: "t"})) // missing ID
	assert.Error(t, store.CreateCase(ctx, &business.Case{ID: "x"}))       // missing TenantID

	_, err := store.GetCase(ctx, "")
	assert.Error(t, err)

	assert.Error(t, store.AddPin(ctx, "", &business.Pin{ID: "p"}))
	assert.Error(t, store.AddPin(ctx, "case-1", nil))
	assert.Error(t, store.AddPin(ctx, "case-1", &business.Pin{})) // missing pin ID

	assert.Error(t, store.RemovePin(ctx, "", "pin-1"))
	assert.Error(t, store.RemovePin(ctx, "case-1", ""))

	assert.Error(t, store.AddContent(ctx, "", &business.ContentEntry{ID: "e"}))
	assert.Error(t, store.AddContent(ctx, "case-1", nil))
	assert.Error(t, store.AddContent(ctx, "case-1", &business.ContentEntry{})) // missing ID
}
