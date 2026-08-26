// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for DatabaseCaseStore (ADR-022 §8, Issue #3602).
package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestCaseStore(t *testing.T) *DatabaseCaseStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	require.NoError(t, NewDatabaseSchemas().CreateCaseTables(ctx, db))

	store, err := NewDatabaseCaseStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func makeDBCase(id, tenantID string) *business.Case {
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

// TestDatabaseCaseStore_RoundTrip creates a case with a ticket, two pins (one eid,
// one subject+time-range), and one content entry; reads back via GetCase and asserts
// every field survives including pin ref kind discrimination.
func TestDatabaseCaseStore_RoundTrip(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeDBCase("db-case-rt-1", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	// Two pins: one plain eid, one subject+time-range.
	pinEID := &business.Pin{
		ID:         "db-pin-eid-1",
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
		ID:     "db-pin-range-1",
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

	// One content entry.
	entry := &business.ContentEntry{
		ID:        "db-content-1",
		CaseID:    c.ID,
		Kind:      business.ContentKindFinding,
		Body:      "Process launched from unusual parent",
		Author:    "op@example.com",
		CreatedAt: c.CreatedAt,
	}
	require.NoError(t, store.AddContent(ctx, c.ID, entry))

	got, err := store.GetCase(ctx, c.ID)
	require.NoError(t, err)

	assert.Equal(t, c.ID, got.ID)
	assert.Equal(t, c.TenantID, got.TenantID)
	assert.Equal(t, business.CaseStatusOpen, got.Status)

	// Ticket round-trip.
	assert.Equal(t, "Endpoint outage", got.Ticket.Title.Value)
	assert.Equal(t, business.TicketFieldSourceEmail, got.Ticket.Title.Source)
	assert.True(t, got.Ticket.Title.Filled)
	assert.Equal(t, "patch", got.Ticket.Category.Value)
	assert.Equal(t, business.TicketFieldSourceInferred, got.Ticket.Category.Source)
	assert.False(t, got.Ticket.Category.Filled)

	// Two pins.
	require.Len(t, got.Pins, 2)
	foundEID, foundRange := false, false
	for _, p := range got.Pins {
		if p.ID == pinEID.ID {
			foundEID = true
			assert.Equal(t, business.PinRefKindEID, p.Ref.Kind)
			assert.Equal(t, "eid-abc-123", p.Ref.EID)
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

// TestDatabaseCaseStore_ListCases_TenantIsolation proves a case in tenant B is
// absent from a ListCases call scoped to tenant A.
func TestDatabaseCaseStore_ListCases_TenantIsolation(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	cA := makeDBCase("db-case-ta-1", "tenant-a")
	cB := makeDBCase("db-case-tb-1", "tenant-b")
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

// TestDatabaseCaseStore_ListCases_Subtree proves a case in a descendant tenant
// (tenant-a/client-1) is included in a ListCases call scoped to the parent
// tenant (tenant-a), while a sibling tenant's case (tenant-ab) is not.
func TestDatabaseCaseStore_ListCases_Subtree(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	cParent := makeDBCase("db-case-parent-1", "tenant-a")
	cChild := makeDBCase("db-case-child-1", "tenant-a/client-1")
	cSibling := makeDBCase("db-case-sibling-1", "tenant-ab")
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

// TestDatabaseCaseStore_GetCase_NotFound verifies ErrCaseNotFound for missing IDs.
func TestDatabaseCaseStore_GetCase_NotFound(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	_, err := store.GetCase(ctx, "does-not-exist")
	assert.ErrorIs(t, err, business.ErrCaseNotFound)
}

// TestDatabaseCaseStore_UpdateCase verifies status and ticket changes persist.
func TestDatabaseCaseStore_UpdateCase(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeDBCase("db-case-upd-1", "tenant-a")
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
}

// TestDatabaseCaseStore_UpdateCase_NotFound verifies that updating a case that was
// never created reports ErrCaseNotFound rather than succeeding silently — the
// UPDATE affects zero rows and must not be mistaken for a successful write.
func TestDatabaseCaseStore_UpdateCase_NotFound(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeDBCase("db-case-no-such", "tenant-x")
	err := store.UpdateCase(ctx, c)
	assert.ErrorIs(t, err, business.ErrCaseNotFound)
}

// TestDatabaseCaseStore_RemovePin verifies pins are deleted via RemovePin.
func TestDatabaseCaseStore_RemovePin(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeDBCase("db-case-rm-pin", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	pin := &business.Pin{
		ID:       "db-pin-remove",
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

// TestDatabaseCaseStore_RemovePin_NotFound verifies ErrPinNotFound.
func TestDatabaseCaseStore_RemovePin_NotFound(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	c := makeDBCase("db-case-rm-nf", "tenant-a")
	require.NoError(t, store.CreateCase(ctx, c))

	err := store.RemovePin(ctx, c.ID, "no-such-pin")
	assert.ErrorIs(t, err, business.ErrPinNotFound)
}

// TestDatabaseCaseStore_ValidationErrors verifies nil/empty guard conditions.
func TestDatabaseCaseStore_ValidationErrors(t *testing.T) {
	store := newTestCaseStore(t)
	ctx := context.Background()

	assert.Error(t, store.CreateCase(ctx, nil))
	assert.Error(t, store.CreateCase(ctx, &business.Case{TenantID: "t"}))
	assert.Error(t, store.CreateCase(ctx, &business.Case{ID: "x"}))

	_, err := store.GetCase(ctx, "")
	assert.Error(t, err)

	assert.Error(t, store.AddPin(ctx, "", &business.Pin{ID: "p"}))
	assert.Error(t, store.AddPin(ctx, "case-1", nil))
	assert.Error(t, store.AddPin(ctx, "case-1", &business.Pin{}))

	assert.Error(t, store.RemovePin(ctx, "", "pin-1"))
	assert.Error(t, store.RemovePin(ctx, "case-1", ""))

	assert.Error(t, store.AddContent(ctx, "", &business.ContentEntry{ID: "e"}))
	assert.Error(t, store.AddContent(ctx, "case-1", nil))
	assert.Error(t, store.AddContent(ctx, "case-1", &business.ContentEntry{}))
}
