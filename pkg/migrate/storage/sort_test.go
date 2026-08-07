// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import "testing"

type parentFirstItem struct {
	id, parent string
}

// TestSortParentFirst guards against a regression where tenant/RBAC-role
// import order was whatever the source store's List* call happened to
// return (e.g. the flatfile provider's directory-read order), which is not
// guaranteed to place a parent before its child. Importing a child before
// its parent violates the target's self-referential foreign key
// (cfgms_tenants_parent_id_fkey / rbac_roles_parent_role_id_fkey) — found
// live migrating the Tier-1 controller onto Postgres (#3127).
func TestSortParentFirst(t *testing.T) {
	id := func(i parentFirstItem) string { return i.id }
	parent := func(i parentFirstItem) string { return i.parent }

	t.Run("reversed order", func(t *testing.T) {
		items := []parentFirstItem{
			{id: "grandchild", parent: "child"},
			{id: "child", parent: "root"},
			{id: "root", parent: ""},
		}
		sorted, err := sortParentFirst(items, id, parent)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertBefore(t, sorted, id, "root", "child")
		assertBefore(t, sorted, id, "child", "grandchild")
	})

	t.Run("already ordered", func(t *testing.T) {
		items := []parentFirstItem{
			{id: "root", parent: ""},
			{id: "child", parent: "root"},
		}
		sorted, err := sortParentFirst(items, id, parent)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertBefore(t, sorted, id, "root", "child")
	})

	t.Run("multiple roots and siblings", func(t *testing.T) {
		items := []parentFirstItem{
			{id: "b-child", parent: "b-root"},
			{id: "a-child", parent: "a-root"},
			{id: "a-root", parent: ""},
			{id: "b-root", parent: ""},
		}
		sorted, err := sortParentFirst(items, id, parent)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sorted) != 4 {
			t.Fatalf("expected 4 items, got %d", len(sorted))
		}
		assertBefore(t, sorted, id, "a-root", "a-child")
		assertBefore(t, sorted, id, "b-root", "b-child")
	})

	t.Run("parent outside the batch is treated as already present", func(t *testing.T) {
		// e.g. a partial/incremental migration where the parent was
		// imported in an earlier run and isn't part of this export.
		items := []parentFirstItem{
			{id: "child", parent: "elsewhere"},
		}
		sorted, err := sortParentFirst(items, id, parent)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sorted) != 1 || sorted[0].id != "child" {
			t.Fatalf("expected [child], got %v", sorted)
		}
	})

	t.Run("cycle returns an error instead of infinite looping", func(t *testing.T) {
		items := []parentFirstItem{
			{id: "a", parent: "b"},
			{id: "b", parent: "a"},
		}
		_, err := sortParentFirst(items, id, parent)
		if err == nil {
			t.Fatal("expected an error for a parent cycle, got nil")
		}
	})
}

func assertBefore(t *testing.T, sorted []parentFirstItem, id func(parentFirstItem) string, before, after string) {
	t.Helper()
	beforeIdx, afterIdx := -1, -1
	for i, item := range sorted {
		switch id(item) {
		case before:
			beforeIdx = i
		case after:
			afterIdx = i
		}
	}
	if beforeIdx == -1 || afterIdx == -1 {
		t.Fatalf("expected both %q and %q in sorted output %v", before, after, sorted)
	}
	if beforeIdx >= afterIdx {
		t.Fatalf("expected %q (index %d) before %q (index %d)", before, beforeIdx, after, afterIdx)
	}
}
