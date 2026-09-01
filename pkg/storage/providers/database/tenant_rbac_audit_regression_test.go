//go:build integration

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database — regression tests for three bugs found live while proving
// the Postgres storage/cluster path against a real database for the first
// time (Issue #3127): a tenant/role hierarchy no root/no-parent row could
// ever be created without violating its own self-referential foreign key,
// and an audit entry with no client IP could never be read back.
package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestDatabaseTenantStore_CreateDuplicate_ReturnsAlreadyExists guards against
// a regression where CreateTenant's Postgres unique-violation error was never
// translated to business.ErrTenantAlreadyExists, so callers that rely on the
// documented sentinel (e.g. the storage migrator's idempotent-retry fallback
// to UpdateTenant) silently broke: a second migration run against a
// partially-populated target failed outright instead of upserting.
func TestDatabaseTenantStore_CreateDuplicate_ReturnsAlreadyExists(t *testing.T) {
	store := newRegressionTenantStore(t)
	ctx := context.Background()

	tenant := &business.TenantData{
		ID:        "dup-tenant",
		Name:      "Original",
		Status:    business.TenantStatusActive,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, store.CreateTenant(ctx, tenant))

	err := store.CreateTenant(ctx, tenant)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrTenantAlreadyExists,
		"a duplicate CreateTenant must return the documented sentinel so callers can fall back to UpdateTenant")
}

// TestDatabaseTenantStore_MissingTenantContract holds the Postgres provider to the
// shared missing-tenant sentinel contract. This provider phrases the condition
// differently from SQLite, which is exactly why callers must classify with errors.Is:
// the tenant API handlers previously matched the message text, so on Postgres a
// missing tenant produced 500 while an out-of-scope tenant produced 404 — a status
// split that disclosed the existence of tenants outside the caller's subtree.
func TestDatabaseTenantStore_MissingTenantContract(t *testing.T) {
	business.TenantStoreMissingTenantContract(t, newRegressionTenantStore(t))
}

// TestDatabaseTenantStore_LifecycleContract holds the Postgres provider to the
// shared suspension provenance persistence contract (ADR-027 Decision 2, Issue #3158).
func TestDatabaseTenantStore_LifecycleContract(t *testing.T) {
	business.TenantStoreLifecycleContract(t, newRegressionTenantStore(t))
}

// TestDatabaseRBACStore_StoreRole_NoParent guards against a regression where
// an empty ParentRoleId was inserted as a literal empty string instead of
// NULL. parent_role_id has a self-referential foreign key, so every
// top-level role (the overwhelming majority — most roles have no parent)
// violated it and could never be stored against real Postgres.
func TestDatabaseRBACStore_StoreRole_NoParent(t *testing.T) {
	store := newTestRBACStore(t)
	ctx := context.Background()

	role := &common.Role{
		Id:           "top-level-role",
		Name:         "Top Level",
		IsSystemRole: true,
		// ParentRoleId intentionally left empty — the common case.
	}
	require.NoError(t, store.StoreRole(ctx, role))

	got, err := store.GetRole(ctx, "top-level-role")
	require.NoError(t, err)
	assert.Empty(t, got.ParentRoleId)
}

// TestDatabaseRBACStore_StoreRole_WithParent covers the non-empty case so the
// nullStringOrEmpty conversion is exercised in both directions.
func TestDatabaseRBACStore_StoreRole_WithParent(t *testing.T) {
	store := newTestRBACStore(t)
	ctx := context.Background()

	require.NoError(t, store.StoreRole(ctx, &common.Role{
		Id:           "parent-role",
		Name:         "Parent",
		IsSystemRole: true,
	}))
	require.NoError(t, store.StoreRole(ctx, &common.Role{
		Id:           "child-role",
		Name:         "Child",
		IsSystemRole: true,
		ParentRoleId: "parent-role",
	}))

	got, err := store.GetRole(ctx, "child-role")
	require.NoError(t, err)
	assert.Equal(t, "parent-role", got.ParentRoleId)
}

// TestDatabaseAuditStore_GetAuditEntry_NoIPAddress guards against a
// regression where scanning a NULL ip_address column into net.IP (which has
// no sql.Scanner) failed the whole Scan() call. This silently defeated the
// storage migrator's idempotent existence-check-before-insert (GetAuditEntry
// returning a real error, not business.ErrAuditNotFound, for any entry
// without a client IP — i.e. every internal/system-generated entry), so a
// re-run of the migration hit a duplicate-key error on the very next retry.
func TestDatabaseAuditStore_GetAuditEntry_NoIPAddress(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	entry := &business.AuditEntry{
		ID:           "no-ip-entry",
		TenantID:     "tenant-audit",
		Timestamp:    time.Now().UTC().Truncate(time.Millisecond),
		EventType:    business.AuditEventAuthentication,
		Action:       "controller-stop",
		UserID:       "system",
		UserType:     business.AuditUserTypeSystem,
		ResourceType: "controller",
		ResourceID:   "cfgms-ctrl-01",
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityLow,
		Source:       "controller",
		// IPAddress intentionally left empty — no client IP for a
		// system-generated entry.
	}
	require.NoError(t, store.StoreAuditEntry(ctx, entry))

	got, err := store.GetAuditEntry(ctx, "no-ip-entry")
	require.NoError(t, err, "GetAuditEntry must not fail scanning a NULL ip_address column")
	require.NotNil(t, got)
	assert.Empty(t, got.IPAddress)
}

// ── factory helpers ─────────────────────────────────────────────────────────

// newRegressionTenantStore returns a bare DatabaseTenantStore for the regression suite.
// Named distinctly from tenant_pending_deletion_test.go's newTestTenantStore: this file is
// //go:build integration and that one is untagged, so identical names compiled together
// under -tags=integration (the tag `make test-integration-db` passes) and broke the build.
func newRegressionTenantStore(t *testing.T) *DatabaseTenantStore {
	t.Helper()
	db := getTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseTenantStore(db, getTestConfig())
	require.NoError(t, err)
	return store
}

func newTestRBACStore(t *testing.T) *DatabaseRBACStore {
	t.Helper()
	db := getTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseRBACStore(db, getTestConfig())
	require.NoError(t, err)
	return store
}

func newTestAuditStore(t *testing.T) *DatabaseAuditStore {
	t.Helper()
	db := getTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseAuditStore(db, getTestConfig())
	require.NoError(t, err)
	return store
}
