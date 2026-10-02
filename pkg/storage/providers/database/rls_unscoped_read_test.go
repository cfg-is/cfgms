// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// Regression coverage for Issue #3478.
//
// The RLS read policies on the tenant-scoped tables are documented as
// "permissive when app.current_tenant is not set (empty string), strict when
// set", and were implemented as:
//
//	current_setting('app.current_tenant', true) = ''
//	OR tenant_id = current_setting('app.current_tenant', true)
//
// `current_setting(<name>, true)` returns NULL — not '' — when the setting has
// never been applied in the session, so for an unscoped caller both branches
// evaluate to NULL and the row is filtered out. The permissive branch never
// fired and an unscoped read returned nothing.
//
// Two things make this hard to catch, and both are encoded in these tests:
//
//  1. **Superusers bypass RLS entirely**, even under FORCE ROW LEVEL SECURITY.
//     A test that connects as the owning/superuser role sees every row whether
//     the policy is correct or not, and passes against the bug. These tests
//     therefore create a dedicated non-superuser role and connect as it.
//
//  2. **The failure is connection-state dependent.** Once a connection has set
//     the GUC — even transaction-locally via set_config(..., true) —
//     current_setting() returns '' rather than NULL for the remainder of that
//     connection's life. A pooled connection that previously served a
//     tenant-scoped query reads correctly; a freshly-opened one reads nothing.
//     TestRLSUnscopedRead_FreshConnection therefore opens its own connection and
//     never sets the GUC on it, which is the case that actually regresses.

const (
	rlsTestRole     = "cfgms_rls_probe"
	rlsTestPassword = "cfgms_rls_probe_pw" // #nosec G101 -- throwaway role in a disposable test database
	rlsTenantA      = "rls3478-tenant-a"
	rlsTenantB      = "rls3478-tenant-b"
)

// rlsStewardID namespaces this file's rows so they cannot collide with, or be
// confused for, rows seeded by other tests sharing this database.
func rlsStewardID(tenant string) string { return "rls3478-steward-" + tenant }

// rlsSetupStewardRecords ensures the steward_records table exists with its RLS
// policies (via the production schema path), seeds one row per tenant, and
// grants the non-superuser probe role access. It returns a DSN for that role.
//
// Deliberately does NOT drop any tables. These tests share one database with the
// rest of the package, and dropping mid-suite breaks whichever neighbour runs
// next — measured: doing so failed TestDatabaseSessionTokenStore_SetUpdatesExistingEntry
// while this file's own tests passed. Every assertion below is therefore scoped
// to this file's own rows so pre-existing data cannot affect it.
func rlsSetupStewardRecords(t *testing.T, db *sql.DB) string {
	t.Helper()
	ctx := context.Background()

	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreateStewardRecordsTable(ctx, db),
		"steward_records table + RLS policies must be creatable")

	t.Cleanup(func() {
		for _, tenant := range []string{rlsTenantA, rlsTenantB} {
			_, _ = db.ExecContext(context.Background(),
				`DELETE FROM steward_records WHERE id = $1`, rlsStewardID(tenant))
		}
	})

	// Seed one row per tenant. Inserts must carry tenant context because the
	// write policy requires it — that is unchanged by this fix.
	for _, tenant := range []string{rlsTenantA, rlsTenantB} {
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenant)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO steward_records (id, tenant_id, hostname, platform, arch, version,
			                             ip_address, status, registered_at, last_seen)
			VALUES ($1, $2, '', '', '', '', '', 'active', NOW(), NOW())
			ON CONFLICT (id) DO NOTHING`, rlsStewardID(tenant), tenant)
		require.NoError(t, err)
		require.NoError(t, tx.Commit())
	}

	return provisionStewardRecordsProbeRole(t, db)
}

// provisionStewardRecordsProbeRole creates (or re-provisions) a dedicated
// non-superuser role that can read/write steward_records and returns a DSN for
// it. A non-superuser role is mandatory: superusers ignore RLS — even under
// FORCE ROW LEVEL SECURITY — so a superuser connection cannot distinguish the
// fixed policy from the broken one, or the enforced policy from an unenforced
// one.
//
// The role is granted USAGE on whatever schema steward_records actually
// resolves to under db's search_path, and its own search_path is pinned to
// match. This matters because test/sql/01-init-test-db.sql pins the test
// database's bootstrap role to a non-default search_path
// (`cfgms_test,public`) for its own isolation purposes, which — as an
// unqualified `CREATE TABLE IF NOT EXISTS` always targets the first schema on
// the creator's search_path — means steward_records lives in `cfgms_test`, not
// `public`, in that environment. A freshly created role defaults to
// `"$user",public` and cannot resolve the unqualified table name at all,
// producing "relation does not exist" rather than a permission error.
// Production carries no such override (lab-datasvc-bootstrap.sh creates the
// service role with no ALTER ROLE ... SET search_path), so this is a
// test-infrastructure artifact, not a production gap — but the probe role must
// still match whatever schema this test run's table actually landed in.
func provisionStewardRecordsProbeRole(t *testing.T, db *sql.DB) string {
	t.Helper()
	ctx := context.Background()

	var schemaName string
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT n.nspname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relname = 'steward_records'
		ORDER BY array_position(current_schemas(false), n.nspname)
		LIMIT 1`).Scan(&schemaName),
		"must resolve the schema steward_records actually lives in")
	schemaIdent := pq.QuoteIdentifier(schemaName)

	// Best-effort: a role left over from an interrupted prior run (or a
	// persisted test-database volume) may still hold grants that block
	// DROP ROLE with "cannot be dropped because some objects depend on it"
	// (2BP01). DROP OWNED BY strips every privilege the role holds in this
	// database — including the schema USAGE and table grants below — before
	// we try to drop it. Ignore the error: it fails with "role does not
	// exist" on a first-ever run, which is the common case.
	_, _ = db.ExecContext(ctx, fmt.Sprintf(`DROP OWNED BY %s`, rlsTestRole))

	cfg := getTestConfig()
	for _, stmt := range []string{
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rlsTestRole),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, rlsTestRole, rlsTestPassword),
		fmt.Sprintf(`ALTER ROLE %s SET search_path = %s, public`, rlsTestRole, schemaIdent),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA %s TO %s`, schemaIdent, rlsTestRole),
		fmt.Sprintf(`GRANT SELECT, INSERT ON steward_records TO %s`, rlsTestRole),
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Skipf("cannot provision a non-superuser probe role (needs CREATEROLE): %v", err)
		}
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_, _ = db.ExecContext(cleanupCtx, fmt.Sprintf(`DROP OWNED BY %s`, rlsTestRole))
		_, _ = db.ExecContext(cleanupCtx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rlsTestRole))
	})

	return fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg["host"], cfg["port"], cfg["database"], rlsTestRole, rlsTestPassword, cfg["sslmode"])
}

// rlsCountStewards opens a *new* connection with the given DSN, optionally sets
// app.current_tenant on it, and counts visible steward_records rows. Opening a
// fresh connection per call is essential — a reused connection that has already
// set the GUC reports an empty string instead of NULL and would mask the defect.
func rlsCountStewards(t *testing.T, dsn string, tenant *string) int {
	t.Helper()
	conn, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	// One underlying connection only, so the GUC state below is deterministic.
	conn.SetMaxOpenConns(1)
	require.NoError(t, conn.Ping())

	ctx := context.Background()
	if tenant != nil {
		_, err = conn.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, false)`, *tenant)
		require.NoError(t, err)
	}

	// Scoped to this file's own rows: RLS is applied before this predicate, so a
	// filtered count still distinguishes "policy hid everything" (0) from
	// "policy is permissive" (2) without depending on the rest of the database.
	var n int
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM steward_records WHERE id = ANY($1)`,
		pq.Array([]string{rlsStewardID(rlsTenantA), rlsStewardID(rlsTenantB)}),
	).Scan(&n))
	return n
}

// TestRLSUnscopedRead_FreshConnection is the regression guard: a caller that has
// never set app.current_tenant must read back every row, not zero.
//
// This is the case that broke the cfg-lab fleet. The ControlChannel admission
// check has no tenant context, so after any controller restart it could not find
// a single steward record and denied every steward — while the rows sat in the
// table the whole time (story #3096, runbook §6 finding F3).
func TestRLSUnscopedRead_FreshConnection(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	probeDSN := rlsSetupStewardRecords(t, db)

	got := rlsCountStewards(t, probeDSN, nil)
	require.Equal(t, 2, got,
		"a connection that never set app.current_tenant must see all rows; got %d. "+
			"Zero means the unscoped branch is comparing NULL to '' again (Issue #3478)", got)
}

// TestRLSUnscopedRead_ExplicitEmptyStringStillPermissive pins the behaviour the
// policy comments already promised, which was the only way to get a permissive
// read before the fix.
func TestRLSUnscopedRead_ExplicitEmptyStringStillPermissive(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	probeDSN := rlsSetupStewardRecords(t, db)

	empty := ""
	require.Equal(t, 2, rlsCountStewards(t, probeDSN, &empty),
		"an explicitly-empty app.current_tenant must remain permissive")
}

// TestRLSScopedRead_StillIsolatesTenants is the other half of the guarantee, and
// the reason this fix needs a test rather than just a migration: widening the
// unscoped branch must not widen the scoped one. A tenant-scoped caller must
// still see only its own rows.
func TestRLSScopedRead_StillIsolatesTenants(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	probeDSN := rlsSetupStewardRecords(t, db)

	for _, tenant := range []string{rlsTenantA, rlsTenantB} {
		scoped := tenant
		n := rlsCountStewards(t, probeDSN, &scoped)
		require.Equalf(t, 1, n,
			"tenant %q must see exactly its own row, got %d — tenant isolation regressed", tenant, n)
	}
}
