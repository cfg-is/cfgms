// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// Issue #4321: rls_update and rls_delete on sessions, steward_records,
// command_records, and session_token_store carried no tenant predicate
// (`USING (TRUE)`), so any tenant-scoped session could UPDATE or DELETE another
// tenant's row at the database layer -- the write-side half of the tenant
// isolation guarantee rls_read (Issue #3478) already enforces on SELECT. This
// file pins the fix with real-Postgres, non-superuser-role tests.
//
// A superuser bypasses row-level security unconditionally, even under FORCE ROW
// LEVEL SECURITY. Per stores_integration_test.go, the shared test role
// (cfgms_test) IS the Postgres bootstrap superuser in this environment, so --
// exactly as rls_unscoped_read_test.go already established for reads -- these
// tests connect as a dedicated, unprivileged role or they pass against the bug.

const (
	rlsWriteProbeRole     = "cfgms_rls_write_probe"
	rlsWriteProbePassword = "cfgms_rls_write_probe_pw" // #nosec G101 -- throwaway role in a disposable test database
	rlsWriteTenantA       = "rls4321-tenant-a"
	rlsWriteTenantB       = "rls4321-tenant-b"
)

// provisionRLSWriteProbeRole creates (or re-provisions) a dedicated non-superuser
// role with SELECT/UPDATE/DELETE on the given tables and returns a DSN for it.
// Kept separate from provisionStewardRecordsProbeRole in rls_unscoped_read_test.go:
// that helper only grants SELECT/INSERT on one table, and this story needs
// UPDATE/DELETE across four.
func provisionRLSWriteProbeRole(t *testing.T, db *sql.DB, tables []string) string {
	t.Helper()
	ctx := context.Background()

	// Best-effort: strip privileges left by an interrupted prior run before
	// dropping the role, mirroring provisionStewardRecordsProbeRole.
	_, _ = db.ExecContext(ctx, fmt.Sprintf(`DROP OWNED BY %s`, rlsWriteProbeRole))

	cfg := getTestConfig()
	setup := []string{
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rlsWriteProbeRole),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, rlsWriteProbeRole, rlsWriteProbePassword),
	}
	for _, stmt := range setup {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Skipf("cannot provision a non-superuser probe role (needs CREATEROLE): %v", err)
		}
	}

	seenSchemas := map[string]bool{}
	for _, table := range tables {
		var schemaName string
		require.NoError(t, db.QueryRowContext(ctx, `
			SELECT n.nspname FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relname = $1
			ORDER BY array_position(current_schemas(false), n.nspname)
			LIMIT 1`, table).Scan(&schemaName),
			"must resolve the schema %q actually lives in", table)

		if !seenSchemas[schemaName] {
			seenSchemas[schemaName] = true
			schemaIdent := pq.QuoteIdentifier(schemaName)
			for _, stmt := range []string{
				fmt.Sprintf(`ALTER ROLE %s SET search_path = %s, public`, rlsWriteProbeRole, schemaIdent),
				fmt.Sprintf(`GRANT USAGE ON SCHEMA %s TO %s`, schemaIdent, rlsWriteProbeRole),
			} {
				if _, err := db.ExecContext(ctx, stmt); err != nil {
					t.Skipf("cannot configure probe role schema access: %v", err)
				}
			}
		}

		grant := fmt.Sprintf(`GRANT SELECT, UPDATE, DELETE ON %s TO %s`, pq.QuoteIdentifier(table), rlsWriteProbeRole)
		if _, err := db.ExecContext(ctx, grant); err != nil {
			t.Skipf("cannot grant probe role access to %s: %v", table, err)
		}
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_, _ = db.ExecContext(cleanupCtx, fmt.Sprintf(`DROP OWNED BY %s`, rlsWriteProbeRole))
		_, _ = db.ExecContext(cleanupCtx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rlsWriteProbeRole))
	})

	return fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cfg["host"], cfg["port"], cfg["database"], rlsWriteProbeRole, rlsWriteProbePassword, cfg["sslmode"])
}

// rlsWriteExecAsTenant opens a fresh connection, sets app.current_tenant to tenant,
// and executes query. A fresh connection per call matters here exactly as it does in
// rlsCountStewards (rls_unscoped_read_test.go): once a connection has set the GUC,
// current_setting() behaves differently for the rest of that connection's life.
//
// It pins a single physical backend via pool.Conn rather than relying on
// SetMaxOpenConns(1): that cap keeps the pool from ever holding two connections at
// once, but does not stop database/sql from transparently discarding and replacing
// a connection it judges bad and opening a fresh one for the next call -- which
// would silently reset this session-scoped GUC. Conn pins the exact backend for its
// whole lifetime, which set_config's session scope requires.
func rlsWriteExecAsTenant(t *testing.T, dsn, tenant, query string, args ...interface{}) (sql.Result, error) {
	t.Helper()
	pool, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	conn, err := pool.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, err = conn.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, false)`, tenant)
	require.NoError(t, err)

	return conn.ExecContext(ctx, query, args...)
}

// rlsWriteExecAsTenantWithMoveAuthorized mirrors what UpdateStewardTenant
// (steward_store.go) does before its own UPDATE: both GUCs set transaction-local
// (is_local=true) inside an explicit transaction that also runs the UPDATE, on a
// single pinned connection (see rlsWriteExecAsTenant's comment on why pinning
// matters). Used to prove steward_records' rls_update WITH CHECK exception is
// reachable only through the flag, not merely by being steward_records.
func rlsWriteExecAsTenantWithMoveAuthorized(t *testing.T, dsn, tenant, query string, args ...interface{}) (sql.Result, error) {
	t.Helper()
	pool, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	conn, err := pool.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenant)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_move_authorized', 'true', true)`)
	require.NoError(t, err)

	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return res, err
	}
	return res, tx.Commit()
}

// ── sessions ─────────────────────────────────────────────────────────────────

func rlsSeedSession(t *testing.T, db *sql.DB, hash, tenant string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO sessions (session_id_hash, user_id, tenant_id, session_type,
			created_at, last_activity, expires_at, status)
		VALUES ($1, 'rls4321-probe-user', $2, 'admin', $3, $3, $4, 'active')
		ON CONFLICT (session_id_hash) DO NOTHING`,
		hash, tenant, now, now.Add(time.Hour))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM sessions WHERE session_id_hash = $1`, hash)
	})
}

func TestRLSWritePolicy_Sessions(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	require.NoError(t, NewDatabaseSchemas().CreateSessionsTable(context.Background(), db))

	hashA := "rls4321-session-" + rlsWriteTenantA
	hashB := "rls4321-session-" + rlsWriteTenantB
	rlsSeedSession(t, db, hashA, rlsWriteTenantA)
	rlsSeedSession(t, db, hashB, rlsWriteTenantB)

	dsn := provisionRLSWriteProbeRole(t, db, []string{"sessions"})

	t.Run("UpdateCrossTenant_ZeroRows", func(t *testing.T) {
		res, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`UPDATE sessions SET status = 'revoked' WHERE session_id_hash = $1`, hashB)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "tenant A must not be able to update tenant B's session")
	})

	t.Run("DeleteCrossTenant_ZeroRows", func(t *testing.T) {
		res, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`DELETE FROM sessions WHERE session_id_hash = $1`, hashB)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "tenant A must not be able to delete tenant B's session")
	})

	t.Run("UpdateMoveToOtherTenant_Refused", func(t *testing.T) {
		_, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`UPDATE sessions SET tenant_id = $1 WHERE session_id_hash = $2`, rlsWriteTenantB, hashA)
		require.Error(t, err, "moving a session to a different tenant must be refused by WITH CHECK")
	})
}

// ── steward_records ───────────────────────────────────────────────────────────

func rlsSeedStewardRecord(t *testing.T, db *sql.DB, id, tenant string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO steward_records (id, tenant_id, status, registered_at, last_seen)
		VALUES ($1, $2, 'active', $3, $3)
		ON CONFLICT (id) DO NOTHING`,
		id, tenant, now)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM steward_records WHERE id = $1`, id)
	})
}

func TestRLSWritePolicy_StewardRecords(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	require.NoError(t, NewDatabaseSchemas().CreateStewardRecordsTable(context.Background(), db))

	idA := "rls4321-steward-" + rlsWriteTenantA
	idB := "rls4321-steward-" + rlsWriteTenantB
	rlsSeedStewardRecord(t, db, idA, rlsWriteTenantA)
	rlsSeedStewardRecord(t, db, idB, rlsWriteTenantB)

	dsn := provisionRLSWriteProbeRole(t, db, []string{"steward_records"})

	t.Run("UpdateCrossTenant_ZeroRows", func(t *testing.T) {
		res, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`UPDATE steward_records SET status = 'deregistered' WHERE id = $1`, idB)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "tenant A must not be able to update tenant B's steward record")
	})

	t.Run("DeleteCrossTenant_ZeroRows", func(t *testing.T) {
		res, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`DELETE FROM steward_records WHERE id = $1`, idB)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "tenant A must not be able to delete tenant B's steward record")
	})
}

// TestRLSWritePolicy_StewardRecordsTenantMove_IntentionallyAllowed pins a
// deliberate, narrow exception to the "no cross-tenant move" rule enforced on the
// other three tables. UpdateStewardTenant (steward_store.go) is a real product
// feature -- moving a steward between tenants -- gated at the Go/API layer
// (handlers_stewards.go's handleMoveSteward requires a root caller or a scoped
// admin whose scope covers BOTH the source and destination tenant), not by an
// unauthenticated raw SQL client. A strict WITH CHECK, as used on
// sessions/command_records/session_token_store, would make that feature
// impossible: USING and a plain tenant-scoped WITH CHECK read the same
// current_setting('app.current_tenant') value within one statement, so no
// tenant-scoped session could ever produce a row whose tenant_id differs from its
// own. steward_records' rls_update therefore additionally accepts a row moving
// tenant when the transaction-local app.tenant_move_authorized flag is 'true' --
// USING still requires the targeted row belong to the caller's own tenant (pinned
// above by UpdateCrossTenant_ZeroRows), and WITH CHECK requires that flag to accept
// a different resulting tenant_id. This test exists so a future reader who removes
// the flag check here -- reasonably, by analogy with the other three tables --
// finds a failing test pointing back at UpdateStewardTenant instead of silently
// breaking it. See TestRLSWritePolicy_StewardRecordsTenantMove_UnauthorizedRefused
// for the companion case: the same move, without the flag, is refused.
func TestRLSWritePolicy_StewardRecordsTenantMove_IntentionallyAllowed(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	require.NoError(t, NewDatabaseSchemas().CreateStewardRecordsTable(context.Background(), db))

	id := "rls4321-steward-move-" + rlsWriteTenantA
	rlsSeedStewardRecord(t, db, id, rlsWriteTenantA)

	dsn := provisionRLSWriteProbeRole(t, db, []string{"steward_records"})

	res, err := rlsWriteExecAsTenantWithMoveAuthorized(t, dsn, rlsWriteTenantA,
		`UPDATE steward_records SET tenant_id = $1 WHERE id = $2 AND tenant_id = $3`,
		rlsWriteTenantB, id, rlsWriteTenantA)
	require.NoError(t, err, "steward_records must allow a tenant-scoped, CAS-guarded move like UpdateStewardTenant")
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	var gotTenant string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT tenant_id FROM steward_records WHERE id = $1`, id).Scan(&gotTenant))
	require.Equal(t, rlsWriteTenantB, gotTenant)
}

// TestRLSWritePolicy_StewardRecordsTenantMove_UnauthorizedRefused is the companion
// to the IntentionallyAllowed test above and the acceptance-review remedy for
// PR #4361: the identical cross-tenant move, issued by a session that never sets
// app.tenant_move_authorized -- i.e. any raw SQL client or compromised session that
// is not going through UpdateStewardTenant -- must be refused by WITH CHECK. This is
// what closes the AC-5 gap the acceptance reviewer flagged: "an UPDATE that would
// move a row to tenant B is refused" now holds for steward_records too, with the one
// documented, narrowly-flagged exception pinned by the test above.
func TestRLSWritePolicy_StewardRecordsTenantMove_UnauthorizedRefused(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	require.NoError(t, NewDatabaseSchemas().CreateStewardRecordsTable(context.Background(), db))

	id := "rls4321-steward-move-refused-" + rlsWriteTenantA
	rlsSeedStewardRecord(t, db, id, rlsWriteTenantA)

	dsn := provisionRLSWriteProbeRole(t, db, []string{"steward_records"})

	_, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
		`UPDATE steward_records SET tenant_id = $1 WHERE id = $2 AND tenant_id = $3`,
		rlsWriteTenantB, id, rlsWriteTenantA)
	require.Error(t, err, "moving a steward_records row to a different tenant without app.tenant_move_authorized must be refused by WITH CHECK")

	var gotTenant string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT tenant_id FROM steward_records WHERE id = $1`, id).Scan(&gotTenant))
	require.Equal(t, rlsWriteTenantA, gotTenant, "the row must not have moved")
}

// ── command_records ──────────────────────────────────────────────────────────

func rlsSeedCommandRecord(t *testing.T, db *sql.DB, id, tenant string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO command_records (id, type, steward_id, tenant_id, status, issued_at)
		VALUES ($1, 'rls4321-probe', 'rls4321-probe-steward', $2, 'pending', $3)
		ON CONFLICT (id) DO NOTHING`,
		id, tenant, now)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM command_records WHERE id = $1`, id)
	})
}

func TestRLSWritePolicy_CommandRecords(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	require.NoError(t, NewDatabaseSchemas().CreateCommandRecordsTable(context.Background(), db))

	idA := "rls4321-command-" + rlsWriteTenantA
	idB := "rls4321-command-" + rlsWriteTenantB
	rlsSeedCommandRecord(t, db, idA, rlsWriteTenantA)
	rlsSeedCommandRecord(t, db, idB, rlsWriteTenantB)

	dsn := provisionRLSWriteProbeRole(t, db, []string{"command_records"})

	t.Run("UpdateCrossTenant_ZeroRows", func(t *testing.T) {
		res, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`UPDATE command_records SET status = 'cancelled' WHERE id = $1`, idB)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "tenant A must not be able to update tenant B's command record")
	})

	t.Run("DeleteCrossTenant_ZeroRows", func(t *testing.T) {
		res, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`DELETE FROM command_records WHERE id = $1`, idB)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "tenant A must not be able to delete tenant B's command record")
	})

	t.Run("UpdateMoveToOtherTenant_Refused", func(t *testing.T) {
		_, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`UPDATE command_records SET tenant_id = $1 WHERE id = $2`, rlsWriteTenantB, idA)
		require.Error(t, err, "moving a command record to a different tenant must be refused by WITH CHECK")
	})
}

// ── session_token_store ──────────────────────────────────────────────────────

func rlsSeedSessionToken(t *testing.T, db *sql.DB, hash, tenant string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO session_token_store (token_hash, session_id, principal_id, connection_name,
			tenant_id, issued_at, last_activity, absolute_expires_at)
		VALUES ($1, $1, 'rls4321-probe-principal', 'rls4321-probe-conn', $2, $3, $3, $4)
		ON CONFLICT (token_hash) DO NOTHING`,
		hash, tenant, now, now.Add(time.Hour))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM session_token_store WHERE token_hash = $1`, hash)
	})
}

func TestRLSWritePolicy_SessionTokenStore(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	require.NoError(t, NewDatabaseSchemas().CreateSessionTokenStoreTable(context.Background(), db))

	hashA := "rls4321-token-" + rlsWriteTenantA
	hashB := "rls4321-token-" + rlsWriteTenantB
	rlsSeedSessionToken(t, db, hashA, rlsWriteTenantA)
	rlsSeedSessionToken(t, db, hashB, rlsWriteTenantB)

	dsn := provisionRLSWriteProbeRole(t, db, []string{"session_token_store"})

	t.Run("UpdateCrossTenant_ZeroRows", func(t *testing.T) {
		res, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`UPDATE session_token_store SET hash_expires_at = NOW() WHERE token_hash = $1`, hashB)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "tenant A must not be able to update tenant B's session token")
	})

	t.Run("DeleteCrossTenant_ZeroRows", func(t *testing.T) {
		res, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`DELETE FROM session_token_store WHERE token_hash = $1`, hashB)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "tenant A must not be able to delete tenant B's session token")
	})

	t.Run("UpdateMoveToOtherTenant_Refused", func(t *testing.T) {
		_, err := rlsWriteExecAsTenant(t, dsn, rlsWriteTenantA,
			`UPDATE session_token_store SET tenant_id = $1 WHERE token_hash = $2`, rlsWriteTenantB, hashA)
		require.Error(t, err, "moving a session token to a different tenant must be refused by WITH CHECK")
	})
}

// ── rbac_roles (migration 003) ───────────────────────────────────────────────

// TestRLSAdminOverride_RBACRoles pins the migration-003 fix: FORCE ROW LEVEL
// SECURITY on rbac_roles, and the role-membership check that constrains
// admin_override_policy from an open bypass to one only a role explicitly granted
// membership in cfgms_rls_admin_override can trigger.
//
// schemas.go does not provision RLS for rbac_roles -- RBAC durable storage does
// not route through RLS on the live provisioning path today, and adding that is
// out of this story's scope (see Issue #4321's Out of Scope: "Adding row-level
// security to tables that do not have it today"). This test applies the same
// DDL migrations/003_enable_rls.sql declares directly, so it exercises the
// shipped policy text rather than a paraphrase of it.
// rlsSeedRBACRole inserts a tenant-scoped rbac_roles row as the (superuser) test
// role, which bypasses RLS, so the row exists regardless of policy. is_system_role
// is deliberately false: tenant_isolation_policy admits system roles into every
// tenant, so a system row could not distinguish a working admin-override gate from
// an open one.
func rlsSeedRBACRole(t *testing.T, db *sql.DB, id, tenant string) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO rbac_roles (id, name, is_system_role, tenant_id)
		VALUES ($1, $1, false, $2)
		ON CONFLICT (id) DO NOTHING`, id, tenant)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM rbac_roles WHERE id = $1`, id)
	})
}

func TestRLSAdminOverride_RBACRoles(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	require.NoError(t, NewDatabaseSchemas().CreateRBACTables(ctx, db))

	rlsStmts := []string{
		`ALTER TABLE IF EXISTS rbac_roles ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE IF EXISTS rbac_roles FORCE ROW LEVEL SECURITY`,
		`DROP POLICY IF EXISTS tenant_isolation_policy ON rbac_roles`,
		`CREATE POLICY tenant_isolation_policy ON rbac_roles
			USING (is_system_role = true OR tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (is_system_role = true OR tenant_id = current_setting('app.current_tenant', true))`,
		`DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cfgms_rls_admin_override') THEN
				CREATE ROLE cfgms_rls_admin_override NOLOGIN;
			END IF;
		END
		$$`,
		`DROP POLICY IF EXISTS admin_override_policy ON rbac_roles`,
		`CREATE POLICY admin_override_policy ON rbac_roles
			USING (pg_has_role(current_user, 'cfgms_rls_admin_override', 'MEMBER'))
			WITH CHECK (pg_has_role(current_user, 'cfgms_rls_admin_override', 'MEMBER'))`,
	}
	for _, stmt := range rlsStmts {
		_, err := db.ExecContext(ctx, stmt)
		require.NoErrorf(t, err, "applying rbac_roles RLS setup: %s", stmt)
	}

	t.Run("ForceRowLevelSecurity_Set", func(t *testing.T) {
		var forced bool
		require.NoError(t, db.QueryRowContext(ctx, `
			SELECT relforcerowsecurity FROM pg_class WHERE relname = 'rbac_roles'`).Scan(&forced))
		require.True(t, forced, "rbac_roles must declare FORCE ROW LEVEL SECURITY")
	})

	// TestRLSAdminOverride_RBACRoles/ApplicationRoleCannotAssumeAdminOverride replaces
	// a round-2 attempt at this same AC that gated the override on a custom placeholder
	// GUC (app.is_admin) constrained by REVOKE SET ON PARAMETER. That failed in the
	// merge queue's real-Postgres run: an ordinary role could still set_config it after
	// the REVOKE. Role membership has no equivalent ambiguity -- SET ROLE requires the
	// caller to already be a member of the target role, which the probe role never is.
	t.Run("ApplicationRoleCannotAssumeAdminOverride", func(t *testing.T) {
		dsn := provisionRLSWriteProbeRole(t, db, []string{"rbac_roles"})
		conn, err := sql.Open("postgres", dsn)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		conn.SetMaxOpenConns(1)
		require.NoError(t, conn.Ping())

		_, err = conn.ExecContext(context.Background(), `SET ROLE cfgms_rls_admin_override`)
		require.Error(t, err, "an ordinary application role must not be able to assume the admin-override "+
			"role -- admin_override_policy in migrations/003_enable_rls.sql relies on membership in "+
			"cfgms_rls_admin_override being explicitly granted, never self-service")

		var isAdmin bool
		require.NoError(t, conn.QueryRowContext(context.Background(),
			`SELECT pg_has_role(current_user, 'cfgms_rls_admin_override', 'MEMBER')`).Scan(&isAdmin))
		require.False(t, isAdmin, "the probe role must not satisfy admin_override_policy's predicate")
	})

	// The subtest above pins the mechanism (the probe role cannot become a member).
	// This one pins the consequence the finding actually turns on: that an ordinary
	// role cannot reach another tenant's rbac_roles rows through admin_override_policy.
	// Kept as a separate assertion because the two can diverge -- a future change that
	// keeps pg_has_role() false for the probe role while reintroducing some other
	// permissive bypass policy on this table would still pass the mechanism check, and
	// must fail here.
	t.Run("ApplicationRoleCannotReadOtherTenantRows", func(t *testing.T) {
		roleA := "rls4321-rbacrole-" + rlsWriteTenantA
		roleB := "rls4321-rbacrole-" + rlsWriteTenantB
		rlsSeedRBACRole(t, db, roleA, rlsWriteTenantA)
		rlsSeedRBACRole(t, db, roleB, rlsWriteTenantB)

		dsn := provisionRLSWriteProbeRole(t, db, []string{"rbac_roles"})
		pool, err := sql.Open("postgres", dsn)
		require.NoError(t, err)
		defer func() { _ = pool.Close() }()

		// Pinned to one backend for the same reason rlsWriteExecAsTenant is: the GUC
		// below is session-scoped.
		probe, err := pool.Conn(ctx)
		require.NoError(t, err)
		defer func() { _ = probe.Close() }()

		_, err = probe.ExecContext(ctx,
			`SELECT set_config('app.current_tenant', $1, false)`, rlsWriteTenantA)
		require.NoError(t, err)

		var foreign int
		require.NoError(t, probe.QueryRowContext(ctx,
			`SELECT count(*) FROM rbac_roles WHERE id = $1`, roleB).Scan(&foreign))
		require.Equal(t, 0, foreign, "a tenant-A-scoped application role must not see tenant B's "+
			"rbac_roles row -- a non-zero count means admin_override_policy is an open cross-tenant bypass again")

		// Control: without this, the zero above would also be produced by a seeding or
		// search_path failure, which would make the assertion vacuous.
		var own int
		require.NoError(t, probe.QueryRowContext(ctx,
			`SELECT count(*) FROM rbac_roles WHERE id = $1`, roleA).Scan(&own))
		require.Equal(t, 1, own, "the probe role must still see its own tenant's rbac_roles row")
	})
}
