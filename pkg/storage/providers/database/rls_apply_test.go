// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #6096 (Epic #5978): applying a tenant table's RLS policies must not open a
// deny-all window for nodes that are still serving. The tests that need Postgres
// connect through the real database provider; the ones that observe tenant
// traffic connect as a non-superuser role, because a superuser bypasses RLS even
// under FORCE ROW LEVEL SECURITY and would pass vacuously.

const (
	rlsApplyTenantA = "rls6096-tenant-a"
	rlsApplyTenantB = "rls6096-tenant-b"
)

// rlsApplyTable describes one tenant-isolated table for the tests: how to create
// it through the production path, which policy set it is meant to carry, and a
// minimal INSERT ($1 = id, $2 = tenant) that satisfies its NOT NULL columns.
type rlsApplyTable struct {
	name     string
	create   func(ctx context.Context, db *sql.DB) error
	policies func() []tenantRLSPolicy
	idColumn string
	insert   string
	// legacyPolicy is true for the tables on which older revisions also created
	// the FOR ALL tenant_isolation_policy.
	legacyPolicy bool
}

func rlsApplyTables() []rlsApplyTable {
	s := NewDatabaseSchemas()
	return []rlsApplyTable{
		{
			name: tableSessions, create: s.CreateSessionsTable, policies: standardTenantPolicies,
			idColumn: "session_id_hash", legacyPolicy: true,
			insert: `INSERT INTO sessions (session_id_hash, user_id, tenant_id, session_type, created_at, last_activity, expires_at, status)
				VALUES ($1, 'rls6096-user', $2, 'admin', now(), now(), now() + interval '1 hour', 'active')`,
		},
		{
			name: tableStewardRecords, create: s.CreateStewardRecordsTable, policies: stewardRecordsPolicies,
			idColumn: "id", legacyPolicy: true,
			insert: `INSERT INTO steward_records (id, tenant_id, status, registered_at, last_seen)
				VALUES ($1, $2, 'active', now(), now())`,
		},
		{
			name: tableCommandRecords, create: s.CreateCommandRecordsTable, policies: standardTenantPolicies,
			idColumn: "id", legacyPolicy: true,
			insert: `INSERT INTO command_records (id, type, steward_id, tenant_id, status, issued_at)
				VALUES ($1, 'rls6096', 'rls6096-steward', $2, 'pending', now())`,
		},
		{
			name: tableRolloutRecords, create: s.CreateRolloutRecordsTable, policies: standardTenantPolicies,
			idColumn: "id",
			insert: `INSERT INTO cfgms_rollout_records (id, tenant_id, status, started_at)
				VALUES ($1, $2, 'in-progress', now())`,
		},
		{
			name: tableUpgradeRecords, create: s.CreateUpgradeRecordsTable, policies: standardTenantPolicies,
			idColumn: "id",
			insert: `INSERT INTO cfgms_upgrade_records (id, steward_id, tenant_id, version, platform, arch, sha256, status,
					initiated_by_subject, initiated_by_tenant, initiated_by_auth_method, publisher, signature_digest,
					bundle_signature, created_at, dispatched_at)
				VALUES ($1, 'rls6096-steward', $2, 'v', 'p', 'a', 'h', 'pending', 'sub', 'ten', 'm', 'pub', 'sd',
					'\x00'::bytea, now(), now())`,
		},
		{
			name: tableSessionTokenStore, create: s.CreateSessionTokenStoreTable, policies: standardTenantPolicies,
			idColumn: "token_hash",
			insert: `INSERT INTO session_token_store (token_hash, session_id, principal_id, connection_name, tenant_id,
					issued_at, last_activity, absolute_expires_at)
				VALUES ($1, 'rls6096-session', 'rls6096-principal', 'c', $2, now(), now(), now() + interval '1 hour')`,
		},
	}
}

// rlsApplyCreateAll creates every tenant table through the production path.
func rlsApplyCreateAll(t *testing.T, db *sql.DB) []rlsApplyTable {
	t.Helper()
	tables := rlsApplyTables()
	for _, tbl := range tables {
		require.NoError(t, tbl.create(context.Background(), db), "creating %s", tbl.name)
	}
	return tables
}

// rlsLegacyInlineStatements is a frozen copy of the RLS statements the previous
// revision ran on every start, one drop and one create per policy, none of them
// stamping a comment. Tests replay it to put a table into the state a database
// created by that revision is in.
//
//duplication:justified pkg/storage/providers/database/schemas.go -- frozen copy of the pre-#6096 inline RLS blocks; reproduces a database created by the previous revision, which the helper that replaced them cannot
var rlsLegacyInlineStatements = map[string][]string{
	"sessions": {
		`ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE sessions FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_isolation_policy ON sessions;`,
		`DROP POLICY IF EXISTS rls_read   ON sessions;`,
		`DROP POLICY IF EXISTS rls_write  ON sessions;`,
		`DROP POLICY IF EXISTS rls_update ON sessions;`,
		`DROP POLICY IF EXISTS rls_delete ON sessions;`,
		// SELECT: permissive when no tenant context (auth lookups), filtered when context is set.
		`CREATE POLICY rls_read ON sessions FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
		);`,
		// INSERT: tenant must be set in the transaction before inserting.
		`CREATE POLICY rls_write ON sessions FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		// UPDATE/DELETE (Issue #4321): the target row must belong to the caller's
		// current tenant, and an UPDATE may not move a row to a different tenant --
		// an unset tenant matches nothing (fail closed), not every row.
		`CREATE POLICY rls_update ON sessions FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (tenant_id = current_setting('app.current_tenant', true));`,
		`CREATE POLICY rls_delete ON sessions FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	},
	"steward_records": {
		`ALTER TABLE steward_records ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE steward_records FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_isolation_policy ON steward_records;`,
		`DROP POLICY IF EXISTS rls_read   ON steward_records;`,
		`DROP POLICY IF EXISTS rls_write  ON steward_records;`,
		`DROP POLICY IF EXISTS rls_update ON steward_records;`,
		`DROP POLICY IF EXISTS rls_delete ON steward_records;`,
		// SELECT: permissive when no tenant context (fleet management), filtered when
		// context is set. The app.tenant_move_target clause exists for
		// UpdateStewardTenant (Issue #4321): an UPDATE whose WHERE reads the row also
		// applies SELECT policies to the NEW row, so a moved row (tenant_id = target)
		// must be visible or Postgres rejects it with "new row violates row-level
		// security policy". The clause admits exactly one extra tenant, the one the
		// transaction named as its move target -- no wider than setting
		// app.current_tenant to that tenant, which any session can already do.
		`CREATE POLICY rls_read ON steward_records FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
			OR (coalesce(current_setting('app.tenant_move_target', true), '') <> ''
				AND tenant_id = current_setting('app.tenant_move_target', true))
		);`,
		// INSERT: tenant must be set in the transaction before inserting.
		`CREATE POLICY rls_write ON steward_records FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		// UPDATE (Issue #4321): the target row must belong to the caller's current
		// tenant -- an unset tenant matches nothing (fail closed), not every row.
		// WITH CHECK allows a row to keep its own tenant, OR to move to exactly the
		// tenant named by the transaction-local app.tenant_move_target -- not to any
		// other tenant. That GUC is set by exactly one caller, UpdateStewardTenant
		// (steward_store.go) -- a real product feature that moves a steward to a
		// different tenant, gated at the Go/API layer (handlers_stewards.go's
		// handleMoveSteward requires a root caller or a scoped admin whose scope
		// covers both tenants). USING and a plain tenant-scoped WITH CHECK read the
		// same current_setting('app.current_tenant') value within one statement, so
		// without a named target a tenant-scoped WITH CHECK would make that move
		// impossible for any caller; a bare raw-SQL session that never names a
		// target still cannot move a row cross-tenant. See
		// TestRLSWritePolicy_StewardRecordsTenantMove_IntentionallyAllowed,
		// TestRLSWritePolicy_StewardRecordsTenantMove_UnauthorizedRefused and
		// TestRLSWritePolicy_StewardRecordsTenantMove_NonTargetTenantRefused.
		`CREATE POLICY rls_update ON steward_records FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (
				tenant_id = current_setting('app.current_tenant', true)
				OR (coalesce(current_setting('app.tenant_move_target', true), '') <> ''
					AND tenant_id = current_setting('app.tenant_move_target', true))
			);`,
		`CREATE POLICY rls_delete ON steward_records FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	},
	"command_records": {
		`ALTER TABLE command_records ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE command_records FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_isolation_policy ON command_records;`,
		`DROP POLICY IF EXISTS rls_read   ON command_records;`,
		`DROP POLICY IF EXISTS rls_write  ON command_records;`,
		`DROP POLICY IF EXISTS rls_update ON command_records;`,
		`DROP POLICY IF EXISTS rls_delete ON command_records;`,
		// SELECT: permissive when no tenant context, filtered when context is set.
		`CREATE POLICY rls_read ON command_records FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
		);`,
		// INSERT: tenant must be set in the transaction before inserting.
		`CREATE POLICY rls_write ON command_records FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		// UPDATE/DELETE (Issue #4321): the target row must belong to the caller's
		// current tenant, and an UPDATE may not move a row to a different tenant --
		// an unset tenant matches nothing (fail closed), not every row.
		`CREATE POLICY rls_update ON command_records FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (tenant_id = current_setting('app.current_tenant', true));`,
		`CREATE POLICY rls_delete ON command_records FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	},
	"cfgms_rollout_records": {
		`ALTER TABLE cfgms_rollout_records ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE cfgms_rollout_records FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS rls_read   ON cfgms_rollout_records;`,
		`DROP POLICY IF EXISTS rls_write  ON cfgms_rollout_records;`,
		`DROP POLICY IF EXISTS rls_update ON cfgms_rollout_records;`,
		`DROP POLICY IF EXISTS rls_delete ON cfgms_rollout_records;`,
		// SELECT: permissive when no tenant context (the by-ID read and the
		// cross-tenant startup sweep), filtered when a context is set.
		`CREATE POLICY rls_read ON cfgms_rollout_records FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
		);`,
		// INSERT/UPDATE/DELETE: the row must belong to the caller's current
		// tenant; an unset tenant matches nothing (fail closed).
		`CREATE POLICY rls_write ON cfgms_rollout_records FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		`CREATE POLICY rls_update ON cfgms_rollout_records FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (tenant_id = current_setting('app.current_tenant', true));`,
		`CREATE POLICY rls_delete ON cfgms_rollout_records FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	},
	"cfgms_upgrade_records": {
		`ALTER TABLE cfgms_upgrade_records ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE cfgms_upgrade_records FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS rls_read   ON cfgms_upgrade_records;`,
		`DROP POLICY IF EXISTS rls_write  ON cfgms_upgrade_records;`,
		`DROP POLICY IF EXISTS rls_update ON cfgms_upgrade_records;`,
		`DROP POLICY IF EXISTS rls_delete ON cfgms_upgrade_records;`,
		// SELECT: permissive when no tenant context (the by-ID read), filtered
		// when a context is set.
		`CREATE POLICY rls_read ON cfgms_upgrade_records FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
		);`,
		// INSERT/UPDATE/DELETE: the row must belong to the caller's current
		// tenant; an unset tenant matches nothing (fail closed).
		`CREATE POLICY rls_write ON cfgms_upgrade_records FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		`CREATE POLICY rls_update ON cfgms_upgrade_records FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (tenant_id = current_setting('app.current_tenant', true));`,
		`CREATE POLICY rls_delete ON cfgms_upgrade_records FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	},
	"session_token_store": {
		`ALTER TABLE session_token_store ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE session_token_store FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS rls_read   ON session_token_store;`,
		`DROP POLICY IF EXISTS rls_write  ON session_token_store;`,
		`DROP POLICY IF EXISTS rls_update ON session_token_store;`,
		`DROP POLICY IF EXISTS rls_delete ON session_token_store;`,
		`CREATE POLICY rls_read ON session_token_store FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
		);`,
		`CREATE POLICY rls_write ON session_token_store FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		// UPDATE/DELETE (Issue #4321): the target row must belong to the caller's
		// current tenant, and an UPDATE may not move a row to a different tenant --
		// an unset tenant matches nothing (fail closed), not every row.
		`CREATE POLICY rls_update ON session_token_store FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (tenant_id = current_setting('app.current_tenant', true));`,
		`CREATE POLICY rls_delete ON session_token_store FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	},
}

// ── catalog helpers ───────────────────────────────────────────────────────────

// rlsPolicyRow is one row of pg_policies for a table.
type rlsPolicyRow struct {
	Name, Permissive, Roles, Cmd, Qual, WithCheck string
}

// rlsSnapshotPolicies returns the pg_policies content of a table (names, commands,
// qual and with_check), ordered by policy name.
func rlsSnapshotPolicies(t *testing.T, db *sql.DB, table string) []rlsPolicyRow {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `
		SELECT policyname::text, permissive, roles::text, cmd, coalesce(qual, ''), coalesce(with_check, '')
		FROM pg_policies
		WHERE tablename = $2
		  AND schemaname = (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		                    WHERE c.oid = to_regclass($1))
		ORDER BY policyname`, pq.QuoteIdentifier(table), table)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out []rlsPolicyRow
	for rows.Next() {
		var r rlsPolicyRow
		require.NoError(t, rows.Scan(&r.Name, &r.Permissive, &r.Roles, &r.Cmd, &r.Qual, &r.WithCheck))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// rlsPolicyIdentity identifies a policy tuple: its OID, the transaction that last
// wrote its pg_policy row, its comment and the transaction that last wrote the
// comment. Any DDL on the policy changes at least one of them.
type rlsPolicyIdentity struct {
	OID, Xmin, Comment, CommentXmin string
}

func rlsSnapshotIdentity(t *testing.T, db *sql.DB, table string) map[string]rlsPolicyIdentity {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `
		SELECT p.polname::text, p.oid::text, p.xmin::text,
		       coalesce(obj_description(p.oid, 'pg_policy'), ''),
		       coalesce((SELECT d.xmin::text FROM pg_description d
		                 WHERE d.objoid = p.oid AND d.classoid = 'pg_policy'::regclass), '')
		FROM pg_policy p WHERE p.polrelid = to_regclass($1)`, pq.QuoteIdentifier(table))
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := map[string]rlsPolicyIdentity{}
	for rows.Next() {
		var name string
		var id rlsPolicyIdentity
		require.NoError(t, rows.Scan(&name, &id.OID, &id.Xmin, &id.Comment, &id.CommentXmin))
		out[name] = id
	}
	require.NoError(t, rows.Err())
	return out
}

// rlsApplyLegacyState puts a table into the state a database created by the
// previous revision is in: policies re-created by drop and create with no hash
// comment, and on the tables where older revisions made it, the legacy
// tenant_isolation_policy.
func rlsApplyLegacyState(t *testing.T, db *sql.DB, tbl rlsApplyTable) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range rlsLegacyInlineStatements[tbl.name] {
		_, err := db.ExecContext(ctx, stmt)
		require.NoError(t, err, "replaying previous revision statement for %s", tbl.name)
	}
	if tbl.legacyPolicy {
		_, err := db.ExecContext(ctx, `CREATE POLICY tenant_isolation_policy ON `+pq.QuoteIdentifier(tbl.name)+
			` USING (tenant_id = current_setting('app.current_tenant', true))`)
		require.NoError(t, err)
	}
}

// rlsApplyRestoreOnCleanup converges every table again when the test ends, so a
// test that left a table in a legacy, drifted or locked state does not leak it.
func rlsApplyRestoreOnCleanup(t *testing.T, db *sql.DB) {
	t.Helper()
	t.Cleanup(func() {
		for _, tbl := range rlsApplyTables() {
			_ = tbl.create(context.Background(), db)
		}
	})
}

func rlsApplyFlags(t *testing.T, db *sql.DB, table string) (enabled, forced bool) {
	t.Helper()
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass($1)`,
		pq.QuoteIdentifier(table)).Scan(&enabled, &forced))
	return enabled, forced
}

// ── unit tests (no database) ──────────────────────────────────────────────────

func TestApplyTenantRLS_PolicySetsAreValid(t *testing.T) {
	for _, tbl := range rlsApplyTables() {
		policies := tbl.policies()
		require.NoError(t, validateTenantRLSPolicies(policies), tbl.name)
		var names []string
		for _, p := range policies {
			names = append(names, p.Name+":"+p.Command)
		}
		assert.Equal(t, []string{"rls_read:SELECT", "rls_write:INSERT", "rls_update:UPDATE", "rls_delete:DELETE"}, names, tbl.name)
	}
}

func TestApplyTenantRLS_ValidateRejectsMalformedPolicies(t *testing.T) {
	cases := map[string][]tenantRLSPolicy{
		"empty":              nil,
		"empty name":         {{Name: "", Command: "SELECT", Using: "true"}},
		"legacy name":        {{Name: rlsLegacyPolicyName, Command: "SELECT", Using: "true"}},
		"unknown command":    {{Name: "p", Command: "TRUNCATE", Using: "true"}},
		"all command":        {{Name: "p", Command: "ALL", Using: "true"}},
		"insert with using":  {{Name: "p", Command: "INSERT", Using: "true", WithCheck: "true"}},
		"insert no check":    {{Name: "p", Command: "INSERT"}},
		"select no using":    {{Name: "p", Command: "SELECT"}},
		"select with check":  {{Name: "p", Command: "SELECT", Using: "true", WithCheck: "true"}},
		"delete with check":  {{Name: "p", Command: "DELETE", Using: "true", WithCheck: "true"}},
		"update no using":    {{Name: "p", Command: "UPDATE", WithCheck: "true"}},
		"duplicate policies": {{Name: "p", Command: "SELECT", Using: "true"}, {Name: "p", Command: "DELETE", Using: "true"}},
	}
	for name, policies := range cases {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateTenantRLSPolicies(policies))
		})
	}
}

func TestApplyTenantRLS_TableHashTracksDefinitionsOnly(t *testing.T) {
	base := standardTenantPolicies()
	h := tenantRLSTableHash("sessions", base)

	reordered := []tenantRLSPolicy{base[3], base[1], base[0], base[2]}
	assert.Equal(t, h, tenantRLSTableHash("sessions", reordered), "policy order must not matter")

	reformatted := append([]tenantRLSPolicy(nil), base...)
	reformatted[0].Using = "  " + strings.ReplaceAll(reformatted[0].Using, "\n", "\n\n   ") + " "
	assert.Equal(t, h, tenantRLSTableHash("sessions", reformatted), "whitespace must not matter")

	assert.NotEqual(t, h, tenantRLSTableHash("command_records", base), "table name is part of the hash")

	for i := range base {
		changed := append([]tenantRLSPolicy(nil), base...)
		changed[i].Using += " AND true"
		changed[i].WithCheck += " AND true"
		assert.NotEqual(t, h, tenantRLSTableHash("sessions", changed), "policy %s change must change the hash", base[i].Name)
	}
	renamed := append([]tenantRLSPolicy(nil), base...)
	renamed[0].Name = "rls_read2"
	assert.NotEqual(t, h, tenantRLSTableHash("sessions", renamed))

	assert.NotEqual(t, tenantRLSTableHash("steward_records", stewardRecordsPolicies()),
		tenantRLSTableHash("steward_records", standardTenantPolicies()))
}

func TestApplyTenantRLS_PolicyStatementsAreRenderedPerCommand(t *testing.T) {
	q := pq.QuoteIdentifier("sessions")
	for _, p := range standardTenantPolicies() {
		create := createPolicySQL(q, p)
		alter := alterPolicySQL(q, p)
		assert.True(t, strings.HasPrefix(create, `CREATE POLICY "`+p.Name+`" ON "sessions" FOR `+p.Command), create)
		assert.True(t, strings.HasPrefix(alter, `ALTER POLICY "`+p.Name+`" ON "sessions" TO PUBLIC`), alter)
		assert.Equal(t, p.Using != "", strings.Contains(create, "USING ("), create)
		assert.Equal(t, p.WithCheck != "", strings.Contains(create, "WITH CHECK ("), create)
		assert.NotContains(t, alter, "FOR "+p.Command, "ALTER POLICY cannot change the command")
	}
	hostile := pq.QuoteIdentifier(`x"; DROP TABLE sessions; --`)
	assert.Equal(t, `"x""; DROP TABLE sessions; --"`, hostile, "table names are quoted as identifiers")
}

func TestApplyTenantRLS_NeedsChange(t *testing.T) {
	policies := standardTenantPolicies()
	hash := tenantRLSTableHash("sessions", policies)

	converged := func() rlsTableState {
		st := rlsTableState{rowSecurity: true, forceRowSecurity: true, policies: map[string]rlsLivePolicy{}}
		for _, p := range policies {
			live := rlsLivePolicy{permissive: true, command: policyCommandCode(p.Command), roles: "public", qual: "q-" + p.Name}
			live.comment = rlsDefCommentPrefix + livePolicyHash(hash, p.Name, live)
			st.policies[p.Name] = live
		}
		return st
	}

	st := converged()
	assert.False(t, st.needsChange(policies, hash), "a converged table needs no DDL")

	t.Run("row security off", func(t *testing.T) {
		st := converged()
		st.rowSecurity = false
		assert.True(t, st.needsChange(policies, hash))
	})
	t.Run("force off", func(t *testing.T) {
		st := converged()
		st.forceRowSecurity = false
		assert.True(t, st.needsChange(policies, hash))
	})
	t.Run("missing policy", func(t *testing.T) {
		st := converged()
		delete(st.policies, "rls_delete")
		assert.True(t, st.needsChange(policies, hash))
	})
	t.Run("lost comment", func(t *testing.T) {
		st := converged()
		live := st.policies["rls_read"]
		live.comment = ""
		st.policies["rls_read"] = live
		assert.True(t, st.needsChange(policies, hash))
	})
	t.Run("hand edited definition keeps its comment", func(t *testing.T) {
		st := converged()
		live := st.policies["rls_update"]
		live.qual = "true"
		st.policies["rls_update"] = live
		assert.True(t, st.needsChange(policies, hash))
	})
	t.Run("definition changed in source", func(t *testing.T) {
		changed := standardTenantPolicies()
		changed[0].Using = "true"
		assert.True(t, st.needsChange(changed, tenantRLSTableHash("sessions", changed)))
	})
	t.Run("legacy policy present", func(t *testing.T) {
		st := converged()
		st.policies[rlsLegacyPolicyName] = rlsLivePolicy{permissive: true, command: "*"}
		assert.True(t, st.needsChange(policies, hash))
	})
}

func TestApplyTenantRLS_ChangeStatements(t *testing.T) {
	q := pq.QuoteIdentifier("sessions")
	policies := standardTenantPolicies()
	hash := tenantRLSTableHash("sessions", policies)
	count := func(stmts []string, prefix string) int {
		n := 0
		for _, s := range stmts {
			if strings.HasPrefix(s, prefix) {
				n++
			}
		}
		return n
	}
	live := func(p tenantRLSPolicy, comment string) rlsLivePolicy {
		return rlsLivePolicy{permissive: true, command: policyCommandCode(p.Command), roles: "public", comment: comment}
	}

	t.Run("new table creates every policy and turns row security on", func(t *testing.T) {
		stmts := tableChangeStatements(q, policies, hash, rlsTableState{policies: map[string]rlsLivePolicy{}})
		assert.Equal(t, 1, count(stmts, "ALTER TABLE "+q+" ENABLE ROW LEVEL SECURITY"))
		assert.Equal(t, 1, count(stmts, "ALTER TABLE "+q+" FORCE ROW LEVEL SECURITY"))
		assert.Equal(t, 4, count(stmts, "CREATE POLICY"))
		assert.Zero(t, count(stmts, "DROP POLICY"))
	})

	t.Run("legacy table alters in place, drops only the legacy policy, leaves flags alone", func(t *testing.T) {
		state := rlsTableState{rowSecurity: true, forceRowSecurity: true, policies: map[string]rlsLivePolicy{
			rlsLegacyPolicyName: {permissive: true, command: "*"},
		}}
		for _, p := range policies {
			state.policies[p.Name] = live(p, "")
		}
		stmts := tableChangeStatements(q, policies, hash, state)
		assert.Zero(t, count(stmts, "ALTER TABLE"), "no ENABLE/FORCE when the catalog shows both on")
		assert.Zero(t, count(stmts, "CREATE POLICY"))
		assert.Equal(t, 4, count(stmts, "ALTER POLICY"))
		require.Equal(t, 1, count(stmts, "DROP POLICY"))
		assert.Contains(t, stmts[0], rlsLegacyPolicyName)
	})

	t.Run("a policy that already matches is left alone", func(t *testing.T) {
		p := policies[0]
		l := live(p, "")
		l.comment = rlsDefCommentPrefix + livePolicyHash(hash, p.Name, l)
		assert.Empty(t, policyChangeStatements(q, p, l, true, hash))
	})

	t.Run("a policy ALTER cannot fix is replaced inside the transaction", func(t *testing.T) {
		p := policies[0]
		wrongCommand := live(p, "")
		wrongCommand.command = policyCommandCode("DELETE")
		restrictive := live(p, "")
		restrictive.permissive = false
		for _, l := range []rlsLivePolicy{wrongCommand, restrictive} {
			stmts := policyChangeStatements(q, p, l, true, hash)
			require.Len(t, stmts, 2)
			assert.True(t, strings.HasPrefix(stmts[0], "DROP POLICY"))
			assert.True(t, strings.HasPrefix(stmts[1], "CREATE POLICY"))
		}
	})
}

func TestApplyTenantRLS_RetryHelperIsBounded(t *testing.T) {
	cfg := rlsApplyConfig{lockTimeout: time.Second, attempts: 3, retryPause: time.Millisecond}
	ctx := context.Background()

	calls := 0
	err := withRLSRetries(ctx, cfg, func() error { calls++; return &pq.Error{Code: "55P03"} })
	require.Error(t, err)
	assert.Equal(t, 3, calls, "lock contention is retried up to the bound")

	calls = 0
	err = withRLSRetries(ctx, cfg, func() error {
		calls++
		if calls < 2 {
			return &pq.Error{Code: "55P03"}
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, calls)

	calls = 0
	err = withRLSRetries(ctx, cfg, func() error { calls++; return errors.New("syntax") })
	require.Error(t, err)
	assert.Equal(t, 1, calls, "other failures are not retried")

	calls = 0
	require.Error(t, withRLSRetries(ctx, rlsApplyConfig{}, func() error { calls++; return errors.New("x") }))
	assert.Equal(t, 1, calls, "a zero attempt count still tries once")

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	err = withRLSRetries(cancelled, rlsApplyConfig{attempts: 3, retryPause: time.Hour}, func() error { return &pq.Error{Code: "55P03"} })
	assert.ErrorIs(t, err, context.Canceled, "a cancelled context ends the pause")
}

func TestApplyTenantRLS_RetriesOnlyOnLockContention(t *testing.T) {
	assert.True(t, isRetryableRLSError(&pq.Error{Code: "55P03"}))
	assert.True(t, isRetryableRLSError(fmt.Errorf("wrapped: %w", &pq.Error{Code: "40P01"})))
	assert.False(t, isRetryableRLSError(&pq.Error{Code: "42601"}), "a syntax error is not retried")
	assert.False(t, isRetryableRLSError(errors.New("boom")))
	assert.False(t, isRetryableRLSError(context.Canceled))
}

func TestApplyTenantRLS_DefaultBoundsMatchContractStep(t *testing.T) {
	assert.Equal(t, 5*time.Second, defaultRLSApplyConfig.lockTimeout)
	assert.Equal(t, 3, defaultRLSApplyConfig.attempts)
	assert.Positive(t, defaultRLSApplyConfig.retryPause)
	assert.Less(t, defaultRLSApplyConfig.retryPause, time.Second)
}

// ── database tests ────────────────────────────────────────────────────────────

func TestApplyTenantRLS_InvalidPoliciesRejectedBeforeAnyDDL(t *testing.T) {
	// A nil handle proves nothing is executed: validation fails first.
	err := applyTenantRLS(context.Background(), nil, tableSessions, []tenantRLSPolicy{{Name: "p", Command: "INSERT"}})
	require.Error(t, err)
}

func TestApplyTenantRLS_MissingTableIsAnError(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	err := applyTenantRLS(context.Background(), db, "rls6096_no_such_table", standardTenantPolicies())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

// TestApplyTenantRLS_ReapplyIssuesNoPolicyDDL proves the steady state touches
// nothing: on an up to date database, calling each CreateXTable again leaves every
// policy tuple (OID, row version, comment, comment version) exactly as it was, and
// the helper needs no lock on the table, so it succeeds while another connection
// holds ACCESS EXCLUSIVE on it.
func TestApplyTenantRLS_ReapplyIssuesNoPolicyDDL(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	tables := rlsApplyCreateAll(t, db)

	for _, tbl := range tables {
		t.Run(tbl.name, func(t *testing.T) {
			before := rlsSnapshotIdentity(t, db, tbl.name)
			require.Len(t, before, 4, "%s must carry its four policies", tbl.name)
			for name, id := range before {
				require.True(t, strings.HasPrefix(id.Comment, rlsDefCommentPrefix), "%s.%s must carry the definition hash", tbl.name, name)
			}

			for i := 0; i < 3; i++ {
				require.NoError(t, tbl.create(ctx, db))
			}
			assert.Equal(t, before, rlsSnapshotIdentity(t, db, tbl.name),
				"re-applying an up to date %s must not rewrite any policy or comment", tbl.name)
		})
	}

	t.Run("steady state takes no table lock", func(t *testing.T) {
		holder, err := db.Conn(ctx)
		require.NoError(t, err)
		defer func() { _ = holder.Close() }()
		_, err = holder.ExecContext(ctx, `BEGIN`)
		require.NoError(t, err)
		defer func() { _, _ = holder.ExecContext(context.Background(), `ROLLBACK`) }()
		_, err = holder.ExecContext(ctx, `LOCK TABLE `+pq.QuoteIdentifier(tableSessions)+` IN ACCESS EXCLUSIVE MODE`)
		require.NoError(t, err)

		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		require.NoError(t, applyTenantRLS(bounded, db, tableSessions, standardTenantPolicies()),
			"an up to date table must be recognised from the catalog without waiting for its lock")
	})
}

// TestApplyTenantRLS_ConcurrentReapplyNeverDeniesTenantTraffic re-applies every
// table's schema while a tenant-scoped, non-superuser connection keeps reading and
// writing those tables. A policy drop and create in separate statements makes the
// table deny the tenant in between, which shows up here as an error, a row that
// cannot be seen, or an UPDATE that touches no row.
func TestApplyTenantRLS_ConcurrentReapplyNeverDeniesTenantTraffic(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tables := rlsApplyCreateAll(t, db)

	names := make([]string, 0, len(tables))
	for _, tbl := range tables {
		names = append(names, tbl.name)
	}
	dsn := provisionRLSWriteProbeRole(t, db, names)
	for _, tbl := range tables {
		_, err := db.ExecContext(ctx, `GRANT INSERT ON `+pq.QuoteIdentifier(tbl.name)+` TO `+rlsWriteProbeRole)
		require.NoError(t, err)
	}

	seedID := func(tbl rlsApplyTable) string { return "rls6096-seed-" + tbl.name }
	probeID := func(tbl rlsApplyTable) string { return "rls6096-probe-" + tbl.name }
	for _, tbl := range tables {
		_, err := db.ExecContext(ctx, tbl.insert, seedID(tbl), rlsApplyTenantA)
		require.NoError(t, err, "seeding %s", tbl.name)
		tbl := tbl
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM `+pq.QuoteIdentifier(tbl.name)+
				` WHERE `+pq.QuoteIdentifier(tbl.idColumn)+` = ANY($1)`, pq.Array([]string{seedID(tbl), probeID(tbl)}))
		})
	}

	pool, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { _ = pool.Close() }()
	pool.SetMaxOpenConns(2)

	// inTenantTx runs fn in a transaction scoped to tenant and always rolls back.
	inTenantTx := func(tenant string, fn func(tx *sql.Tx) error) error {
		tx, err := pool.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenant); err != nil {
			return err
		}
		return fn(tx)
	}

	// The probe must actually be subject to RLS, or the run below proves nothing.
	for _, tbl := range tables {
		var seen int
		require.NoError(t, inTenantTx(rlsApplyTenantB, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM `+pq.QuoteIdentifier(tbl.name)+
				` WHERE `+pq.QuoteIdentifier(tbl.idColumn)+` = $1`, seedID(tbl)).Scan(&seen)
		}))
		require.Zero(t, seen, "%s: the probe role must not see another tenant's row; RLS is not being enforced", tbl.name)
	}

	// One pass of tenant traffic over every table: write a row, read it and the
	// seeded row back, and update the seeded row.
	traffic := func(tbl rlsApplyTable) error {
		return inTenantTx(rlsApplyTenantA, func(tx *sql.Tx) error {
			ident := pq.QuoteIdentifier(tbl.name)
			id := pq.QuoteIdentifier(tbl.idColumn)
			if _, err := tx.ExecContext(ctx, tbl.insert, probeID(tbl), rlsApplyTenantA); err != nil {
				return fmt.Errorf("insert: %w", err)
			}
			var visible int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+ident+` WHERE `+id+` = ANY($1)`,
				pq.Array([]string{seedID(tbl), probeID(tbl)})).Scan(&visible); err != nil {
				return fmt.Errorf("select: %w", err)
			}
			if visible != 2 {
				return fmt.Errorf("select: %d of 2 own rows visible", visible)
			}
			res, err := tx.ExecContext(ctx, `UPDATE `+ident+` SET tenant_id = tenant_id WHERE `+id+` = $1`, seedID(tbl))
			if err != nil {
				return fmt.Errorf("update: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return fmt.Errorf("update: %d rows affected, want 1", n)
			}
			return nil
		})
	}

	var stop atomic.Bool
	var passes atomic.Int64
	readerDone := make(chan error, 1)
	go func() {
		for !stop.Load() {
			for _, tbl := range tables {
				if err := traffic(tbl); err != nil {
					readerDone <- fmt.Errorf("%s: %w", tbl.name, err)
					return
				}
			}
			passes.Add(1)
		}
		readerDone <- nil
	}()

	const reapplies = 200
	var applyErr error
	for i := 0; i < reapplies && applyErr == nil; i++ {
		if len(readerDone) > 0 {
			break // the reader already failed; stop early and report it
		}
		for _, tbl := range tables {
			if applyErr = tbl.create(ctx, db); applyErr != nil {
				applyErr = fmt.Errorf("re-apply %d of %s: %w", i, tbl.name, applyErr)
				break
			}
		}
	}
	stop.Store(true)
	readerErr := <-readerDone

	require.NoError(t, applyErr)
	require.NoError(t, readerErr, "tenant traffic was denied while the schema was re-applied")
	require.Greater(t, passes.Load(), int64(5), "the tenant traffic loop must have overlapped the re-applies")
}

// TestApplyTenantRLS_LegacyPoliciesConvergeAtomically converges a database created
// by the previous revision (policies without a hash comment, plus the legacy
// tenant_isolation_policy) to the current definitions in one transaction.
func TestApplyTenantRLS_LegacyPoliciesConvergeAtomically(t *testing.T) {
	skipInKeepSchemaMode(t, "replays the previous revision's drop and create on the real tables")
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	rlsApplyCreateAll(t, db)
	rlsApplyRestoreOnCleanup(t, db)

	for _, tbl := range rlsApplyTables() {
		t.Run(tbl.name, func(t *testing.T) {
			rlsApplyLegacyState(t, db, tbl)
			legacyDefs := rlsSnapshotPolicies(t, db, tbl.name)
			legacyIDs := rlsSnapshotIdentity(t, db, tbl.name)
			for name, id := range legacyIDs {
				require.Empty(t, id.Comment, "%s.%s: the previous revision stamps no comment", tbl.name, name)
			}
			if tbl.legacyPolicy {
				require.Contains(t, legacyIDs, rlsLegacyPolicyName)
			}

			t.Run("a failure part way rolls everything back", func(t *testing.T) {
				// The first policy would deny every row if it were applied; the last one
				// cannot be, so the transaction fails after the earlier DDL ran.
				broken := tbl.policies()
				broken[0].Using = "false"
				broken[len(broken)-1].Using = "no_such_column = 1"
				err := applyTenantRLSWith(ctx, db, tbl.name, broken, defaultRLSApplyConfig)
				require.Error(t, err)
				assert.False(t, isRetryableRLSError(err))

				assert.Equal(t, legacyIDs, rlsSnapshotIdentity(t, db, tbl.name),
					"a failed apply must leave every policy, comment and the legacy policy untouched")
				assert.Equal(t, legacyDefs, rlsSnapshotPolicies(t, db, tbl.name))
			})

			require.NoError(t, tbl.create(ctx, db))

			after := rlsSnapshotIdentity(t, db, tbl.name)
			assert.NotContains(t, after, rlsLegacyPolicyName, "the legacy policy must be gone")
			require.Len(t, after, 4)
			var xmin string
			for name, id := range after {
				assert.True(t, strings.HasPrefix(id.Comment, rlsDefCommentPrefix), "%s.%s must carry the hash", tbl.name, name)
				assert.Equal(t, legacyIDs[name].OID, id.OID, "%s.%s must be altered, never dropped and re-created", tbl.name, name)
				if xmin == "" {
					xmin = id.Xmin
				}
				assert.Equal(t, xmin, id.Xmin, "%s: all policies must be rewritten by the same transaction", tbl.name)
			}
			assert.Equal(t, rlsExpectedWithoutLegacy(legacyDefs), rlsSnapshotPolicies(t, db, tbl.name),
				"converging must not change any policy definition")
			enabled, forced := rlsApplyFlags(t, db, tbl.name)
			assert.True(t, enabled && forced)

			t.Run("lost comments are restored", func(t *testing.T) {
				rlsApplyLegacyState(t, db, tbl) // an older node dropped and re-created its policies
				for name, id := range rlsSnapshotIdentity(t, db, tbl.name) {
					require.Empty(t, id.Comment, name)
				}
				require.NoError(t, tbl.create(ctx, db))
				restored := rlsSnapshotIdentity(t, db, tbl.name)
				require.Len(t, restored, 4)
				for name, id := range restored {
					assert.True(t, strings.HasPrefix(id.Comment, rlsDefCommentPrefix), "%s.%s", tbl.name, name)
				}
				assert.Equal(t, rlsExpectedWithoutLegacy(legacyDefs), rlsSnapshotPolicies(t, db, tbl.name))
			})
		})
	}
}

func rlsExpectedWithoutLegacy(rows []rlsPolicyRow) []rlsPolicyRow {
	var out []rlsPolicyRow
	for _, r := range rows {
		if r.Name != rlsLegacyPolicyName {
			out = append(out, r)
		}
	}
	return out
}

// TestApplyTenantRLS_RestoresRowSecurityFlags covers a table whose row level
// security was switched off or un-forced by hand.
func TestApplyTenantRLS_RestoresRowSecurityFlags(t *testing.T) {
	skipInKeepSchemaMode(t, "switches row level security off on the real tables")
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	rlsApplyCreateAll(t, db)
	rlsApplyRestoreOnCleanup(t, db)

	tbl := rlsApplyTables()[0]
	ident := pq.QuoteIdentifier(tbl.name)
	for _, off := range []string{"NO FORCE ROW LEVEL SECURITY", "DISABLE ROW LEVEL SECURITY"} {
		_, err := db.ExecContext(ctx, `ALTER TABLE `+ident+` `+off)
		require.NoError(t, err)
		require.NoError(t, tbl.create(ctx, db))
		enabled, forced := rlsApplyFlags(t, db, tbl.name)
		assert.True(t, enabled, "after %s", off)
		assert.True(t, forced, "after %s", off)
	}
}

// TestApplyTenantRLS_LockTimeoutFailsFastNotBlocking holds a conflicting lock on
// the table and expects a change-path apply to give up after its bounded retries
// with the lock-not-available error, rather than queueing behind the lock (and
// every request behind it).
func TestApplyTenantRLS_LockTimeoutFailsFastNotBlocking(t *testing.T) {
	skipInKeepSchemaMode(t, "removes a policy comment on the real sessions table")
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	require.NoError(t, NewDatabaseSchemas().CreateSessionsTable(ctx, db))
	rlsApplyRestoreOnCleanup(t, db)

	// Make the table need a change.
	_, err := db.ExecContext(ctx, `COMMENT ON POLICY rls_read ON sessions IS NULL`)
	require.NoError(t, err)
	before := rlsSnapshotIdentity(t, db, tableSessions)

	holder, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = holder.Close() }()
	_, err = holder.ExecContext(ctx, `BEGIN`)
	require.NoError(t, err)
	released := false
	release := func() {
		if !released {
			released = true
			_, _ = holder.ExecContext(context.Background(), `ROLLBACK`)
		}
	}
	defer release()
	// ACCESS SHARE is what any open SELECT holds; it conflicts with the ACCESS
	// EXCLUSIVE lock ALTER POLICY and COMMENT ON POLICY need.
	_, err = holder.ExecContext(ctx, `LOCK TABLE sessions IN ACCESS SHARE MODE`)
	require.NoError(t, err)

	cfg := rlsApplyConfig{lockTimeout: 200 * time.Millisecond, attempts: 3, retryPause: 50 * time.Millisecond}
	start := time.Now()
	err = applyTenantRLSWith(ctx, db, tableSessions, standardTenantPolicies(), cfg)
	elapsed := time.Since(start)

	require.Error(t, err, "a blocked change must be reported, not waited out")
	var pqErr *pq.Error
	require.True(t, errors.As(err, &pqErr), "the lock timeout must surface as the Postgres error: %v", err)
	assert.Equal(t, rlsSQLStateLockNotAvailable, string(pqErr.Code))
	assert.GreaterOrEqual(t, elapsed, 3*cfg.lockTimeout-50*time.Millisecond, "all three attempts must have been made")
	assert.Less(t, elapsed, 10*time.Second, "the apply must be bounded by its retries")
	assert.Equal(t, before, rlsSnapshotIdentity(t, db, tableSessions), "a timed out attempt must change nothing")

	// Once the lock is gone the same apply goes through.
	release()
	require.NoError(t, applyTenantRLSWith(ctx, db, tableSessions, standardTenantPolicies(), cfg))
	assert.True(t, strings.HasPrefix(rlsSnapshotIdentity(t, db, tableSessions)["rls_read"].Comment, rlsDefCommentPrefix))
}

// TestApplyTenantRLS_DriftedPolicyIsRestored alters policies by hand, leaving their
// comments in place, and expects the next apply to put the current definitions
// back by altering the policies, never dropping them.
func TestApplyTenantRLS_DriftedPolicyIsRestored(t *testing.T) {
	skipInKeepSchemaMode(t, "alters policies on the real tables")
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	tables := rlsApplyCreateAll(t, db)
	rlsApplyRestoreOnCleanup(t, db)

	for _, tbl := range tables {
		t.Run(tbl.name, func(t *testing.T) {
			ident := pq.QuoteIdentifier(tbl.name)
			wantDefs := rlsSnapshotPolicies(t, db, tbl.name)
			wantIDs := rlsSnapshotIdentity(t, db, tbl.name)

			for _, stmt := range []string{
				`ALTER POLICY rls_read ON ` + ident + ` USING (true)`,
				`ALTER POLICY rls_update ON ` + ident + ` USING (true)`,
				`ALTER POLICY rls_delete ON ` + ident + ` USING (false)`,
			} {
				_, err := db.ExecContext(ctx, stmt)
				require.NoError(t, err)
			}
			require.NotEqual(t, wantDefs, rlsSnapshotPolicies(t, db, tbl.name), "the drift must be visible in pg_policies")
			for name, id := range rlsSnapshotIdentity(t, db, tbl.name) {
				require.Equal(t, wantIDs[name].Comment, id.Comment, "%s: the hand edit keeps the comment, so only the definition shows the drift", name)
			}

			require.NoError(t, tbl.create(ctx, db))

			assert.Equal(t, wantDefs, rlsSnapshotPolicies(t, db, tbl.name), "the current definitions must be back")
			for name, id := range rlsSnapshotIdentity(t, db, tbl.name) {
				assert.Equal(t, wantIDs[name].OID, id.OID, "%s must be altered in place, never dropped", name)
				assert.True(t, strings.HasPrefix(id.Comment, rlsDefCommentPrefix), name)
			}

			// And it is stable again.
			settled := rlsSnapshotIdentity(t, db, tbl.name)
			require.NoError(t, tbl.create(ctx, db))
			assert.Equal(t, settled, rlsSnapshotIdentity(t, db, tbl.name))
		})
	}
}

// TestApplyTenantRLS_PolicyDefinitionsUnchanged compares pg_policies (names,
// commands, qual and with_check) for all six tables between the previous
// revision's inline statements and the helper.
func TestApplyTenantRLS_PolicyDefinitionsUnchanged(t *testing.T) {
	skipInKeepSchemaMode(t, "replays the previous revision's drop and create on the real tables")
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	rlsApplyCreateAll(t, db)
	rlsApplyRestoreOnCleanup(t, db)

	for _, tbl := range rlsApplyTables() {
		t.Run(tbl.name, func(t *testing.T) {
			// The previous revision's statements, run by themselves, drop the legacy
			// policy and re-create the four current ones.
			for _, stmt := range rlsLegacyInlineStatements[tbl.name] {
				_, err := db.ExecContext(ctx, stmt)
				require.NoError(t, err)
			}
			previous := rlsSnapshotPolicies(t, db, tbl.name)
			require.Len(t, previous, 4)
			for _, r := range previous {
				require.NotEmpty(t, r.Qual+r.WithCheck, "%s.%s must carry an expression", tbl.name, r.Name)
			}

			require.NoError(t, tbl.create(ctx, db))
			assert.Equal(t, previous, rlsSnapshotPolicies(t, db, tbl.name),
				"%s: policy names, commands, qual and with_check must be identical to the previous revision", tbl.name)
		})
	}
}

func TestApplyTenantRLS_CommentStatementQuotesIdentifiersAndLiteral(t *testing.T) {
	got := commentPolicySQL(pq.QuoteIdentifier("sessions"), `po"licy`, "cfgms-rls-def:ab'cd")
	assert.Equal(t, `COMMENT ON POLICY "po""licy" ON "sessions" IS 'cfgms-rls-def:ab''cd'`, got)
}
