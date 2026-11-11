// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

// Tests for lockSafeDB (Epic #5978): re-applying an up-to-date schema must not
// issue ALTER TABLE ... ADD COLUMN IF NOT EXISTS, because Postgres takes the
// table lock before it evaluates IF NOT EXISTS. The splitter and statement
// parser tests need no database; the rest run against the real Postgres test
// database.

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingExecutor records every statement that reaches the database through
// ExecContext. It sits under lockSafeDB in tests.
type countingExecutor struct {
	*sql.DB
	mu    sync.Mutex
	execs []string
}

func newCountingExecutor(db *sql.DB) *countingExecutor {
	return &countingExecutor{DB: db}
}

func (c *countingExecutor) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	c.mu.Lock()
	c.execs = append(c.execs, query)
	c.mu.Unlock()
	return c.DB.ExecContext(ctx, query, args...)
}

func (c *countingExecutor) sqlDB() *sql.DB { return c.DB }

func (c *countingExecutor) issued() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.execs...)
}

var addColumnTextRe = regexp.MustCompile(`(?i)ADD\s+COLUMN`)

// addColumnCount is the number of issued queries that hold an ADD COLUMN action.
func (c *countingExecutor) addColumnCount() int {
	n := 0
	for _, q := range c.issued() {
		if addColumnTextRe.MatchString(q) {
			n++
		}
	}
	return n
}

var (
	createIndexTextRe = regexp.MustCompile(`(?i)CREATE\s+(UNIQUE\s+)?INDEX`)
	setNotNullTextRe  = regexp.MustCompile(`(?i)SET\s+NOT\s+NULL`)
)

// countMatching is the number of issued queries that match re.
func (c *countingExecutor) countMatching(re *regexp.Regexp) int {
	n := 0
	for _, q := range c.issued() {
		if re.MatchString(q) {
			n++
		}
	}
	return n
}

type namedSchemaMethod struct {
	name string
	run  func(ctx context.Context, db schemaExecutor) error
}

// allSchemaMethods lists every Create* and Backfill* method of DatabaseSchemas, tables
// first, so each Backfill* finds the table it alters.
func allSchemaMethods(s DatabaseSchemas) []namedSchemaMethod {
	return []namedSchemaMethod{
		{"CreateConfigsTable", s.CreateConfigsTable},
		{"CreateConfigHistoryTable", s.CreateConfigHistoryTable},
		{"CreateAuditEntriesTable", s.CreateAuditEntriesTable},
		{"CreateAuditChainHeadsTable", s.CreateAuditChainHeadsTable},
		{"CreateAuditStatsView", s.CreateAuditStatsView},
		{"CreateRBACTables", s.CreateRBACTables},
		{"CreatePendingDeletionsTable", s.CreatePendingDeletionsTable},
		{"CreateTenantTables", s.CreateTenantTables},
		{"CreateRBACPermissionsTable", s.CreateRBACPermissionsTable},
		{"CreateRBACRolesTable", s.CreateRBACRolesTable},
		{"CreateRBACSubjectsTable", s.CreateRBACSubjectsTable},
		{"CreateRBACRoleAssignmentsTable", s.CreateRBACRoleAssignmentsTable},
		{"CreateRegistrationTokensTable", s.CreateRegistrationTokensTable},
		{"CreateLeaseTable", s.CreateLeaseTable},
		{"CreateRoutingTable", s.CreateRoutingTable},
		{"CreateScriptRunTables", s.CreateScriptRunTables},
		{"CreateExecutionQueueTable", s.CreateExecutionQueueTable},
		{"CreateNodeRegistryTable", s.CreateNodeRegistryTable},
		{"CreateCertRevocationsTable", s.CreateCertRevocationsTable},
		{"CreateSigningCursorTable", s.CreateSigningCursorTable},
		{"CreateSigningTrustAckTable", s.CreateSigningTrustAckTable},
		{"CreateModuleApprovalsTable", s.CreateModuleApprovalsTable},
		{"CreateRateCountersTable", s.CreateRateCountersTable},
		{"CreateIPTrustRangesTable", s.CreateIPTrustRangesTable},
		{"CreatePendingRegistrationsTable", s.CreatePendingRegistrationsTable},
		{"CreateAssurancePolicyOverridesTable", s.CreateAssurancePolicyOverridesTable},
		{"CreateBlastRadiusPolicyOverridesTable", s.CreateBlastRadiusPolicyOverridesTable},
		{"CreateTenantCrossingsTable", s.CreateTenantCrossingsTable},
		{"CreateRefreshPoliciesTable", s.CreateRefreshPoliciesTable},
		{"CreatePendingRefreshRequestsTable", s.CreatePendingRefreshRequestsTable},
		{"CreateRefreshNoncesTable", s.CreateRefreshNoncesTable},
		{"CreateSessionsTable", s.CreateSessionsTable},
		{"CreateStewardRecordsTable", s.CreateStewardRecordsTable},
		{"CreateCommandRecordsTable", s.CreateCommandRecordsTable},
		{"CreateRolloutRecordsTable", s.CreateRolloutRecordsTable},
		{"CreateUpgradeRecordsTable", s.CreateUpgradeRecordsTable},
		{"CreateCommandTransitionsTable", s.CreateCommandTransitionsTable},
		{"CreateSessionTokenStoreTable", s.CreateSessionTokenStoreTable},
		{"CreateTriggersTable", s.CreateTriggersTable},
		{"CreatePushRecordsTable", s.CreatePushRecordsTable},
		{"CreateAlertStatesTable", s.CreateAlertStatesTable},
		{"CreateWorkflowApprovalsTable", s.CreateWorkflowApprovalsTable},
		{"CreateReportTemplatesTable", s.CreateReportTemplatesTable},
		{"CreateWorkflowExecutionsTable", s.CreateWorkflowExecutionsTable},
		{"CreateCaseTables", s.CreateCaseTables},
		{"BackfillTenantLifecycle", s.BackfillTenantLifecycle},
		{"BackfillTenantBillingLabel", s.BackfillTenantBillingLabel},
		{"BackfillRegistrationTokenIDs", s.BackfillRegistrationTokenIDs},
		{"BackfillCommandRecordsDeliveryStatus", s.BackfillCommandRecordsDeliveryStatus},
		{"BackfillSessionTokenStoreContinuity", s.BackfillSessionTokenStoreContinuity},
		{"CreateAllTables", s.CreateAllTables},
	}
}

// createEverything applies every schema method once with a plain *sql.DB.
func createEverything(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, m := range allSchemaMethods(NewDatabaseSchemas()) {
		require.NoError(t, m.run(context.Background(), db), m.name)
	}
}

// lockSafeScratchTable creates a scratch table for a test and drops it afterwards.
func lockSafeScratchTable(t *testing.T, db *sql.DB, name, columns string) {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+pq.QuoteIdentifier(name))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "CREATE TABLE "+pq.QuoteIdentifier(name)+" ("+columns+")")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+pq.QuoteIdentifier(name))
	})
}

func columnPresent(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var exists bool
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`,
		table, column).Scan(&exists))
	return exists
}

func TestSplitStatementsRespectsQuotingAndComments(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"empty", "", nil},
		{"only whitespace and semicolons", " ; \n;; ", nil},
		{"two statements", "SELECT 1; SELECT 2;", []string{"SELECT 1", "SELECT 2"}},
		{"no trailing semicolon", "SELECT 1; SELECT 2", []string{"SELECT 1", "SELECT 2"}},
		{"semicolon in single-quoted string", "SELECT 'a;b'; SELECT 2", []string{"SELECT 'a;b'", "SELECT 2"}},
		{"doubled quote in string", "SELECT 'it''s; here'; SELECT 2", []string{"SELECT 'it''s; here'", "SELECT 2"}},
		{"escape string with backslash quote", `SELECT E'a\';b'; SELECT 2`, []string{`SELECT E'a\';b'`, "SELECT 2"}},
		{"backslash is literal in a plain string", `SELECT 'a\'; SELECT 2`, []string{`SELECT 'a\'`, "SELECT 2"}},
		{"semicolon in quoted identifier", `ALTER TABLE "a;b" ADD COLUMN c INT; SELECT 2`, []string{`ALTER TABLE "a;b" ADD COLUMN c INT`, "SELECT 2"}},
		{"doubled quote in identifier", `SELECT "a"";b"; SELECT 2`, []string{`SELECT "a"";b"`, "SELECT 2"}},
		{"dollar-quoted body", "DO $$ BEGIN PERFORM 1; PERFORM 2; END $$; SELECT 2", []string{"DO $$ BEGIN PERFORM 1; PERFORM 2; END $$", "SELECT 2"}},
		{"tagged dollar-quoted body", "DO $body$ BEGIN PERFORM $$x;$$; END $body$; SELECT 2", []string{"DO $body$ BEGIN PERFORM $$x;$$; END $body$", "SELECT 2"}},
		{"parameter is not a dollar quote", "SELECT $1; SELECT $2", []string{"SELECT $1", "SELECT $2"}},
		{"semicolon in line comment", "SELECT 1 -- a; b\n; SELECT 2", []string{"SELECT 1 -- a; b", "SELECT 2"}},
		{"semicolon in block comment", "SELECT 1 /* a; b */; SELECT 2", []string{"SELECT 1 /* a; b */", "SELECT 2"}},
		{"nested block comment", "SELECT 1 /* a /* ; */ ; */; SELECT 2", []string{"SELECT 1 /* a /* ; */ ; */", "SELECT 2"}},
		{"quote inside comment does not open a string", "SELECT 1 -- it's\n; SELECT 2", []string{"SELECT 1 -- it's", "SELECT 2"}},
		{"comment marker inside string is not a comment", "SELECT '-- x'; SELECT 2", []string{"SELECT '-- x'", "SELECT 2"}},
		{"leading comment stays with its statement", "-- why\nSELECT 1;\n/* more */ SELECT 2;", []string{"-- why\nSELECT 1", "/* more */ SELECT 2"}},
		{"comment-only fragment dropped", "SELECT 1; -- trailing\n", []string{"SELECT 1"}},
		{"unterminated string runs to the end", "SELECT 'a; SELECT 2", []string{"SELECT 'a; SELECT 2"}},
		{"unterminated dollar body runs to the end", "SELECT $$ a; b", []string{"SELECT $$ a; b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitSQLStatements(tc.src))
		})
	}
}

func TestParseAddColumnIfNotExists(t *testing.T) {
	tests := []struct {
		name          string
		stmt          string
		table, column string
		ok            bool
	}{
		{"plain", "ALTER TABLE t ADD COLUMN IF NOT EXISTS c INT", "t", "c", true},
		{"mixed case folds", "alter TABLE Foo_Bar Add Column if not exists Baz_Qux TEXT", "foo_bar", "baz_qux", true},
		{"quoted keeps case", `ALTER TABLE "Foo" ADD COLUMN IF NOT EXISTS "Bar" INT`, "Foo", "Bar", true},
		{"quoted with doubled quote", `ALTER TABLE t ADD COLUMN IF NOT EXISTS "a""b" INT`, "t", `a"b`, true},
		{"trailing semicolon-free and multi-line", "ALTER TABLE\n\tt\n ADD COLUMN IF NOT EXISTS\n c\n INT NOT NULL DEFAULT 1", "t", "c", true},
		{"column with nothing after it", "ALTER TABLE t ADD COLUMN IF NOT EXISTS c", "t", "c", true},
		{"leading comments", "-- note\n/* x */ ALTER TABLE t ADD COLUMN IF NOT EXISTS c INT", "t", "c", true},
		{"default with comma in parentheses", "ALTER TABLE t ADD COLUMN IF NOT EXISTS c INT DEFAULT greatest(1, 2)", "t", "c", true},
		{"default with comma in string", "ALTER TABLE t ADD COLUMN IF NOT EXISTS c TEXT DEFAULT 'a,b'", "t", "c", true},
		{"two actions is not matched", "ALTER TABLE t ADD COLUMN IF NOT EXISTS a INT, ADD COLUMN IF NOT EXISTS b INT", "", "", false},
		{"without IF NOT EXISTS", "ALTER TABLE t ADD COLUMN c INT", "", "", false},
		{"schema qualified", "ALTER TABLE s.t ADD COLUMN IF NOT EXISTS c INT", "", "", false},
		{"ONLY", "ALTER TABLE ONLY t ADD COLUMN IF NOT EXISTS c INT", "", "", false},
		{"table IF EXISTS", "ALTER TABLE IF EXISTS t ADD COLUMN IF NOT EXISTS c INT", "", "", false},
		{"other alter", "ALTER TABLE t ALTER COLUMN c SET NOT NULL", "", "", false},
		{"not an alter", "SELECT 'ALTER TABLE t ADD COLUMN IF NOT EXISTS c INT'", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			table, column, ok := parseAddColumnIfNotExists(tc.stmt)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.table, table)
			assert.Equal(t, tc.column, column)
		})
	}
}

func TestLockSafeWrapsOnce(t *testing.T) {
	var base schemaExecutor = &sql.DB{}
	once := lockSafe(base)
	assert.Same(t, once, lockSafe(once), "wrapping a lockSafeDB must return it unchanged")

	raw, err := underlyingSQLDB(once)
	require.NoError(t, err)
	assert.Same(t, base, schemaExecutor(raw))
}

func TestUnderlyingSQLDBRejectsExecutorWithoutDB(t *testing.T) {
	_, err := underlyingSQLDB(struct{ schemaExecutor }{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not expose")
}

func TestLockSafeDBIssuesDDLWhenColumnMissing(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	lockSafeScratchTable(t, db, "lock_safe_missing", "id INT PRIMARY KEY")

	counter := newCountingExecutor(db)
	safe := lockSafe(counter)

	_, err := safe.ExecContext(ctx, "ALTER TABLE lock_safe_missing ADD COLUMN IF NOT EXISTS added_col INT NOT NULL DEFAULT 7")
	require.NoError(t, err)
	assert.Equal(t, 1, counter.addColumnCount(), "a missing column must reach the database")
	assert.True(t, columnPresent(t, db, "lock_safe_missing", "added_col"), "the column must appear")

	// A quoted identifier keeps its case.
	_, err = safe.ExecContext(ctx, `ALTER TABLE lock_safe_missing ADD COLUMN IF NOT EXISTS "MixedCase" INT`)
	require.NoError(t, err)
	assert.True(t, columnPresent(t, db, "lock_safe_missing", "MixedCase"))
	assert.Equal(t, 2, counter.addColumnCount())

	// Now both exist: nothing further reaches the database.
	_, err = safe.ExecContext(ctx, "ALTER TABLE lock_safe_missing ADD COLUMN IF NOT EXISTS added_col INT NOT NULL DEFAULT 7")
	require.NoError(t, err)
	_, err = safe.ExecContext(ctx, `ALTER TABLE lock_safe_missing ADD COLUMN IF NOT EXISTS "MixedCase" INT`)
	require.NoError(t, err)
	assert.Equal(t, 2, counter.addColumnCount(), "an existing column must not be issued again")

	t.Run("a statement error is returned", func(t *testing.T) {
		_, err := safe.ExecContext(ctx, "ALTER TABLE lock_safe_no_such_table ADD COLUMN IF NOT EXISTS c INT")
		require.Error(t, err)
	})
	t.Run("a cancelled context fails the catalog read", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := safe.ExecContext(cancelled, "ALTER TABLE lock_safe_missing ADD COLUMN IF NOT EXISTS added_col INT")
		require.Error(t, err)
	})
}

func TestLockSafeDBFoldsUnquotedIdentifierCase(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	lockSafeScratchTable(t, db, "lock_safe_fold", "id INT PRIMARY KEY, widget INT")

	counter := newCountingExecutor(db)
	safe := lockSafe(counter)

	_, err := safe.ExecContext(ctx, "ALTER TABLE LOCK_SAFE_FOLD ADD COLUMN IF NOT EXISTS Widget INT")
	require.NoError(t, err)
	assert.Empty(t, counter.issued(), "a mixed-case unquoted name folds to the lower-case catalog entry and is skipped")

	// A quoted upper-case name is a different column and is issued.
	_, err = safe.ExecContext(ctx, `ALTER TABLE lock_safe_fold ADD COLUMN IF NOT EXISTS "WIDGET" INT`)
	require.NoError(t, err)
	assert.Equal(t, 1, counter.addColumnCount())
	assert.True(t, columnPresent(t, db, "lock_safe_fold", "WIDGET"))
}

func TestLockSafeDBSplitsMultiStatementStrings(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	name := "lock_safe_multi"
	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+name)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+name) })

	// Mirrors CreateNodeRegistryTable: a CREATE TABLE, then ADD COLUMNs, with a
	// comment, a semicolon inside a string and an ordering dependency on the new
	// column. The catalog is read before anything runs, so the column the table
	// already has is skipped and the one it lacks is kept.
	_, err = db.ExecContext(ctx, `CREATE TABLE lock_safe_multi (id INT PRIMARY KEY, kept TEXT NOT NULL DEFAULT 'a;b')`)
	require.NoError(t, err)
	multi := `
		CREATE TABLE IF NOT EXISTS lock_safe_multi (
			id   INT PRIMARY KEY,
			kept TEXT NOT NULL DEFAULT 'a;b'
		);
		ALTER TABLE lock_safe_multi ADD COLUMN IF NOT EXISTS kept TEXT NOT NULL DEFAULT 'a;b';
		-- a comment; with a semicolon
		ALTER TABLE lock_safe_multi ADD COLUMN IF NOT EXISTS late INT NOT NULL DEFAULT 0;
		INSERT INTO lock_safe_multi (id, kept, late) VALUES (1, 'x;y', 5);
	`
	counter := newCountingExecutor(db)
	_, err = lockSafe(counter).ExecContext(ctx, multi)
	require.NoError(t, err)

	issued := counter.issued()
	require.Len(t, issued, 1, "the remaining statements go in one call")
	assert.NotContains(t, issued[0], "ADD COLUMN IF NOT EXISTS kept", "the up-to-date ADD COLUMN is skipped")
	assert.Contains(t, issued[0], "ADD COLUMN IF NOT EXISTS late", "the ADD COLUMN for a column the CREATE did not make is kept")
	create := strings.Index(issued[0], "CREATE TABLE")
	alter := strings.Index(issued[0], "ADD COLUMN IF NOT EXISTS late")
	insert := strings.Index(issued[0], "INSERT INTO")
	assert.True(t, create >= 0 && create < alter && alter < insert, "statements keep their order: %q", issued[0])

	var kept string
	var late int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT kept, late FROM lock_safe_multi WHERE id = 1").Scan(&kept, &late))
	assert.Equal(t, "x;y", kept)
	assert.Equal(t, 5, late)

	t.Run("nothing skipped passes the string through unchanged", func(t *testing.T) {
		counter := newCountingExecutor(db)
		q := "CREATE TABLE IF NOT EXISTS lock_safe_multi (id INT PRIMARY KEY); SELECT 1"
		_, err := lockSafe(counter).ExecContext(ctx, q)
		require.NoError(t, err)
		assert.Equal(t, []string{q}, counter.issued())
	})
	t.Run("everything skipped issues nothing", func(t *testing.T) {
		counter := newCountingExecutor(db)
		res, err := lockSafe(counter).ExecContext(ctx, `
			ALTER TABLE lock_safe_multi ADD COLUMN IF NOT EXISTS kept TEXT;
			-- only a comment between
			ALTER TABLE lock_safe_multi ADD COLUMN IF NOT EXISTS late INT;`)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Empty(t, counter.issued())
	})
	t.Run("a later statement that fails reports the error and the earlier ones do not commit", func(t *testing.T) {
		counter := newCountingExecutor(db)
		_, err := lockSafe(counter).ExecContext(ctx, `
			ALTER TABLE lock_safe_multi ADD COLUMN IF NOT EXISTS kept TEXT;
			ALTER TABLE lock_safe_multi ADD COLUMN IF NOT EXISTS extra INT;
			INSERT INTO lock_safe_multi (id) VALUES (1);`)
		require.Error(t, err, "duplicate key")
		assert.False(t, columnPresent(t, db, name, "extra"), "the remaining statements keep their single-call atomicity")
	})
	t.Run("a statement with arguments is passed through", func(t *testing.T) {
		counter := newCountingExecutor(db)
		_, err := lockSafe(counter).ExecContext(ctx, "INSERT INTO lock_safe_multi (id) VALUES ($1)", 2)
		require.NoError(t, err)
		assert.Len(t, counter.issued(), 1)
	})
}

// TestSchemaMethodsIssueNoAddColumnWhenUpToDate runs every Create* and Backfill*
// method against a database that already holds the full schema and asserts that
// no ADD COLUMN, CREATE INDEX or SET NOT NULL statement reaches the database.
func TestSchemaMethodsIssueNoAddColumnWhenUpToDate(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	createEverything(t, db)

	counter := newCountingExecutor(db)
	for _, m := range allSchemaMethods(NewDatabaseSchemas()) {
		require.NoError(t, m.run(ctx, counter), m.name)
	}
	for _, q := range counter.issued() {
		assert.NotRegexp(t, addColumnTextRe, q, "an ADD COLUMN reached the database on an up-to-date schema")
		assert.NotRegexp(t, createIndexTextRe, q, "a CREATE INDEX reached the database on an up-to-date schema")
		assert.NotRegexp(t, setNotNullTextRe, q, "a SET NOT NULL reached the database on an up-to-date schema")
	}
	assert.Zero(t, counter.addColumnCount())
	assert.Zero(t, counter.countMatching(createIndexTextRe))
	assert.Zero(t, counter.countMatching(setNotNullTextRe))
	assert.NotEmpty(t, counter.issued(), "the other statements still run")
}

// TestSchemaMethodsAddMissingColumns drops a column each ADD COLUMN-bearing method
// owns and checks the method adds it back.
func TestSchemaMethodsAddMissingColumns(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	createEverything(t, db)
	s := NewDatabaseSchemas()

	tests := []struct {
		table, column string
		run           func(context.Context, schemaExecutor) error
	}{
		{"cfgms_node_registry", "schema_required", s.CreateNodeRegistryTable},
		{"session_token_store", "channel", s.BackfillSessionTokenStoreContinuity},
		{"steward_records", "health_reasons", s.CreateStewardRecordsTable},
	}
	for _, tc := range tests {
		t.Run(tc.table+"."+tc.column, func(t *testing.T) {
			// test-only schema surgery: the removed column is what the method restores.
			_, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", tc.table, tc.column))
			require.NoError(t, err)
			require.False(t, columnPresent(t, db, tc.table, tc.column))

			counter := newCountingExecutor(db)
			require.NoError(t, tc.run(ctx, counter))
			assert.True(t, columnPresent(t, db, tc.table, tc.column))
			assert.Equal(t, 1, counter.addColumnCount())
		})
	}
}

// addColumnLockCases names, for each table that has an ADD COLUMN IF NOT EXISTS in
// schemas.go, the method that re-applies it.
func addColumnLockCases() []struct {
	table string
	run   func(context.Context, schemaExecutor) error
} {
	s := NewDatabaseSchemas()
	both := func(a, b func(context.Context, schemaExecutor) error) func(context.Context, schemaExecutor) error {
		return func(ctx context.Context, db schemaExecutor) error {
			if err := a(ctx, db); err != nil {
				return err
			}
			return b(ctx, db)
		}
	}
	return []struct {
		table string
		run   func(context.Context, schemaExecutor) error
	}{
		{"cases", s.CreateCaseTables},
		{"cfgms_node_registry", s.CreateNodeRegistryTable},
		{"cfgms_pending_registrations", s.CreatePendingRegistrationsTable},
		{"cfgms_push_records", s.CreatePushRecordsTable},
		{"cfgms_rate_counters", s.CreateRateCountersTable},
		{"cfgms_registration_tokens", both(s.BackfillRegistrationTokenIDs, s.CreateRegistrationTokensTable)},
		{"cfgms_script_run_jobs", s.CreateScriptRunTables},
		{"cfgms_script_runs", s.CreateScriptRunTables},
		{"cfgms_tenants", both(s.BackfillTenantLifecycle, s.BackfillTenantBillingLabel)},
		{"command_records", s.BackfillCommandRecordsDeliveryStatus},
		{"pending_refresh_requests", s.CreatePendingRefreshRequestsTable},
		{"session_token_store", s.BackfillSessionTokenStoreContinuity},
		{"steward_records", s.CreateStewardRecordsTable},
		{"tenant_crossings", s.CreateTenantCrossingsTable},
	}
}

// addColumnTablesInSchemas lists the tables schemas.go alters with ADD COLUMN IF
// NOT EXISTS, so a new one cannot be added without a lock case.
func addColumnTablesInSchemas(t *testing.T) []string {
	t.Helper()
	stmts := collectPackageStatements(t)
	seen := map[string]bool{}
	var tables []string
	for _, st := range stmts {
		if st.File != "schemas.go" {
			continue
		}
		if table, _, ok := parseAddColumnIfNotExists(st.Text); ok && !seen[table] {
			seen[table] = true
			tables = append(tables, table)
		}
	}
	return tables
}

func TestAddColumnLockCasesCoverSchemas(t *testing.T) {
	var covered []string
	for _, tc := range addColumnLockCases() {
		covered = append(covered, tc.table)
	}
	assert.ElementsMatch(t, uniqueStrings(covered), addColumnTablesInSchemas(t),
		"every table with an ADD COLUMN IF NOT EXISTS in schemas.go needs a case in addColumnLockCases")
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// TestReapplyAddColumnTakesNoConflictingLock holds an open transaction that has
// read a table on a second connection (an ACCESS SHARE lock) and re-applies the
// schema method for that table under a 2s deadline. An ALTER TABLE needs ACCESS
// EXCLUSIVE, so any ADD COLUMN that reaches the database queues behind the reader
// and the deadline expires.
func TestReapplyAddColumnTakesNoConflictingLock(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	createEverything(t, db)

	for _, tc := range addColumnLockCases() {
		t.Run(tc.table, func(t *testing.T) {
			reader, err := db.BeginTx(context.Background(), nil)
			require.NoError(t, err)
			defer func() { _ = reader.Rollback() }()
			var n int
			require.NoError(t, reader.QueryRowContext(context.Background(),
				"SELECT count(*) FROM "+pq.QuoteIdentifier(tc.table)).Scan(&n))

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			require.NoError(t, tc.run(ctx, db), "re-applying %s must not wait on the reader's lock", tc.table)
		})
	}
}

func TestParseCreateIndexIfNotExists(t *testing.T) {
	tests := []struct {
		name  string
		stmt  string
		index string
		ok    bool
	}{
		{"plain", "CREATE INDEX IF NOT EXISTS idx_a ON t (a)", "idx_a", true},
		{"unique", "CREATE UNIQUE INDEX IF NOT EXISTS idx_a ON t (a)", "idx_a", true},
		{"concurrently", "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t (a)", "idx_a", true},
		{"lower case, tabs and newlines", "create\tunique\nindex if not exists  Idx_A\nON t(a)", "idx_a", true},
		{"quoted name keeps case", `CREATE INDEX IF NOT EXISTS "Idx_A" ON t (a)`, "Idx_A", true},
		{"quoted name with doubled quote", `CREATE INDEX IF NOT EXISTS "a""b" ON t (a)`, `a"b`, true},
		{"leading comment", "-- why\nCREATE INDEX IF NOT EXISTS idx_a ON t (a)", "idx_a", true},
		{"partial index", "CREATE INDEX IF NOT EXISTS idx_a ON t (a) WHERE a <> ''", "idx_a", true},
		{"no IF NOT EXISTS", "CREATE INDEX idx_a ON t (a)", "", false},
		{"not an index", "CREATE TABLE IF NOT EXISTS idx_a (a INT)", "", false},
		{"drop index", "DROP INDEX IF EXISTS idx_a", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			index, ok := parseCreateIndexIfNotExists(tc.stmt)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.index, index)
		})
	}
}

func TestParseSetNotNull(t *testing.T) {
	tests := []struct {
		name          string
		stmt          string
		table, column string
		ok            bool
	}{
		{"plain", "ALTER TABLE t ALTER COLUMN c SET NOT NULL", "t", "c", true},
		{"trailing semicolon", "ALTER TABLE t ALTER COLUMN c SET NOT NULL;", "t", "c", true},
		{"COLUMN keyword optional", "ALTER TABLE t ALTER c SET NOT NULL", "t", "c", true},
		{"folds case", "ALTER TABLE T ALTER COLUMN C SET NOT NULL", "t", "c", true},
		{"quoted keeps case", `ALTER TABLE "T" ALTER COLUMN "C" SET NOT NULL`, "T", "C", true},
		{"leading comment", "-- why\nALTER TABLE t ALTER COLUMN c SET NOT NULL", "t", "c", true},
		{"schema qualified table", "ALTER TABLE s.t ALTER COLUMN c SET NOT NULL", "", "", false},
		{"ONLY", "ALTER TABLE ONLY t ALTER COLUMN c SET NOT NULL", "", "", false},
		{"second action", "ALTER TABLE t ALTER COLUMN c SET NOT NULL, ALTER COLUMN d SET NOT NULL", "", "", false},
		{"drop not null", "ALTER TABLE t ALTER COLUMN c DROP NOT NULL", "", "", false},
		{"set default", "ALTER TABLE t ALTER COLUMN c SET DEFAULT 1", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			table, column, ok := parseSetNotNull(tc.stmt)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.table, table)
			assert.Equal(t, tc.column, column)
		})
	}
}

func indexValidity(t *testing.T, db *sql.DB, index string) (exists, valid bool) {
	t.Helper()
	err := db.QueryRowContext(context.Background(),
		`SELECT i.indisvalid FROM pg_index i
			JOIN pg_class c ON c.oid = i.indexrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = current_schema() AND c.relname = $1`, index).Scan(&valid)
	if err == sql.ErrNoRows {
		return false, false
	}
	require.NoError(t, err)
	return true, valid
}

func columnIsNullable(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var nullable string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT is_nullable FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
		table, column).Scan(&nullable))
	return nullable == "YES"
}

func TestLockSafeDBCreatesMissingIndex(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	lockSafeScratchTable(t, db, "lock_safe_idx", "id INT PRIMARY KEY, a INT, b INT")

	counter := newCountingExecutor(db)
	safe := lockSafe(counter)

	_, err := safe.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS lock_safe_idx_a ON lock_safe_idx (a)")
	require.NoError(t, err)
	assert.Equal(t, 1, counter.countMatching(createIndexTextRe), "a missing index must reach the database")
	exists, valid := indexValidity(t, db, "lock_safe_idx_a")
	assert.True(t, exists, "the index must be created")
	assert.True(t, valid)

	// A unique index, a quoted mixed-case name and a partial index are created too.
	_, err = safe.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS lock_safe_idx_b ON lock_safe_idx (b) WHERE b IS NOT NULL")
	require.NoError(t, err)
	_, err = safe.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS "Lock_Safe_Idx_Mixed" ON lock_safe_idx (a, b)`)
	require.NoError(t, err)
	assert.Equal(t, 3, counter.countMatching(createIndexTextRe))
	exists, _ = indexValidity(t, db, "lock_safe_idx_b")
	assert.True(t, exists)
	exists, _ = indexValidity(t, db, "Lock_Safe_Idx_Mixed")
	assert.True(t, exists, "a quoted name keeps its case")

	// Every index now exists and is valid: nothing further reaches the database,
	// whatever the case of an unquoted name.
	for _, q := range []string{
		"CREATE INDEX IF NOT EXISTS lock_safe_idx_a ON lock_safe_idx (a)",
		"CREATE INDEX IF NOT EXISTS LOCK_SAFE_IDX_A ON lock_safe_idx (a)",
		"CREATE UNIQUE INDEX IF NOT EXISTS lock_safe_idx_b ON lock_safe_idx (b) WHERE b IS NOT NULL",
		`CREATE INDEX IF NOT EXISTS "Lock_Safe_Idx_Mixed" ON lock_safe_idx (a, b)`,
	} {
		_, err := safe.ExecContext(ctx, q)
		require.NoError(t, err, q)
	}
	assert.Equal(t, 3, counter.countMatching(createIndexTextRe), "an existing valid index must not be issued again")

	t.Run("a missing index in a multi-statement string is kept in order", func(t *testing.T) {
		counter := newCountingExecutor(db)
		_, err := lockSafe(counter).ExecContext(ctx, `
			CREATE INDEX IF NOT EXISTS lock_safe_idx_a ON lock_safe_idx (a);
			ALTER TABLE lock_safe_idx ADD COLUMN IF NOT EXISTS c INT;
			CREATE INDEX IF NOT EXISTS lock_safe_idx_c ON lock_safe_idx (c);`)
		require.NoError(t, err)
		issued := counter.issued()
		require.Len(t, issued, 1)
		assert.NotContains(t, issued[0], "lock_safe_idx_a")
		assert.Less(t, strings.Index(issued[0], "ADD COLUMN"), strings.Index(issued[0], "lock_safe_idx_c"))
		exists, valid := indexValidity(t, db, "lock_safe_idx_c")
		assert.True(t, exists && valid)
	})
	t.Run("a statement error is returned", func(t *testing.T) {
		_, err := safe.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS lock_safe_idx_bad ON lock_safe_idx (no_such_column)")
		require.Error(t, err)
	})
	t.Run("a cancelled context fails the catalog read", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := safe.ExecContext(cancelled, "CREATE INDEX IF NOT EXISTS lock_safe_idx_a ON lock_safe_idx (a)")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to check for index")
	})
}

func TestLockSafeDBSetsNotNullWhenNullable(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	lockSafeScratchTable(t, db, "lock_safe_nn", "id INT PRIMARY KEY, c INT, d INT NOT NULL DEFAULT 0")

	counter := newCountingExecutor(db)
	safe := lockSafe(counter)
	require.True(t, columnIsNullable(t, db, "lock_safe_nn", "c"))

	_, err := safe.ExecContext(ctx, "ALTER TABLE lock_safe_nn ALTER COLUMN c SET NOT NULL;")
	require.NoError(t, err)
	assert.Equal(t, 1, counter.countMatching(setNotNullTextRe), "a nullable column must be altered")
	assert.False(t, columnIsNullable(t, db, "lock_safe_nn", "c"), "the column must become NOT NULL")

	// Already NOT NULL, by this statement or by its definition: nothing is issued,
	// and an unquoted name folds to lower case.
	_, err = safe.ExecContext(ctx, "ALTER TABLE lock_safe_nn ALTER COLUMN c SET NOT NULL;")
	require.NoError(t, err)
	_, err = safe.ExecContext(ctx, "ALTER TABLE LOCK_SAFE_NN ALTER COLUMN D SET NOT NULL")
	require.NoError(t, err)
	_, err = safe.ExecContext(ctx, "ALTER TABLE lock_safe_nn ALTER COLUMN id SET NOT NULL")
	require.NoError(t, err)
	assert.Equal(t, 1, counter.countMatching(setNotNullTextRe), "an already NOT NULL column must not be issued again")

	t.Run("a column that cannot take NOT NULL reports the error", func(t *testing.T) {
		lockSafeScratchTable(t, db, "lock_safe_nn_rows", "id INT PRIMARY KEY, c INT")
		_, err := db.ExecContext(ctx, "INSERT INTO lock_safe_nn_rows (id) VALUES (1)")
		require.NoError(t, err)
		_, err = lockSafe(newCountingExecutor(db)).ExecContext(ctx, "ALTER TABLE lock_safe_nn_rows ALTER COLUMN c SET NOT NULL")
		require.Error(t, err)
		assert.True(t, columnIsNullable(t, db, "lock_safe_nn_rows", "c"))
	})
	t.Run("a missing column is passed through and fails as before", func(t *testing.T) {
		counter := newCountingExecutor(db)
		_, err := lockSafe(counter).ExecContext(ctx, "ALTER TABLE lock_safe_nn ALTER COLUMN no_such SET NOT NULL")
		require.Error(t, err)
		assert.Equal(t, 1, counter.countMatching(setNotNullTextRe))
	})
	t.Run("a cancelled context fails the catalog read", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := safe.ExecContext(cancelled, "ALTER TABLE lock_safe_nn ALTER COLUMN c SET NOT NULL")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to check nullability")
	})
}

func TestLockSafeDBInvalidIndexPassesThrough(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	lockSafeScratchTable(t, db, "lock_safe_invalid", "id INT PRIMARY KEY, a INT")

	// A unique index built CONCURRENTLY over duplicate rows fails and leaves an
	// INVALID index behind.
	_, err := db.ExecContext(ctx, "INSERT INTO lock_safe_invalid (id, a) VALUES (1, 7), (2, 7)")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "CREATE UNIQUE INDEX CONCURRENTLY lock_safe_invalid_a ON lock_safe_invalid (a)")
	require.Error(t, err, "duplicate rows must fail the concurrent build")
	exists, valid := indexValidity(t, db, "lock_safe_invalid_a")
	require.True(t, exists, "the failed build leaves its index behind")
	require.False(t, valid, "the leftover index is invalid")

	counter := newCountingExecutor(db)
	stmt := "CREATE UNIQUE INDEX IF NOT EXISTS lock_safe_invalid_a ON lock_safe_invalid (a)"
	_, err = lockSafe(counter).ExecContext(ctx, stmt)
	require.NoError(t, err, "IF NOT EXISTS on the existing relation is a no-op for the database")
	assert.Equal(t, []string{stmt}, counter.issued(), "an invalid index passes through byte for byte")

	// Not re-created or repaired here: that is a deliberate rebuild.
	_, valid = indexValidity(t, db, "lock_safe_invalid_a")
	assert.False(t, valid)
}

var createTableNameRe = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+(` + sqlIdentPattern + `)`)

// tablesCreatedBySchemaMethods maps each table to the schema methods that issue its
// CREATE TABLE IF NOT EXISTS. It runs every method against an up-to-date database
// and reads what reaches it, so a new table is covered without a hand-kept list.
func tablesCreatedBySchemaMethods(t *testing.T, db *sql.DB) map[string][]namedSchemaMethod {
	t.Helper()
	out := map[string][]namedSchemaMethod{}
	for _, m := range allSchemaMethods(NewDatabaseSchemas()) {
		if m.name == "CreateAllTables" {
			continue // it only calls the others
		}
		counter := newCountingExecutor(db)
		require.NoError(t, m.run(context.Background(), counter), m.name)
		seen := map[string]bool{}
		for _, q := range counter.issued() {
			for _, match := range createTableNameRe.FindAllStringSubmatch(q, -1) {
				table := foldIdentifier(match[1])
				if !seen[table] {
					seen[table] = true
					out[table] = append(out[table], m)
				}
			}
		}
	}
	return out
}

// TestReapplyTakesNoConflictingLock holds, for every table the schema creates, an
// open transaction on a second connection that has read the table (ACCESS SHARE) and,
// in a second variant, one that has written to it (ROW EXCLUSIVE, the lock a write
// takes), then re-applies the schema methods that create that table under a 2s
// deadline. Any statement that reaches the database and needs a conflicting lock
// (ALTER TABLE ... ADD COLUMN or SET NOT NULL needs ACCESS EXCLUSIVE, CREATE INDEX
// needs SHARE, which a writer blocks) queues behind the holder and the deadline
// expires.
func TestReapplyTakesNoConflictingLock(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	createEverything(t, db)

	creators := tablesCreatedBySchemaMethods(t, db)
	var tables []string
	for table := range creators {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	require.GreaterOrEqual(t, len(tables), 40, "the schema methods create many tables; found %v", tables)

	// Every table schemas.go creates with a literal name must be among them.
	for _, st := range collectPackageStatements(t) {
		if st.File != "schemas.go" {
			continue
		}
		if m := createTableNameRe.FindStringSubmatch(st.Text); m != nil {
			assert.Contains(t, creators, foldIdentifier(m[1]), "no schema method re-applies %s", m[1])
		}
	}

	variants := []struct {
		name string
		hold func(ctx context.Context, tx *sql.Tx, quotedTable string) error
	}{
		{"read", func(ctx context.Context, tx *sql.Tx, quotedTable string) error {
			var n int
			return tx.QueryRowContext(ctx, "SELECT count(*) FROM "+quotedTable).Scan(&n)
		}},
		{"write", func(ctx context.Context, tx *sql.Tx, quotedTable string) error {
			// Takes the ROW EXCLUSIVE table lock of any write without touching a row.
			_, err := tx.ExecContext(ctx, "DELETE FROM "+quotedTable+" WHERE false")
			return err
		}},
	}
	for _, table := range tables {
		for _, v := range variants {
			t.Run(table+"/"+v.name, func(t *testing.T) {
				holder, err := db.BeginTx(context.Background(), nil)
				require.NoError(t, err)
				defer func() { _ = holder.Rollback() }()
				require.NoError(t, v.hold(context.Background(), holder, pq.QuoteIdentifier(table)))

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				for _, m := range creators[table] {
					require.NoError(t, m.run(ctx, db), "re-applying %s for %s must not wait on the %s lock", m.name, table, v.name)
				}
			})
		}
	}
}
