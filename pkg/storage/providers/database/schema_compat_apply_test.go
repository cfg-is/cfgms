// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

// Schema compatibility harness for this package's tests (Epic #5978, N / N-1).
//
// The package's store suite can be run against a schema that a different
// revision of the code created. Two environment variables drive that:
//
//   - CFGMS_TEST_KEEP_SCHEMA=1 puts the shared test helpers in keep-schema mode.
//     setupTestDatabase (via resetSchemaForTest) stops dropping tables and instead
//     truncates every table in the current schema, except cfgms_schema_version, so
//     the structure the other revision created survives while the rows are cleared.
//     Tests that need a fresh database or mutate shared schema state call
//     skipInKeepSchemaMode.
//
//   - CFGMS_SCHEMA_COMPAT_APPLY=1 enables TestSchemaCompat_ApplyAllStores, which
//     creates every store the provider offers so that this revision's schema is
//     materialised without the caller knowing which stores the revision has.
//
// Nothing in this file names a store type or a Create*Store method: it must compile
// against any revision of the package.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// schemaCompatApplyEnv enables TestSchemaCompat_ApplyAllStores.
	schemaCompatApplyEnv = "CFGMS_SCHEMA_COMPAT_APPLY"

	// keepSchemaSelfTestEnv is set on the nested test binary started by
	// TestKeepSchemaMode_NoTestDropsSchemaObjects so that the nested run skips that
	// test instead of recursing.
	keepSchemaSelfTestEnv = "CFGMS_KEEP_SCHEMA_SELFTEST"

	// keepSchemaCanaryColumn is added to every table by the no-drop self-test.
	keepSchemaCanaryColumn = "keep_schema_canary"
)

// createStoreMethods returns the name of every exported method of the provider
// called Create*Store that takes a map[string]interface{} and returns two values.
func createStoreMethods() []string {
	configType := reflect.TypeOf(map[string]interface{}{})
	providerType := reflect.TypeOf(&DatabaseProvider{})

	var names []string
	for i := 0; i < providerType.NumMethod(); i++ {
		m := providerType.Method(i)
		if !strings.HasPrefix(m.Name, "Create") || !strings.HasSuffix(m.Name, "Store") {
			continue
		}
		// In: receiver and config. Out: the store and an error.
		if m.Type.NumIn() != 2 || m.Type.In(1) != configType || m.Type.NumOut() != 2 {
			continue
		}
		names = append(names, m.Name)
	}
	return names
}

// createEveryStore calls every Create*Store method the provider offers, which
// creates the tables of every store. An error other than business.ErrNotSupported
// is a failure: a store that needs more configuration than getTestConfig supplies
// must have that configuration added there, never be skipped here.
func createEveryStore(t *testing.T) []string {
	t.Helper()

	provider := &DatabaseProvider{}
	t.Cleanup(func() {
		if closer, ok := interface{}(provider).(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	})

	errorType := reflect.TypeOf((*error)(nil)).Elem()
	methods := createStoreMethods()
	require.NotEmpty(t, methods, "no Create*Store method found on the provider")

	var created []string
	for _, name := range methods {
		method := reflect.ValueOf(provider).MethodByName(name)
		require.True(t, method.IsValid(), "method %s not found", name)

		out := method.Call([]reflect.Value{reflect.ValueOf(getTestConfig())})
		require.True(t, out[1].Type().Implements(errorType), "%s: second result is not an error", name)
		if !out[1].IsNil() {
			err := out[1].Interface().(error)
			if errors.Is(err, business.ErrNotSupported) {
				continue
			}
			require.NoError(t, err, "%s failed", name)
		}
		created = append(created, name)
	}
	return created
}

// TestSchemaCompat_ApplyAllStores materialises the schema of the revision under
// test by creating every store the provider offers.
func TestSchemaCompat_ApplyAllStores(t *testing.T) {
	// This is an operation used by the schema compat script, not an assertion about
	// the code, so it only runs when the script asks for it.
	if os.Getenv(schemaCompatApplyEnv) != "1" {
		t.Skip(schemaCompatApplyEnv + "=1 not set: this test applies the schema for the compat script")
	}

	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	created := createEveryStore(t)
	assert.NotEmpty(t, created, "at least one store must have been created")
}

// currentSchemaTables lists the base tables in the current schema.
func currentSchemaTables(ctx context.Context, t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	tables := map[string]bool{}
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables[name] = true
	}
	require.NoError(t, rows.Err())
	return tables
}

// columnExists reports whether table has the named column in the current schema.
func columnExists(ctx context.Context, t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
		table, column).Scan(&n))
	return n > 0
}

// TestSchemaCompat_ApplyAllStoresCoversKnownStores proves the apply test really
// creates the stores' tables rather than passing without effect.
func TestSchemaCompat_ApplyAllStoresCoversKnownStores(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	t.Setenv(schemaCompatApplyEnv, "1")
	TestSchemaCompat_ApplyAllStores(t)
	require.False(t, t.Failed(), "the apply test failed")

	tables := currentSchemaTables(ctx, t, db)
	// One table from each of the config, audit, session and node-registry stores.
	for _, table := range []string{"configs", "audit_entries", "sessions", "cfgms_node_registry"} {
		assert.True(t, tables[table], "table %s must exist after applying every store", table)
	}
}

// TestSkipInKeepSchemaMode_SkipsOnlyInKeepMode proves the helper skips when
// CFGMS_TEST_KEEP_SCHEMA=1 and does nothing for any other value.
func TestSkipInKeepSchemaMode_SkipsOnlyInKeepMode(t *testing.T) {
	cases := []struct {
		name string
		env  string
		skip bool
	}{
		{"keep mode", "1", true},
		{"unset", "", false},
		{"zero", "0", false},
		{"true is not 1", "true", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(keepSchemaEnv, tc.env)
			reached := false
			var skipped bool
			// A skip ends the goroutine, so it is observed from a nested test.
			t.Run("probe", func(t *testing.T) {
				defer func() {
					skipped = t.Skipped()
				}()
				skipInKeepSchemaMode(t, "keep mode reason")
				reached = true
			})
			assert.Equal(t, tc.skip, !reached, "helper must run the rest of the test only outside keep mode")
			assert.Equal(t, tc.skip, skipped)
		})
	}
}

// TestSetupTestDatabase_KeepSchemaPreservesStructureClearsRows proves keep mode
// leaves a table's structure alone, including a table the Go code does not know
// about, empties its rows, and does not truncate cfgms_schema_version.
func TestSetupTestDatabase_KeepSchemaPreservesStructureClearsRows(t *testing.T) {
	ctx := context.Background()
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	const marker = "keep_schema_marker_table"
	const versionTable = "cfgms_schema_version"

	_, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS `+marker)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `CREATE TABLE `+marker+` (id SERIAL PRIMARY KEY, note TEXT NOT NULL)`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+marker) })
	_, err = db.ExecContext(ctx, `INSERT INTO `+marker+` (note) VALUES ('a'), ('b')`)
	require.NoError(t, err)

	// cfgms_schema_version may already exist (a keep-mode run); create a stand-in
	// only when it does not, and remove only what this test created.
	if !currentSchemaTables(ctx, t, db)[versionTable] {
		_, err = db.ExecContext(ctx, `CREATE TABLE `+versionTable+` (version INTEGER NOT NULL)`)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+versionTable) })
		_, err = db.ExecContext(ctx, `INSERT INTO `+versionTable+` (version) VALUES (1)`)
		require.NoError(t, err)
	}
	var versionRowsBefore int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM `+versionTable).Scan(&versionRowsBefore))
	require.NotZero(t, versionRowsBefore, "the version table needs a row for the survival check to mean anything")

	t.Setenv(keepSchemaEnv, "1")
	keepDB := setupTestDatabase(t)
	defer func() { _ = keepDB.Close() }()

	assert.True(t, currentSchemaTables(ctx, t, db)[marker], "marker table must survive")
	assert.True(t, columnExists(ctx, t, db, marker, "id"), "marker column id must survive")
	assert.True(t, columnExists(ctx, t, db, marker, "note"), "marker column note must survive")

	var rows int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM `+marker).Scan(&rows))
	assert.Zero(t, rows, "marker rows must be gone")

	// RESTART IDENTITY: the sequence starts over.
	var id int
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO `+marker+` (note) VALUES ('c') RETURNING id`).Scan(&id))
	assert.Equal(t, 1, id, "identity must restart after truncation")

	var versionRowsAfter int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM `+versionTable).Scan(&versionRowsAfter))
	assert.Equal(t, versionRowsBefore, versionRowsAfter, "cfgms_schema_version must not be truncated")
}

// keepSchemaRepresentativeTests is a regexp over store tests that exercise the
// helpers which used to drop schema objects: the pending-store per-table drops, the
// benchmark-style setup and setupTestDatabase. Each prefix names a family that must
// actually run, which TestKeepSchemaMode_NoTestDropsSchemaObjects verifies.
var keepSchemaRepresentativeTests = []string{
	"TestDatabaseNodeRegistryStore_",
	"TestDatabaseConfigStore_",
	"TestDatabaseSessionStore_",
	"TestDatabaseStewardStore_",
	"TestDatabaseCommandStore_",
	"TestDatabasePendingRefreshStore_",
	"TestDatabasePendingRegistrationStore_",
	"TestCreatePendingRefreshRequestsTable_FreshTable",
	"TestCreatePendingRegistrationsTable_FreshTable",
}

// TestKeepSchemaMode_NoTestDropsSchemaObjects runs a representative set of the
// package's store tests in keep-schema mode and asserts that a canary column added
// to every table beforehand is still there afterwards. A test that dropped and
// rebuilt a table would silently replace the other revision's schema with this
// revision's, which would make a compat run pass for the wrong reason.
func TestKeepSchemaMode_NoTestDropsSchemaObjects(t *testing.T) {
	if os.Getenv(keepSchemaSelfTestEnv) == "1" {
		t.Skip("nested run started by this test: skipping to prevent recursion")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	// Materialise every store so that the tables the representative tests touch exist.
	createEveryStore(t)

	rows, err := db.QueryContext(ctx, `
		SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema()
		  AND c.relkind = 'r' AND NOT c.relispartition
		  AND c.relname <> 'cfgms_schema_version'
		ORDER BY c.relname`)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.NotEmpty(t, tables)

	for _, table := range tables {
		_, err := db.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s INTEGER`,
			pq.QuoteIdentifier(table), keepSchemaCanaryColumn))
		require.NoError(t, err, "adding canary column to %s", table)
	}
	t.Cleanup(func() {
		for _, table := range tables {
			_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`ALTER TABLE IF EXISTS %s DROP COLUMN IF EXISTS %s`,
				pq.QuoteIdentifier(table), keepSchemaCanaryColumn))
		}
	})

	pattern := "^(" + strings.Join(keepSchemaRepresentativeTests, "|") + ")"
	_, err = regexp.Compile(pattern)
	require.NoError(t, err)

	// #nosec G204 -- re-executes this test binary with fixed, test-defined arguments.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", pattern, "-test.count=1", "-test.v", "-test.timeout=8m")
	cmd.Env = append(os.Environ(), keepSchemaEnv+"=1", keepSchemaSelfTestEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	start := time.Now()
	require.NoError(t, cmd.Run(), "nested keep-mode run failed after %s:\n%s", time.Since(start), tail(out.String(), 8000))

	// A nested run that matched nothing, or skipped everything, proves nothing.
	for _, prefix := range keepSchemaRepresentativeTests {
		assert.Contains(t, out.String(), "--- PASS: "+prefix, "no test of %q passed in the nested run", prefix)
	}

	var missing []string
	for _, table := range tables {
		if !columnExists(ctx, t, db, table, keepSchemaCanaryColumn) {
			missing = append(missing, table)
		}
	}
	sort.Strings(missing)
	assert.Empty(t, missing, "tables whose canary column is gone, i.e. dropped or recreated in keep mode")
}

// tail returns the last n bytes of s.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
