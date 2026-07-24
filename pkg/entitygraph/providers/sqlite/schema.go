// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package sqlite implements the SQLite entity graph provider for CFGMS.
//
// This is the OSS default entity-graph backend for single-instance
// deployments (ADR-022/ADR-023). It uses modernc.org/sqlite, a pure-Go port
// of SQLite that builds with CGO_ENABLED=0 and cross-compiles cleanly to all
// controller platforms.
//
// The store is observation-first: every write is an append to an
// observation log (eg_observation_log). Current-state and index projections
// are derived from that log and can always be rebuilt via RebuildProjections.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite" // Pure-Go SQLite driver (CGO-free)

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
)

// Compile-time assertion that SQLiteEntityGraphProvider satisfies the contract.
var _ interfaces.EntityGraphProvider = (*SQLiteEntityGraphProvider)(nil)

// ErrNotFound is returned when a requested entity has no current-state
// projection (or is filtered out by the caller's tenant cut).
var ErrNotFound = errors.New("entitygraph: not found")

// SQLiteEntityGraphProvider is the SQLite-backed EntityGraphProvider.
// It is safe for concurrent use: all writes go through short transactions and
// SQLite (WAL mode) serialises writers while permitting concurrent readers.
type SQLiteEntityGraphProvider struct {
	db *sql.DB
}

// NewSQLiteEntityGraphProvider opens (or creates) the entity-graph database at
// path, runs schema initialisation, and returns a ready provider.
//
// path may be ":memory:", a "file:" DSN, or a plain filesystem path.
func NewSQLiteEntityGraphProvider(path string) (*SQLiteEntityGraphProvider, error) {
	db, err := openDB(path)
	if err != nil {
		return nil, err
	}
	if err := initializeSchema(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("entitygraph/sqlite: schema initialisation failed: %w", err)
	}
	return &SQLiteEntityGraphProvider{db: db}, nil
}

// Name returns the provider name used for registration and lookup.
func (p *SQLiteEntityGraphProvider) Name() string { return "sqlite" }

// Description returns a human-readable description of the provider.
func (p *SQLiteEntityGraphProvider) Description() string {
	return "SQLite entity graph provider — OSS default for single-instance deployments"
}

// Available reports whether the provider is usable. The pure-Go SQLite driver
// is always linked in, so this is always true.
func (p *SQLiteEntityGraphProvider) Available() (bool, error) { return true, nil }

// Close closes the underlying database connection pool.
func (p *SQLiteEntityGraphProvider) Close() error {
	if p.db == nil {
		return nil
	}
	return p.db.Close()
}

// openDB opens (or creates) a SQLite database at path and enables WAL mode and
// foreign keys. Pragmas are passed via DSN _pragma= tokens so every pooled
// connection applies them (see pkg/storage/providers/sqlite for the rationale).
func openDB(path string) (*sql.DB, error) {
	const pragmas = "_pragma=busy_timeout(15000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"

	var dsn string
	switch {
	case path == ":memory:":
		dsn = "file::memory:?cache=shared&" + pragmas
	case strings.HasPrefix(path, "file:"):
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		dsn = path + sep + pragmas
	default:
		dsn = "file:" + path + "?" + pragmas
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: open %s: %w", path, err)
	}

	// SQLite WAL mode allows one writer at a time. Using a single connection
	// serialises writes at the database/sql pool level, avoiding SQLITE_BUSY
	// under concurrent goroutines (modernc.org/sqlite does not reliably honour
	// PRAGMA busy_timeout across pool connections). In-memory mode additionally
	// requires a single connection to keep the backing store alive for the
	// pool's lifetime.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("entitygraph/sqlite: ping %s: %w", path, err)
	}
	return db, nil
}

// schemaStatements is the ordered DDL that establishes the entity-graph schema.
//
// All tables are prefixed eg_ to avoid collisions with the business-data
// schema when both share a database file. The observation log uses
// INTEGER PRIMARY KEY AUTOINCREMENT (never a bare rowid) so log sequence
// numbers are monotonic and never reused after deletion (ADR-023 §5).
var schemaStatements = []string{
	// Content-hash-deduped payload blobs. payload_hash is SHA-256(json) hex.
	`CREATE TABLE IF NOT EXISTS eg_payload_content (
		payload_hash TEXT PRIMARY KEY,
		payload      TEXT NOT NULL
	)`,

	// Append-only observation log — the source of truth. Projections derive
	// from it and can be rebuilt at any time.
	`CREATE TABLE IF NOT EXISTS eg_observation_log (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		subject         TEXT NOT NULL,
		source          TEXT NOT NULL,
		source_class    TEXT NOT NULL,
		observed_at     TEXT NOT NULL,
		recorded_at     TEXT NOT NULL,
		kind            TEXT NOT NULL,
		confidence      TEXT NOT NULL,
		claim_scope_key TEXT NOT NULL DEFAULT '',
		payload_hash    TEXT NOT NULL,
		tenant_path     TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS eg_observation_log_subject ON eg_observation_log(subject)`,
	`CREATE INDEX IF NOT EXISTS eg_observation_log_subject_source ON eg_observation_log(subject, source)`,

	// Current-state projection: highest-seq observation per (subject, source).
	`CREATE TABLE IF NOT EXISTS eg_entity_current (
		subject      TEXT NOT NULL,
		source       TEXT NOT NULL,
		source_class TEXT NOT NULL,
		kind         TEXT NOT NULL,
		confidence   TEXT NOT NULL,
		observed_at  TEXT NOT NULL,
		recorded_at  TEXT NOT NULL,
		payload_hash TEXT NOT NULL,
		tenant_path  TEXT NOT NULL DEFAULT '',
		log_seq      INTEGER NOT NULL,
		PRIMARY KEY (subject, source)
	)`,
	`CREATE INDEX IF NOT EXISTS eg_entity_current_subject ON eg_entity_current(subject)`,

	// Entity type/tenant/identity index for QueryEntities and ResolveIdentity.
	// owning_tenant is the ONLY access-control axis (ADR-023 §111-119); the
	// tenant_path columns elsewhere are ingest-time provenance only.
	`CREATE TABLE IF NOT EXISTS eg_entity_index (
		subject         TEXT PRIMARY KEY,
		entity_kind     TEXT NOT NULL DEFAULT '',
		owning_tenant   TEXT NOT NULL DEFAULT '',
		hostname        TEXT NOT NULL DEFAULT '',
		mac_addrs       TEXT NOT NULL DEFAULT '',
		machine_sid     TEXT NOT NULL DEFAULT '',
		dir_object_guid TEXT NOT NULL DEFAULT '',
		serial_number   TEXT NOT NULL DEFAULT '',
		cloud_object_id TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS eg_entity_index_kind ON eg_entity_index(entity_kind)`,
	`CREATE INDEX IF NOT EXISTS eg_entity_index_tenant ON eg_entity_index(owning_tenant)`,
	`CREATE INDEX IF NOT EXISTS eg_entity_index_hostname ON eg_entity_index(hostname)`,
	`CREATE INDEX IF NOT EXISTS eg_entity_index_machine_sid ON eg_entity_index(machine_sid)`,
	`CREATE INDEX IF NOT EXISTS eg_entity_index_dir_guid ON eg_entity_index(dir_object_guid)`,
	`CREATE INDEX IF NOT EXISTS eg_entity_index_serial ON eg_entity_index(serial_number)`,
	`CREATE INDEX IF NOT EXISTS eg_entity_index_cloud_id ON eg_entity_index(cloud_object_id)`,

	// Edge projection — populated by STORY-3. edge_key encodes uniqueness as
	// from_subject + "\x1f" + edge_type + "\x1f" + to_subject + "\x1f" + source.
	`CREATE TABLE IF NOT EXISTS eg_edge_projection (
		edge_key     TEXT PRIMARY KEY,
		edge_type    TEXT NOT NULL DEFAULT '',
		from_subject TEXT NOT NULL DEFAULT '',
		to_subject   TEXT NOT NULL DEFAULT '',
		source       TEXT NOT NULL DEFAULT '',
		source_class TEXT NOT NULL DEFAULT '',
		observed_at  TEXT NOT NULL DEFAULT '',
		payload_hash TEXT NOT NULL DEFAULT '',
		log_seq      INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS eg_edge_proj_from ON eg_edge_projection(from_subject)`,
	`CREATE INDEX IF NOT EXISTS eg_edge_proj_to   ON eg_edge_projection(to_subject)`,

	// Drift projection — populated by a later story. Created now (empty).
	`CREATE TABLE IF NOT EXISTS eg_drift_projection (
		subject          TEXT PRIMARY KEY,
		detected_at      TEXT NOT NULL DEFAULT '',
		config_revision  TEXT NOT NULL DEFAULT '',
		lifecycle_status TEXT NOT NULL DEFAULT 'detected',
		fields           TEXT NOT NULL DEFAULT ''
	)`,

	// Claim-scope prior-assertion tracking — populated by STORY-4. Empty now.
	`CREATE TABLE IF NOT EXISTS eg_claim_scope_prior (
		scope_key TEXT PRIMARY KEY,
		source    TEXT NOT NULL DEFAULT '',
		as_of     TEXT NOT NULL DEFAULT '',
		subjects  TEXT NOT NULL DEFAULT ''
	)`,

	// Per-tenant-subtree retention policy overrides (ADR-023 §7).
	// history_days=0 means "use global default". tombstone_days=0 means history+7.
	// The most-specific matching tenant_path prefix wins at GC time.
	`CREATE TABLE IF NOT EXISTS eg_retention_policy (
		tenant_path    TEXT PRIMARY KEY,
		history_days   INTEGER NOT NULL DEFAULT 0,
		tombstone_days INTEGER NOT NULL DEFAULT 0
	)`,
}

// egTableExists reports whether the named table is present in the SQLite schema catalog.
func egTableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&count)
	return count > 0, err
}

// egColumnExists reports whether the named column is present in the given table.
// SQLite PRAGMA does not support ? binding, so only literal table/column names
// from trusted call-sites may be passed.
func egColumnExists(ctx context.Context, db *sql.DB, table, column string) (found bool, retErr error) {
	// #nosec G202 -- PRAGMA does not support ? binding; caller passes only literals.
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, err
	}
	defer func() {
		if err := rows.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()
	for rows.Next() {
		var cid, notNull, pk int
		var colName, colType string
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if colName == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// backfillEdgeProjection adds the source, source_class, and observed_at columns
// to an eg_edge_projection table created by STORY-2 before those columns existed,
// and creates the from/to indexes. It is idempotent: presence of each column is
// checked via PRAGMA before ALTER TABLE is attempted.
func backfillEdgeProjection(ctx context.Context, db *sql.DB) error {
	exists, err := egTableExists(ctx, db, "eg_edge_projection")
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: probe eg_edge_projection: %w", err)
	}
	if !exists {
		return nil
	}

	type colDef struct {
		name string
		ddl  string
	}
	for _, c := range []colDef{
		{"source", `ALTER TABLE eg_edge_projection ADD COLUMN source TEXT NOT NULL DEFAULT ''`},
		{"source_class", `ALTER TABLE eg_edge_projection ADD COLUMN source_class TEXT NOT NULL DEFAULT ''`},
		{"observed_at", `ALTER TABLE eg_edge_projection ADD COLUMN observed_at TEXT NOT NULL DEFAULT ''`},
	} {
		present, err := egColumnExists(ctx, db, "eg_edge_projection", c.name)
		if err != nil {
			return fmt.Errorf("entitygraph/sqlite: probe column %s: %w", c.name, err)
		}
		if present {
			continue
		}
		if _, err := db.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("entitygraph/sqlite: add column %s: %w", c.name, err)
		}
	}

	// Indexes are idempotent due to IF NOT EXISTS.
	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS eg_edge_proj_from ON eg_edge_projection(from_subject)`,
		`CREATE INDEX IF NOT EXISTS eg_edge_proj_to   ON eg_edge_projection(to_subject)`,
	} {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("entitygraph/sqlite: create index: %w", err)
		}
	}
	return nil
}

// initializeSchema creates all entity-graph tables and indexes in a single
// transaction. It is idempotent (every statement uses IF NOT EXISTS).
// After the DDL pass, it runs backfill migrations for databases created by
// earlier story revisions that may be missing columns.
func initializeSchema(ctx context.Context, db *sql.DB) error {
	// Backfill before the DDL pass so that ALTER TABLE runs on the old schema
	// before CREATE TABLE IF NOT EXISTS is a no-op for existing tables.
	if err := backfillEdgeProjection(ctx, db); err != nil {
		return fmt.Errorf("entitygraph/sqlite: backfill edge projection: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: begin schema tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range schemaStatements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("entitygraph/sqlite: schema statement failed: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entitygraph/sqlite: commit schema tx: %w", err)
	}
	return nil
}
