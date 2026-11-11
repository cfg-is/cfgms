// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Schema version model (Epic #5978, zero-downtime schema evolution, N / N-1).
//
// The shared database records the schema version it is at in a single-row table,
// cfgms_schema_version. Every controller node carries two constants:
//
//   - SchemaVersion is the schema version this build creates and expects.
//   - MinToleratedSchemaVersion is the oldest recorded schema version this build
//     still runs against.
//
// The recorded row carries two matching numbers:
//
//   - version is the highest SchemaVersion any node has applied. It only ever rises.
//   - min_node_version is the contract floor: the lowest node SchemaVersion that may
//     still use the database. It is raised only by a contract step (a later story),
//     which removes schema that older nodes depend on.
//
// A node refuses to start (sharedPool returns an error) when the recorded version is
// below its MinToleratedSchemaVersion, or when min_node_version is above its own
// SchemaVersion. A database with no recorded row counts as version 0.
const (
	// SchemaVersion is the schema version this build creates and expects.
	SchemaVersion = 1

	// MinToleratedSchemaVersion is the oldest recorded schema version this build
	// still starts against. Version 0 is a database created before versions were
	// recorded.
	MinToleratedSchemaVersion = 0

	// schemaGateTimeout bounds every statement of the gate. The gate runs while
	// sharedPool holds poolMu, so a stuck database must not be able to hold the
	// provider-wide mutex indefinitely.
	schemaGateTimeout = 10 * time.Second

	// schemaGateLockKey is the transaction-scoped advisory lock that serialises the
	// first-start CREATE TABLE across nodes (concurrent CREATE TABLE IF NOT EXISTS can
	// fail on the catalog's unique index otherwise).
	schemaGateLockKey int64 = 0x63666d7373636d76 // "cfgmsscmv"
)

// ErrSchemaVersionOutOfRange is wrapped by the error sharedPool returns when the
// database's recorded schema version is outside the range this node tolerates.
var ErrSchemaVersionOutOfRange = errors.New("database schema version is outside the range this controller tolerates")

// schemaRange is the range a node tolerates. Production passes the package
// constants; tests inject other ranges.
type schemaRange struct {
	// SchemaVersion is the version this node creates and expects.
	SchemaVersion int
	// MinTolerated is the oldest recorded version this node starts against.
	MinTolerated int
}

// currentSchemaRange is the range of this build.
func currentSchemaRange() schemaRange {
	return schemaRange{SchemaVersion: SchemaVersion, MinTolerated: MinToleratedSchemaVersion}
}

// schemaVersionDDL creates the version record. migrations/017_schema_version.sql
// mirrors it.
//
// The table holds no tenant data (only a version counter), so it has no tenant_id
// column and no row-level security.
const schemaVersionDDL = `
	CREATE TABLE IF NOT EXISTS cfgms_schema_version (
		id                   INTEGER PRIMARY KEY CHECK (id = 1),
		version              INTEGER NOT NULL,
		min_node_version     INTEGER NOT NULL DEFAULT 0,
		contract_applied     INTEGER NOT NULL DEFAULT 0,
		recent_gate_required INTEGER,
		recent_gate_at       TIMESTAMPTZ,
		updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
	)`

// schemaVersionSeed adds the version-0 row. ON CONFLICT keeps concurrent first
// starts converging on one row.
const schemaVersionSeed = `
	INSERT INTO cfgms_schema_version (id, version) VALUES (1, 0)
	ON CONFLICT (id) DO NOTHING`

// checkSchemaVersion is the start-up gate. In one transaction it creates the version
// record if absent, locks the row, refuses when the recorded state is outside r, and
// otherwise raises the recorded version to r.SchemaVersion (never lowering it) and
// records that this node recently passed the gate.
//
// recent_gate_required / recent_gate_at let the contract guard see a node that passed
// the gate but has not registered in the node registry yet: the lowest SchemaVersion
// among gate passes within business.NodeRegistryStaleAfter is kept. The gate and the
// guard serialise on the row lock. A refused node records neither field.
func checkSchemaVersion(ctx context.Context, db *sql.DB, r schemaRange) error {
	ctx, cancel := context.WithTimeout(ctx, schemaGateTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("schema version gate: begin transaction: %w", err)
	}
	if err := runSchemaGate(ctx, tx, r); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("schema version gate: commit: %w", err)
	}
	return nil
}

// runSchemaGate is the body of the gate transaction; the caller commits or rolls back.
func runSchemaGate(ctx context.Context, tx *sql.Tx, r schemaRange) error {
	if err := ensureSchemaVersionRow(ctx, tx); err != nil {
		return err
	}

	var recorded, minNode int
	if err := tx.QueryRowContext(ctx,
		`SELECT version, min_node_version FROM cfgms_schema_version WHERE id = 1 FOR UPDATE`,
	).Scan(&recorded, &minNode); err != nil {
		return fmt.Errorf("schema version gate: read version row: %w", err)
	}

	if err := refuseOutOfRange(recorded, minNode, r); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE cfgms_schema_version SET
			version = GREATEST(version, $1::integer),
			recent_gate_required = LEAST(
				CASE WHEN recent_gate_at >= now() - ($2::double precision * interval '1 second')
				     THEN recent_gate_required END,
				$1::integer),
			recent_gate_at = now(),
			updated_at = now()
		WHERE id = 1`,
		r.SchemaVersion, business.NodeRegistryStaleAfter.Seconds(),
	); err != nil {
		return fmt.Errorf("schema version gate: record version: %w", err)
	}
	return nil
}

// ensureSchemaVersionRow creates the version table and its seed row if absent, under
// the advisory lock that serialises first-start DDL across nodes.
func ensureSchemaVersionRow(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, schemaGateLockKey); err != nil {
		return fmt.Errorf("schema version gate: acquire lock: %w", err)
	}
	if _, err := tx.ExecContext(ctx, schemaVersionDDL); err != nil {
		return fmt.Errorf("schema version gate: create version table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, schemaVersionSeed); err != nil {
		return fmt.Errorf("schema version gate: seed version row: %w", err)
	}
	return nil
}

// refuseOutOfRange returns the refusal error when the recorded state is outside r.
func refuseOutOfRange(recorded, minNode int, r schemaRange) error {
	if recorded < r.MinTolerated {
		return fmt.Errorf("%w: recorded schema version is %d but this controller tolerates %d through %d; "+
			"upgrade the controllers that last wrote the database, or restore a database at a tolerated schema version",
			ErrSchemaVersionOutOfRange, recorded, r.MinTolerated, r.SchemaVersion)
	}
	if minNode > r.SchemaVersion {
		return fmt.Errorf("%w: the database requires controllers at schema version %d or later but this controller is at %d; "+
			"upgrade this controller, or restore a database at a tolerated schema version",
			ErrSchemaVersionOutOfRange, minNode, r.SchemaVersion)
	}
	return nil
}
