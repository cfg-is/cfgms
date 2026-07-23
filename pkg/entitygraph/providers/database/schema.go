// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package database implements the PostgreSQL entity graph provider for CFGMS.
//
// It is the production backend for clustered controller deployments and mirrors
// the SQLite entity graph provider's projection model (observation log →
// current-state → derived index/edge/drift projections) using PostgreSQL syntax:
// BIGSERIAL identities, $N placeholders, ON CONFLICT upserts, and INSERT ...
// RETURNING for log sequence assignment (ADR-022).
package database

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
)

//go:embed migrations.sql
var migrationsSQL string

// Compile-time assertion that the provider satisfies the central contract.
var _ interfaces.EntityGraphProvider = (*DatabaseEntityGraphProvider)(nil)

// errNotFound is the provider-local not-found sentinel. The interfaces package
// intentionally does not export a not-found error, so reads that miss return
// this value for callers to test with errors.Is.
var errNotFound = errors.New("entitygraph/database: not found")

// DatabaseEntityGraphProvider is the PostgreSQL-backed EntityGraphProvider.
// It is safe for concurrent use: all state lives in the connection-pooled
// *sql.DB, and per-observation ingestion is transactional.
type DatabaseEntityGraphProvider struct {
	db *sql.DB
}

// NewDatabaseEntityGraphProvider opens a PostgreSQL connection using dsn,
// initializes the entity graph schema, and returns a ready provider. The caller
// owns the returned provider and must call Close when done.
func NewDatabaseEntityGraphProvider(dsn string) (*DatabaseEntityGraphProvider, error) {
	db, err := openPGDB(dsn)
	if err != nil {
		return nil, err
	}

	if err := initializeSchema(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("entitygraph/database: initialize schema: %w", err)
	}

	return &DatabaseEntityGraphProvider{db: db}, nil
}

// Name returns the provider registry name.
func (p *DatabaseEntityGraphProvider) Name() string { return "database" }

// Description returns a human-readable description of the provider.
func (p *DatabaseEntityGraphProvider) Description() string {
	return "PostgreSQL entity graph provider — production backend for clustered deployments"
}

// Available reports whether the provider is usable. A live connection ping is
// deferred to first use, matching the storage database provider convention.
func (p *DatabaseEntityGraphProvider) Available() (bool, error) {
	return true, nil
}

// Close releases the underlying connection pool.
func (p *DatabaseEntityGraphProvider) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

// openPGDB opens a PostgreSQL database handle and configures the connection
// pool for controller-scale concurrency.
func openPGDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: open connection: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	return db, nil
}

// initializeSchema executes the embedded migrations.sql DDL. The DDL is
// idempotent (CREATE TABLE/INDEX IF NOT EXISTS), so repeated invocation across
// controller nodes is safe.
func initializeSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, migrationsSQL); err != nil {
		return fmt.Errorf("entitygraph/database: exec migrations: %w", err)
	}
	return nil
}
