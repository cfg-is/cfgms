// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements business.NodeRegistryStore using PostgreSQL —
// the shared controller-node registry (Issue #3763, ADR-031 Decision 5's
// post-Raft membership mechanism).
package database

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.NodeRegistryStore = (*DatabaseNodeRegistryStore)(nil)

// DatabaseNodeRegistryStore implements business.NodeRegistryStore using
// PostgreSQL. Every controller node in a cluster deployment shares this
// table through the same database, which is what makes ListNodes report
// peers this process never registered itself.
type DatabaseNodeRegistryStore struct {
	db      *sql.DB
	schemas DatabaseSchemas
}

// NewDatabaseNodeRegistryStore creates a PostgreSQL-backed NodeRegistryStore
// using the shared connection pool db (owned by DatabaseProvider; ADR-031
// Decision 6).
func NewDatabaseNodeRegistryStore(db *sql.DB, config map[string]interface{}) (*DatabaseNodeRegistryStore, error) {
	store := &DatabaseNodeRegistryStore{db: db, schemas: NewDatabaseSchemas()}

	ctx := context.Background()
	if err := store.schemas.CreateNodeRegistryTable(ctx, db); err != nil {
		return nil, fmt.Errorf("failed to create cfgms_node_registry table: %w", err)
	}

	return store, nil
}

// RegisterNode implements business.NodeRegistryStore.RegisterNode. The
// liveness timestamp is derived server-side (now()), never from a caller
// clock, for the same reason RoutingStore.RecordConnection derives it
// server-side: a caller's clock offset must never enter a decision another
// node relies on.
func (s *DatabaseNodeRegistryStore) RegisterNode(ctx context.Context, self business.NodeRecord) error {
	if self.ID == "" {
		return fmt.Errorf("database: node id cannot be empty")
	}

	const query = `
		INSERT INTO cfgms_node_registry (node_id, address, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (node_id) DO UPDATE SET
			address    = EXCLUDED.address,
			updated_at = now()
	`
	if _, err := s.db.ExecContext(ctx, query, self.ID, self.Address); err != nil {
		return fmt.Errorf("failed to register cluster node %q: %w", self.ID, err)
	}
	return nil
}

// ListNodes implements business.NodeRegistryStore.ListNodes. Staleness is
// evaluated in the same query, against the database server's own now(), so a
// record just outside business.NodeRegistryStaleAfter is omitted exactly
// like a never-registered node.
func (s *DatabaseNodeRegistryStore) ListNodes(ctx context.Context) ([]business.NodeRecord, error) {
	const query = `
		SELECT node_id, address
		FROM cfgms_node_registry
		WHERE updated_at >= now() - ($1::double precision * interval '1 second')
	`
	rows, err := s.db.QueryContext(ctx, query, business.NodeRegistryStaleAfter.Seconds())
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []business.NodeRecord
	for rows.Next() {
		var r business.NodeRecord
		if err := rows.Scan(&r.ID, &r.Address); err != nil {
			return nil, fmt.Errorf("failed to scan cluster node row: %w", err)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate cluster node rows: %w", err)
	}
	return records, nil
}

// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseNodeRegistryStore) Close() error {
	return nil
}
