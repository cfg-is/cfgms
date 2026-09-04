// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements business.NodeRegistryStore using the
// cfgms_node_registry table (Issue #3763, ADR-031 Decision 5's post-Raft
// membership mechanism).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.NodeRegistryStore = (*SQLiteNodeRegistryStore)(nil)

// SQLiteNodeRegistryStore implements business.NodeRegistryStore using
// SQLite. The database is a file on the node's own disk, so in a
// non-clustered deployment this store only ever sees the local node's own
// record — harmless, since ListNodes returning peers from another node is
// never reached without a shared substrate. Cluster deployments use the
// database provider instead.
type SQLiteNodeRegistryStore struct {
	db *sql.DB
}

// RegisterNode implements business.NodeRegistryStore.RegisterNode.
func (s *SQLiteNodeRegistryStore) RegisterNode(ctx context.Context, self business.NodeRecord) error {
	if self.ID == "" {
		return fmt.Errorf("sqlite: node id cannot be empty")
	}

	const query = `
		INSERT INTO cfgms_node_registry (node_id, address, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			address = excluded.address,
			updated_at = excluded.updated_at
	`
	if _, err := s.db.ExecContext(ctx, query, self.ID, self.Address, formatTime(nowUTC())); err != nil {
		return fmt.Errorf("sqlite: failed to register cluster node %q: %w", self.ID, err)
	}
	return nil
}

// ListNodes implements business.NodeRegistryStore.ListNodes. Staleness is
// evaluated against nowUTC() — the same process clock formatTime/parseTime
// use elsewhere in this package — so a record just outside
// business.NodeRegistryStaleAfter is omitted exactly like a
// never-registered node.
func (s *SQLiteNodeRegistryStore) ListNodes(ctx context.Context) ([]business.NodeRecord, error) {
	const query = `SELECT node_id, address, updated_at FROM cfgms_node_registry`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list cluster nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []business.NodeRecord
	for rows.Next() {
		var r business.NodeRecord
		var updatedAtStr string
		if err := rows.Scan(&r.ID, &r.Address, &updatedAtStr); err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan cluster node row: %w", err)
		}
		if nowUTC().Sub(parseTime(updatedAtStr)) > business.NodeRegistryStaleAfter {
			continue
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: failed to iterate cluster node rows: %w", err)
	}
	return records, nil
}

// Close closes the underlying database connection.
func (s *SQLiteNodeRegistryStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
