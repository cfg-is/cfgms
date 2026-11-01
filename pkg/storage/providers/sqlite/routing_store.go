// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements business.RoutingStore using the cfgms_routing
// table (ADR-031 Decision 3, Issue #3764).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.RoutingStore = (*SQLiteRoutingStore)(nil)

// SQLiteRoutingStore implements business.RoutingStore using SQLite. The
// database is a file on the node's own disk, so in a non-clustered
// deployment this store only ever sees the local node's own records — which
// is harmless, since LookupNode from any other node is never reached without
// a shared substrate. Cluster deployments use the database provider instead.
type SQLiteRoutingStore struct {
	db *sql.DB
}

// RecordConnection implements business.RoutingStore.RecordConnection.
func (s *SQLiteRoutingStore) RecordConnection(ctx context.Context, stewardID, nodeID string) error {
	if stewardID == "" {
		return fmt.Errorf("sqlite: steward id cannot be empty")
	}
	if nodeID == "" {
		return fmt.Errorf("sqlite: node id cannot be empty")
	}

	const query = `
		INSERT INTO cfgms_routing (steward_id, node_id, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(steward_id) DO UPDATE SET
			node_id = excluded.node_id,
			updated_at = excluded.updated_at
	`
	if _, err := s.db.ExecContext(ctx, query, stewardID, nodeID, formatTime(nowUTC())); err != nil {
		return fmt.Errorf("sqlite: failed to record routing connection for %q: %w", stewardID, err)
	}
	return nil
}

// LookupNode implements business.RoutingStore.LookupNode. Staleness is
// evaluated against nowUTC() — the same process clock formatTime/parseTime
// use elsewhere in this package — so a record just outside
// business.RoutingStaleAfter is reported exactly like a missing one.
func (s *SQLiteRoutingStore) LookupNode(ctx context.Context, stewardID string) (string, bool, error) {
	const query = `SELECT node_id, updated_at FROM cfgms_routing WHERE steward_id = ?`
	var nodeID, updatedAtStr string
	err := s.db.QueryRowContext(ctx, query, stewardID).Scan(&nodeID, &updatedAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("sqlite: failed to look up routing node for %q: %w", stewardID, err)
	}
	updatedAt := parseTime(updatedAtStr)
	if nowUTC().Sub(updatedAt) > business.RoutingStaleAfter {
		return "", false, nil
	}
	return nodeID, true, nil
}

// RemoveConnection implements business.RoutingStore.RemoveConnection. The
// nodeID predicate makes this safe against a late-arriving disconnect from a
// node that lost a reconnect race: only the row this exact node currently
// owns is removed.
func (s *SQLiteRoutingStore) RemoveConnection(ctx context.Context, stewardID, nodeID string) error {
	const query = `DELETE FROM cfgms_routing WHERE steward_id = ? AND node_id = ?`
	if _, err := s.db.ExecContext(ctx, query, stewardID, nodeID); err != nil {
		return fmt.Errorf("sqlite: failed to remove routing connection for %q: %w", stewardID, err)
	}
	return nil
}

// CountByNode implements business.RoutingStore.CountByNode. Staleness is
// evaluated the same way as LookupNode: against nowUTC() using the same
// RoutingStaleAfter window, so a crashed node's abandoned records are not
// counted as live sessions.
func (s *SQLiteRoutingStore) CountByNode(ctx context.Context, nodeID string) (int, error) {
	const query = `SELECT updated_at FROM cfgms_routing WHERE node_id = ?`
	rows, err := s.db.QueryContext(ctx, query, nodeID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: failed to count routing connections for %q: %w", nodeID, err)
	}
	defer func() { _ = rows.Close() }()

	now := nowUTC()
	count := 0
	for rows.Next() {
		var updatedAtStr string
		if err := rows.Scan(&updatedAtStr); err != nil {
			return 0, fmt.Errorf("sqlite: failed to scan routing connection for %q: %w", nodeID, err)
		}
		if now.Sub(parseTime(updatedAtStr)) <= business.RoutingStaleAfter {
			count++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("sqlite: failed to count routing connections for %q: %w", nodeID, err)
	}
	return count, nil
}

// Close closes the underlying database connection.
func (s *SQLiteRoutingStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
