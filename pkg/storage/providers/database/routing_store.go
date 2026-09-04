// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements business.RoutingStore using PostgreSQL — the
// shared steward-routing table (ADR-031 Decision 3, Issue #3764).
package database

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.RoutingStore = (*DatabaseRoutingStore)(nil)

// DatabaseRoutingStore implements business.RoutingStore using PostgreSQL.
// Every controller node in a cluster deployment shares this table through
// the same database, which is what makes a lookup here meaningful across
// nodes.
type DatabaseRoutingStore struct {
	db      *sql.DB
	schemas DatabaseSchemas
}

// NewDatabaseRoutingStore creates a PostgreSQL-backed RoutingStore using the
// shared connection pool db (owned by DatabaseProvider; ADR-031 Decision 6).
func NewDatabaseRoutingStore(db *sql.DB, config map[string]interface{}) (*DatabaseRoutingStore, error) {
	store := &DatabaseRoutingStore{db: db, schemas: NewDatabaseSchemas()}

	ctx := context.Background()
	if err := store.schemas.CreateRoutingTable(ctx, db); err != nil {
		return nil, fmt.Errorf("failed to create cfgms_routing table: %w", err)
	}

	return store, nil
}

// RecordConnection implements business.RoutingStore.RecordConnection. The
// liveness timestamp is derived server-side (now()), never from a caller
// clock, for the same reason LeaseStore.AcquireOrRenew derives its expiry
// server-side: a caller's clock offset must never enter a decision another
// node relies on.
func (s *DatabaseRoutingStore) RecordConnection(ctx context.Context, stewardID, nodeID string) error {
	if stewardID == "" {
		return fmt.Errorf("database: steward id cannot be empty")
	}
	if nodeID == "" {
		return fmt.Errorf("database: node id cannot be empty")
	}

	const query = `
		INSERT INTO cfgms_routing (steward_id, node_id, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (steward_id) DO UPDATE SET
			node_id = EXCLUDED.node_id,
			updated_at = now()
	`
	if _, err := s.db.ExecContext(ctx, query, stewardID, nodeID); err != nil {
		return fmt.Errorf("failed to record routing connection for %q: %w", stewardID, err)
	}
	return nil
}

// LookupNode implements business.RoutingStore.LookupNode. Staleness is
// evaluated in the same query, against the database server's own now(), so a
// record just outside business.RoutingStaleAfter is reported exactly like a
// missing one.
func (s *DatabaseRoutingStore) LookupNode(ctx context.Context, stewardID string) (string, bool, error) {
	const query = `
		SELECT node_id
		FROM cfgms_routing
		WHERE steward_id = $1
		  AND updated_at >= now() - ($2::double precision * interval '1 second')
	`
	var nodeID string
	err := s.db.QueryRowContext(ctx, query, stewardID, business.RoutingStaleAfter.Seconds()).Scan(&nodeID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to look up routing node for %q: %w", stewardID, err)
	}
	return nodeID, true, nil
}

// RemoveConnection implements business.RoutingStore.RemoveConnection. The
// nodeID predicate makes this safe against a late-arriving disconnect from a
// node that lost a reconnect race: only the row this exact node currently
// owns is removed.
func (s *DatabaseRoutingStore) RemoveConnection(ctx context.Context, stewardID, nodeID string) error {
	const query = `DELETE FROM cfgms_routing WHERE steward_id = $1 AND node_id = $2`
	if _, err := s.db.ExecContext(ctx, query, stewardID, nodeID); err != nil {
		return fmt.Errorf("failed to remove routing connection for %q: %w", stewardID, err)
	}
	return nil
}

// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseRoutingStore) Close() error {
	return nil
}
