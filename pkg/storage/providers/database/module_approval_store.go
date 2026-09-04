// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package database implements business.ModuleApprovalStore using PostgreSQL
// (Issue #3886, ADR-031 Decision 1: module bundle approval status must be
// cluster-visible and CAS-protected so a concurrent approve/reject race between
// controller nodes always converges on exactly one winner).
package database

import (
	"context"
	"database/sql"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.ModuleApprovalStore = (*DatabaseModuleApprovalStore)(nil)

// DatabaseModuleApprovalStore implements business.ModuleApprovalStore using
// PostgreSQL. CompareAndSetApprovalStatus is a single UPDATE ... WHERE
// statement: PostgreSQL's own row-level locking on the targeted row serializes
// concurrent callers — including callers on different controller nodes sharing
// this store — so a concurrent approve and reject against the same address
// always converge on exactly one winner, following the same
// no-application-mutex idiom as DatabaseLeaseStore.AcquireOrRenew and
// DatabaseSigningCursorStore.TransitionCursor.
type DatabaseModuleApprovalStore struct {
	db *sql.DB
}

// NewDatabaseModuleApprovalStore initialises the schema on the given shared
// connection pool and returns a ready-to-use ModuleApprovalStore.
func NewDatabaseModuleApprovalStore(db *sql.DB, config map[string]interface{}) (*DatabaseModuleApprovalStore, error) {
	store := &DatabaseModuleApprovalStore{db: db}
	if err := NewDatabaseSchemas().CreateModuleApprovalsTable(context.Background(), db); err != nil {
		return nil, fmt.Errorf("database: failed to initialise module approval schema: %w", err)
	}
	return store, nil
}

// Close is a no-op — DatabaseProvider.Close() owns the shared pool's lifecycle.
func (s *DatabaseModuleApprovalStore) Close() error {
	return nil
}

// GetApprovalStatus implements business.ModuleApprovalStore.GetApprovalStatus.
func (s *DatabaseModuleApprovalStore) GetApprovalStatus(ctx context.Context, addr string) (business.ModuleApprovalStatus, bool, error) {
	var status string
	err := s.db.QueryRowContext(ctx,
		"SELECT status FROM cfgms_module_approvals WHERE address = $1", addr,
	).Scan(&status)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("database: failed to get approval status: %w", err)
	}
	return business.ModuleApprovalStatus(status), true, nil
}

// PutApprovalStatusIfAbsent implements
// business.ModuleApprovalStore.PutApprovalStatusIfAbsent. ON CONFLICT DO NOTHING
// makes ingestion incapable of erasing a decision another node already recorded:
// the row is written only when the address has no record at all, and the status
// in force is reported back to the caller either way.
func (s *DatabaseModuleApprovalStore) PutApprovalStatusIfAbsent(ctx context.Context, addr string, status business.ModuleApprovalStatus) (business.ModuleApprovalStatus, error) {
	if addr == "" {
		return "", fmt.Errorf("database: module approval address cannot be empty")
	}

	// Two attempts: the insert can report a conflict while the read that follows
	// finds no row, if a concurrent transaction deleted the conflicting row in
	// between. Retrying resolves that; a persistent disagreement is an error, not
	// something to paper over by reporting an unstored status as in force.
	for attempt := 0; attempt < 2; attempt++ {
		result, err := s.db.ExecContext(ctx, `
			INSERT INTO cfgms_module_approvals (address, status)
			VALUES ($1, $2)
			ON CONFLICT (address) DO NOTHING`,
			addr, string(status),
		)
		if err != nil {
			return "", fmt.Errorf("database: failed to record initial approval status: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return "", fmt.Errorf("database: failed to read initial approval status result: %w", err)
		}
		if rows == 1 {
			return status, nil
		}

		existing, found, err := s.GetApprovalStatus(ctx, addr)
		if err != nil {
			return "", err
		}
		if found {
			return existing, nil
		}
	}

	return "", fmt.Errorf("database: failed to record initial approval status: record repeatedly removed between insert and read")
}

// CompareAndSetApprovalStatus implements
// business.ModuleApprovalStore.CompareAndSetApprovalStatus. Requires an
// existing row whose status matches expectedCurrent — unlike SetApprovalStatus,
// this never creates a row, so a CAS against an address with no record always
// reports ok=false, matching the interface contract.
func (s *DatabaseModuleApprovalStore) CompareAndSetApprovalStatus(ctx context.Context, addr string, expectedCurrent, newStatus business.ModuleApprovalStatus) (bool, error) {
	if addr == "" {
		return false, fmt.Errorf("database: module approval address cannot be empty")
	}
	result, err := s.db.ExecContext(ctx,
		"UPDATE cfgms_module_approvals SET status = $1 WHERE address = $2 AND status = $3",
		string(newStatus), addr, string(expectedCurrent),
	)
	if err != nil {
		return false, fmt.Errorf("database: failed to compare-and-set approval status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("database: failed to read compare-and-set result: %w", err)
	}
	return rows == 1, nil
}
