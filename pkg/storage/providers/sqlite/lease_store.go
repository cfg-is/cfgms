// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements business.LeaseStore using the cfgms_leases table —
// the fenced, quorum-equivalent singleton-claim primitive (ADR-031 Decision 5,
// Issue #3756).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertions.
var (
	_ business.LeaseStore           = (*SQLiteLeaseStore)(nil)
	_ business.NodeSharedLeaseStore = (*SQLiteLeaseStore)(nil)
)

// SQLiteLeaseStore implements business.LeaseStore using SQLite. In
// SingleServerMode this store is never on a contended path — only one process
// ever acquires a given lease — so the atomic UPSERT below (identical in
// spirit to the PostgreSQL provider's) is correctness insurance rather than a
// concurrency requirement.
type SQLiteLeaseStore struct {
	db *sql.DB
}

// SharedAcrossNodes implements business.NodeSharedLeaseStore: false. The
// database is a file on the node's own disk, so a second controller node runs
// against a different file and contends with nothing. Leases held here are
// single-node claims (background-job singletons within one process); they must
// never be read as cluster-wide leadership authority, which is why the
// controller refuses to start a cluster deployment on this substrate
// (ADR-031 Decision 5).
func (s *SQLiteLeaseStore) SharedAcrossNodes() bool { return false }

// Close closes the underlying database connection.
func (s *SQLiteLeaseStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// AcquireOrRenew implements business.LeaseStore.AcquireOrRenew. See the
// PostgreSQL provider's AcquireOrRenew for the branch semantics; this is the
// same UPSERT pattern expressed against SQLite's UPSERT-with-WHERE syntax.
// The token CASE branch increments on every genuine acquisition (first
// creation, a different holder taking an expired lease, or the same holder
// re-acquiring after its own lease lapsed) and is skipped only when the
// current, unexpired holder renews.
func (s *SQLiteLeaseStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	if name == "" {
		return nil, fmt.Errorf("sqlite: lease name cannot be empty")
	}
	if holderID == "" {
		return nil, fmt.Errorf("sqlite: holder id cannot be empty")
	}

	nowStr := formatTime(nowUTC())
	expiresAtStr := formatTime(nowUTC().Add(ttl))

	const query = `
		INSERT INTO cfgms_leases (name, holder_id, token, expires_at)
		VALUES (?, ?, 1, ?)
		ON CONFLICT(name) DO UPDATE SET
			holder_id  = excluded.holder_id,
			expires_at = excluded.expires_at,
			token      = CASE
				WHEN cfgms_leases.holder_id = excluded.holder_id AND cfgms_leases.expires_at >= ?
				THEN cfgms_leases.token
				ELSE cfgms_leases.token + 1
			END
		WHERE cfgms_leases.expires_at < ? OR cfgms_leases.holder_id = excluded.holder_id
		RETURNING name, holder_id, token, expires_at
	`

	row := s.db.QueryRowContext(ctx, query, name, holderID, expiresAtStr, nowStr, nowStr)
	state, err := scanLeaseState(row)
	if err == nil {
		state.Acquired = true
		return state, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("sqlite: failed to acquire or renew lease %q: %w", name, err)
	}

	// The UPDATE branch's WHERE clause evaluated false: a different holder
	// currently holds an unexpired lease. Read back the contested row so the
	// caller can see who holds it.
	current, err := s.getLease(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to read contested lease %q: %w", name, err)
	}
	current.Acquired = false
	return current, nil
}

// Release implements business.LeaseStore.Release. The row is force-expired
// (expires_at set to the Unix epoch) rather than deleted, preserving the
// token as the lease's high-water mark for the next acquisition.
func (s *SQLiteLeaseStore) Release(ctx context.Context, name, holderID string, token uint64) error {
	const query = `
		UPDATE cfgms_leases
		SET expires_at = ?
		WHERE name = ? AND holder_id = ? AND token = ?
	`
	// #nosec G115 -- token is a monotonic counter that starts at 1 and is never negative
	if _, err := s.db.ExecContext(ctx, query, formatTime(time.Unix(0, 0)), name, holderID, int64(token)); err != nil {
		return fmt.Errorf("sqlite: failed to release lease %q: %w", name, err)
	}
	return nil
}

// GetLease implements business.LeaseStore.GetLease.
func (s *SQLiteLeaseStore) GetLease(ctx context.Context, name string) (*business.LeaseState, error) {
	return s.getLease(ctx, name)
}

func (s *SQLiteLeaseStore) getLease(ctx context.Context, name string) (*business.LeaseState, error) {
	const query = `SELECT name, holder_id, token, expires_at FROM cfgms_leases WHERE name = ?`
	row := s.db.QueryRowContext(ctx, query, name)
	state, err := scanLeaseState(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, business.ErrLeaseNotFound
		}
		return nil, fmt.Errorf("sqlite: failed to get lease %q: %w", name, err)
	}
	return state, nil
}

// scanLeaseState reads a lease row and evaluates its validity against
// nowUTC() — the same clock that wrote expires_at and that the UPSERT's
// contention predicates compare against. The database provider must derive
// validity inside SQL because its clock lives on another host; here the store
// and its clock are the one process, so there is no offset that could enter
// the decision (business.LeaseStore's "one clock only" contract).
func scanLeaseState(row *sql.Row) (*business.LeaseState, error) {
	state := &business.LeaseState{}
	var expiresAtStr string
	var token int64
	if err := row.Scan(&state.Name, &state.HolderID, &token, &expiresAtStr); err != nil {
		return nil, err
	}
	state.Token = uint64(token) // #nosec G115 -- token is a monotonic counter that starts at 1 and is never negative
	state.ExpiresAt = parseTime(expiresAtStr)
	state.Valid = state.ExpiresAt.After(nowUTC())
	return state, nil
}
