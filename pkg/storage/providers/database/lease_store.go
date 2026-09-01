// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements business.LeaseStore using PostgreSQL — the fenced,
// quorum-equivalent singleton-claim primitive (ADR-031 Decision 5, Issue #3756).
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.LeaseStore = (*DatabaseLeaseStore)(nil)

// DatabaseLeaseStore implements business.LeaseStore using PostgreSQL. The
// fencing-token increment and contention resolution are performed entirely by
// a single atomic INSERT ... ON CONFLICT ... DO UPDATE statement (see
// AcquireOrRenew), so concurrent callers racing for the same lease name —
// whether goroutines sharing this store or separate processes with their own
// connections — are serialized by PostgreSQL's own unique-index row locking.
// Deliberately no application-level mutex: one would only mask a correctness
// bug in the SQL by serializing callers that must instead be proven safe
// under real concurrent access to the database.
type DatabaseLeaseStore struct {
	db      *sql.DB
	schemas DatabaseSchemas
}

// NewDatabaseLeaseStore creates a PostgreSQL-backed LeaseStore using the
// shared connection pool db (owned by DatabaseProvider; ADR-031 Decision 6).
func NewDatabaseLeaseStore(db *sql.DB, config map[string]interface{}) (*DatabaseLeaseStore, error) {
	store := &DatabaseLeaseStore{db: db, schemas: NewDatabaseSchemas()}

	ctx := context.Background()
	if err := store.schemas.CreateLeaseTable(ctx, db); err != nil {
		return nil, fmt.Errorf("failed to create cfgms_leases table: %w", err)
	}

	return store, nil
}

// AcquireOrRenew implements business.LeaseStore.AcquireOrRenew.
//
// The token CASE branch fires ("increment") on every genuine acquisition —
// first creation, a different holder taking over an expired lease, or the
// same holder re-acquiring after its own lease lapsed — and is skipped only
// when the current, unexpired holder renews. The WHERE clause is what makes
// contention resolution atomic: it allows the UPDATE branch to apply only
// when the existing row is expired or already held by holderID, so a
// concurrent racer that loses gets zero affected rows rather than
// overwriting the winner.
//
// # One clock only
//
// The new expiry is derived server-side (now() + ttl seconds), never as a
// timestamp computed on the calling host. The contention predicates compare
// expires_at against the PostgreSQL server's now(), so writing a
// caller-computed expiry would let the offset between the caller's wall clock
// and the database server's decide whether another node may steal the lease —
// and it would fail open, not closed: a host whose clock trails the server
// (routine after an NTP step correction or a VM suspend/resume) would store an
// expiry already in the past by server time, letting a second node acquire
// immediately while the first still believes it holds authority for its full
// monotonic safety margin. Two simultaneous holders of a fencing lease is
// exactly what ADR-029 Decision 2 / Issue #2037 forbids, and what pkg/lease
// documents as its invariant. Every now() in one statement is the same
// transaction timestamp, so the derivation and the comparisons cannot disagree
// even with each other.
func (s *DatabaseLeaseStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	if name == "" {
		return nil, fmt.Errorf("database: lease name cannot be empty")
	}
	if holderID == "" {
		return nil, fmt.Errorf("database: holder id cannot be empty")
	}

	const query = `
		INSERT INTO cfgms_leases (name, holder_id, token, expires_at)
		VALUES ($1, $2, 1, now() + ($3::double precision * interval '1 second'))
		ON CONFLICT (name) DO UPDATE SET
			holder_id  = EXCLUDED.holder_id,
			expires_at = now() + ($3::double precision * interval '1 second'),
			token      = CASE
				WHEN cfgms_leases.holder_id = EXCLUDED.holder_id AND cfgms_leases.expires_at >= now()
				THEN cfgms_leases.token
				ELSE cfgms_leases.token + 1
			END
		WHERE cfgms_leases.expires_at < now() OR cfgms_leases.holder_id = EXCLUDED.holder_id
		RETURNING name, holder_id, token, expires_at, expires_at > now() AS valid
	`

	row := s.db.QueryRowContext(ctx, query, name, holderID, ttl.Seconds())
	state := &business.LeaseState{}
	var token int64
	err := row.Scan(&state.Name, &state.HolderID, &token, &state.ExpiresAt, &state.Valid)
	if err == nil {
		state.Token = uint64(token) // #nosec G115 -- token is a monotonic counter that starts at 1 and is never negative
		state.Acquired = true
		return state, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to acquire or renew lease %q: %w", name, err)
	}

	// The UPDATE branch's WHERE clause evaluated false: a different holder
	// currently holds an unexpired lease. Read back the contested row so the
	// caller can see who holds it.
	current, err := s.getLease(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read contested lease %q: %w", name, err)
	}
	current.Acquired = false
	return current, nil
}

// Release implements business.LeaseStore.Release. The row is force-expired
// (expires_at set to the epoch) rather than deleted, preserving the token as
// the lease's high-water mark for the next acquisition.
func (s *DatabaseLeaseStore) Release(ctx context.Context, name, holderID string, token uint64) error {
	const query = `
		UPDATE cfgms_leases
		SET expires_at = TIMESTAMP WITH TIME ZONE 'epoch'
		WHERE name = $1 AND holder_id = $2 AND token = $3
	`
	// #nosec G115 -- token is a monotonic counter that starts at 1 and is never negative
	if _, err := s.db.ExecContext(ctx, query, name, holderID, int64(token)); err != nil {
		return fmt.Errorf("failed to release lease %q: %w", name, err)
	}
	return nil
}

// GetLease implements business.LeaseStore.GetLease.
func (s *DatabaseLeaseStore) GetLease(ctx context.Context, name string) (*business.LeaseState, error) {
	return s.getLease(ctx, name)
}

// getLease reads the row for name. Validity is computed by the database from
// its own now() and returned as a column, so no caller-side clock takes part
// in the decision (see AcquireOrRenew's "One clock only").
func (s *DatabaseLeaseStore) getLease(ctx context.Context, name string) (*business.LeaseState, error) {
	const query = `SELECT name, holder_id, token, expires_at, expires_at > now() AS valid FROM cfgms_leases WHERE name = $1`

	state := &business.LeaseState{}
	var token int64
	err := s.db.QueryRowContext(ctx, query, name).Scan(&state.Name, &state.HolderID, &token, &state.ExpiresAt, &state.Valid)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, business.ErrLeaseNotFound
		}
		return nil, fmt.Errorf("failed to get lease %q: %w", name, err)
	}
	state.Token = uint64(token) // #nosec G115 -- token is a monotonic counter that starts at 1 and is never negative
	return state, nil
}

// Close closes the underlying database connection.
// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseLeaseStore) Close() error {
	return nil
}
