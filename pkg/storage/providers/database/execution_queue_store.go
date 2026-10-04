// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements business.ExecutionQueueStore using PostgreSQL —
// the shared execution queue every controller node dispatches from (Issue #4528).
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.ExecutionQueueStore = (*DatabaseExecutionQueueStore)(nil)

// DatabaseExecutionQueueStore implements business.ExecutionQueueStore using
// PostgreSQL. Every transition is a single statement or a row-locked
// transaction, so concurrent callers on different controller nodes never claim
// the same queued entry.
type DatabaseExecutionQueueStore struct {
	db *sql.DB
}

// NewDatabaseExecutionQueueStore creates the store on the shared connection
// pool db (owned by DatabaseProvider; ADR-031 Decision 6) and ensures its
// table exists.
func NewDatabaseExecutionQueueStore(db *sql.DB, _ map[string]interface{}) (*DatabaseExecutionQueueStore, error) {
	if err := NewDatabaseSchemas().CreateExecutionQueueTable(context.Background(), db); err != nil {
		return nil, err
	}
	return &DatabaseExecutionQueueStore{db: db}, nil
}

const executionQueueColumns = `execution_id, device_id, param_hash, state, queued_at, expires_at,
	dispatched_at, completed_at, payload`

func scanExecutionQueueEntry(row rowScanner) (*business.ExecutionQueueEntry, error) {
	e := &business.ExecutionQueueEntry{}
	var dispatchedAt, completedAt sql.NullTime
	var payload []byte
	if err := row.Scan(&e.ExecutionID, &e.DeviceID, &e.ParamHash, &e.State, &e.QueuedAt, &e.ExpiresAt,
		&dispatchedAt, &completedAt, &payload); err != nil {
		return nil, err
	}
	if dispatchedAt.Valid {
		t := dispatchedAt.Time
		e.DispatchedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		e.CompletedAt = &t
	}
	e.Payload = payload
	return e, nil
}

func collectExecutionQueueEntries(rows *sql.Rows) ([]*business.ExecutionQueueEntry, error) {
	defer func() { _ = rows.Close() }()
	entries := make([]*business.ExecutionQueueEntry, 0)
	for rows.Next() {
		e, err := scanExecutionQueueEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Enqueue implements business.ExecutionQueueStore.
func (s *DatabaseExecutionQueueStore) Enqueue(ctx context.Context, e *business.ExecutionQueueEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO cfgms_execution_queue (`+executionQueueColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.ExecutionID, e.DeviceID, e.ParamHash, e.State, e.QueuedAt.UTC(), e.ExpiresAt.UTC(),
		nullTime(e.DispatchedAt), nullTime(e.CompletedAt), string(e.Payload))
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == "idx_execution_queue_queued_dedup" {
			return business.ErrDuplicateQueuedExecution
		}
		return fmt.Errorf("database: enqueue execution: %w", err)
	}
	return nil
}

// Dequeue implements business.ExecutionQueueStore. One transaction expires
// overdue queued entries, locks the device's remaining queued and dispatched
// rows (skipping rows another node holds locked), moves the queued ones to
// dispatched, and returns everything it locked.
func (s *DatabaseExecutionQueueStore) Dequeue(ctx context.Context, deviceID string, now time.Time) ([]*business.ExecutionQueueEntry, error) {
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("database: dequeue begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `UPDATE cfgms_execution_queue SET state = 'expired'
		WHERE device_id = $1 AND state = 'queued' AND expires_at < $2`, deviceID, now); err != nil {
		return nil, fmt.Errorf("database: dequeue expire: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT `+executionQueueColumns+` FROM cfgms_execution_queue
		WHERE device_id = $1 AND state IN ('queued', 'dispatched')
		ORDER BY queued_at
		FOR UPDATE SKIP LOCKED`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("database: dequeue select: %w", err)
	}
	entries, err := collectExecutionQueueEntries(rows)
	if err != nil {
		return nil, fmt.Errorf("database: dequeue scan: %w", err)
	}

	var claim []string
	for _, e := range entries {
		if e.State == business.ExecutionQueueStateQueued {
			claim = append(claim, e.ExecutionID)
			e.State = business.ExecutionQueueStateDispatched
			t := now
			e.DispatchedAt = &t
		}
	}
	if len(claim) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE cfgms_execution_queue
			SET state = 'dispatched', dispatched_at = $1
			WHERE execution_id = ANY($2)`, now, pq.Array(claim)); err != nil {
			return nil, fmt.Errorf("database: dequeue claim: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("database: dequeue commit: %w", err)
	}
	return entries, nil
}

// AcknowledgeCompletion implements business.ExecutionQueueStore.
func (s *DatabaseExecutionQueueStore) AcknowledgeCompletion(ctx context.Context, executionID, deviceID, state string, now time.Time) error {
	if state != business.ExecutionQueueStateCompleted && state != business.ExecutionQueueStateFailed {
		return fmt.Errorf("invalid completion state %q: must be completed or failed", state)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE cfgms_execution_queue SET state = $1, completed_at = $2
		WHERE execution_id = $3 AND device_id = $4 AND state = 'dispatched'`,
		state, now.UTC(), executionID, deviceID)
	if err != nil {
		return fmt.Errorf("database: acknowledge execution: %w", err)
	}
	return requireOneRow(res, executionID, deviceID)
}

// Cancel implements business.ExecutionQueueStore.
func (s *DatabaseExecutionQueueStore) Cancel(ctx context.Context, deviceID, executionID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE cfgms_execution_queue SET state = 'cancelled'
		WHERE execution_id = $1 AND device_id = $2 AND state IN ('queued', 'dispatched')`,
		executionID, deviceID)
	if err != nil {
		return fmt.Errorf("database: cancel execution: %w", err)
	}
	return requireOneRow(res, executionID, deviceID)
}

func requireOneRow(res sql.Result, executionID, deviceID string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("database: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("execution %s for device %s: %w", executionID, deviceID, business.ErrExecutionQueueEntryNotFound)
	}
	return nil
}

// RequeueStale implements business.ExecutionQueueStore.
func (s *DatabaseExecutionQueueStore) RequeueStale(ctx context.Context, dispatchedBefore time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE cfgms_execution_queue SET state = 'queued', dispatched_at = NULL
		WHERE state = 'dispatched' AND dispatched_at < $1`, dispatchedBefore.UTC())
	if err != nil {
		return 0, fmt.Errorf("database: requeue stale executions: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// CleanupExpired implements business.ExecutionQueueStore.
func (s *DatabaseExecutionQueueStore) CleanupExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE cfgms_execution_queue SET state = 'expired'
		WHERE state = 'queued' AND expires_at < $1`, now.UTC())
	if err != nil {
		return 0, fmt.Errorf("database: cleanup expired executions: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// List implements business.ExecutionQueueStore.
func (s *DatabaseExecutionQueueStore) List(ctx context.Context, deviceID string) ([]*business.ExecutionQueueEntry, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if deviceID != "" {
		rows, err = s.db.QueryContext(ctx, `SELECT `+executionQueueColumns+` FROM cfgms_execution_queue
			WHERE device_id = $1 AND state IN ('queued', 'dispatched') ORDER BY queued_at`, deviceID)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT `+executionQueueColumns+` FROM cfgms_execution_queue
			WHERE state IN ('queued', 'dispatched') ORDER BY queued_at`)
	}
	if err != nil {
		return nil, fmt.Errorf("database: list executions: %w", err)
	}
	entries, err := collectExecutionQueueEntries(rows)
	if err != nil {
		return nil, fmt.Errorf("database: list executions scan: %w", err)
	}
	return entries, nil
}

// GetStats implements business.ExecutionQueueStore.
func (s *DatabaseExecutionQueueStore) GetStats(ctx context.Context) (business.ExecutionQueueStats, error) {
	stats := business.ExecutionQueueStats{
		CountsByState:     make(map[string]int),
		DeviceQueueDepths: make(map[string]int),
	}
	rows, err := s.db.QueryContext(ctx, `SELECT device_id, state, count(*) FROM cfgms_execution_queue
		GROUP BY device_id, state`)
	if err != nil {
		return stats, fmt.Errorf("database: execution queue stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var device, state string
		var n int
		if err := rows.Scan(&device, &state, &n); err != nil {
			return stats, fmt.Errorf("database: execution queue stats scan: %w", err)
		}
		stats.TotalEntries += n
		stats.CountsByState[state] += n
		if state == business.ExecutionQueueStateQueued || state == business.ExecutionQueueStateDispatched {
			stats.DeviceQueueDepths[device] += n
		}
	}
	return stats, rows.Err()
}
