// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements business.RolloutStore using PostgreSQL — the
// durable ring-advance rollout records shared by every controller node
// (Issue #5976).
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.RolloutStore = (*DatabaseRolloutStore)(nil)

// rolloutSchemaLockID is the advisory lock ID unique to the rollout records
// schema; it serialises concurrent node startups creating the table and its
// policies.
const rolloutSchemaLockID = 71934865

// DatabaseRolloutStore implements business.RolloutStore using PostgreSQL with
// row-level tenant isolation. Writes run in a transaction that sets
// app.current_tenant; reads by ID and the cross-tenant in-progress listing run
// without a tenant context, which the read policy permits.
type DatabaseRolloutStore struct {
	db *sql.DB
}

// NewDatabaseRolloutStore creates the store on the shared connection pool db
// (owned by DatabaseProvider; ADR-031 Decision 6) and ensures its table exists.
func NewDatabaseRolloutStore(db *sql.DB, _ map[string]interface{}) (*DatabaseRolloutStore, error) {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("database: failed to acquire rollout schema connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", rolloutSchemaLockID); err != nil {
		return nil, fmt.Errorf("database: failed to acquire rollout schema lock: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", rolloutSchemaLockID) }()
	if err := NewDatabaseSchemas().CreateRolloutRecordsTable(ctx, db); err != nil {
		return nil, err
	}
	return &DatabaseRolloutStore{db: db}, nil
}

const rolloutColumns = `id, tenant_id, initiated_by, target_version, current_ring,
	rings_completed, rings_total, status, started_at, halted_at, error_message,
	owner_node_id, deferred_stewards`

// CreateRollout implements business.RolloutStore.
func (s *DatabaseRolloutStore) CreateRollout(ctx context.Context, record *business.RolloutRecord) error {
	if record == nil {
		return errors.New("database: rollout record cannot be nil")
	}
	deferred, err := json.Marshal(nonNilStrings(record.DeferredStewards))
	if err != nil {
		return fmt.Errorf("database: failed to marshal deferred stewards: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin create rollout tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenantLocal(ctx, tx, record.TenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cfgms_rollout_records
			(`+rolloutColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		record.ID, record.TenantID, record.InitiatedBy, record.TargetVersion, record.CurrentRing,
		record.RingsCompleted, record.RingsTotal, string(record.Status), record.StartedAt,
		record.HaltedAt, record.Error, record.OwnerNodeID, deferred,
	); err != nil {
		return fmt.Errorf("database: failed to insert rollout %s: %w", record.ID, err)
	}
	return tx.Commit()
}

func scanRollout(row rowScanner) (*business.RolloutRecord, error) {
	r := &business.RolloutRecord{}
	var status string
	var halted sql.NullTime
	var deferred []byte
	if err := row.Scan(&r.ID, &r.TenantID, &r.InitiatedBy, &r.TargetVersion, &r.CurrentRing,
		&r.RingsCompleted, &r.RingsTotal, &status, &r.StartedAt, &halted, &r.Error,
		&r.OwnerNodeID, &deferred); err != nil {
		return nil, err
	}
	r.Status = business.RolloutStatus(status)
	if halted.Valid {
		t := halted.Time
		r.HaltedAt = &t
	}
	if err := json.Unmarshal(deferred, &r.DeferredStewards); err != nil {
		return nil, fmt.Errorf("database: failed to decode deferred stewards: %w", err)
	}
	if len(r.DeferredStewards) == 0 {
		r.DeferredStewards = nil
	}
	return r, nil
}

// GetRollout implements business.RolloutStore.
func (s *DatabaseRolloutStore) GetRollout(ctx context.Context, id string) (*business.RolloutRecord, error) {
	r, err := scanRollout(s.db.QueryRowContext(ctx,
		`SELECT `+rolloutColumns+` FROM cfgms_rollout_records WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrRolloutNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to get rollout %s: %w", id, err)
	}
	return r, nil
}

// tenantOf returns the tenant owning rollout id, which the row-level update
// policy needs before the write. Returns business.ErrRolloutNotFound when absent.
func (s *DatabaseRolloutStore) tenantOf(ctx context.Context, id string) (string, error) {
	var tenantID string
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id FROM cfgms_rollout_records WHERE id = $1`, id).Scan(&tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", business.ErrRolloutNotFound
	}
	if err != nil {
		return "", fmt.Errorf("database: failed to fetch rollout tenant: %w", err)
	}
	return tenantID, nil
}

// updateInTenant runs one UPDATE of rollout id inside a transaction scoped to
// the rollout's tenant. A row that vanished reports business.ErrRolloutNotFound.
func (s *DatabaseRolloutStore) updateInTenant(ctx context.Context, id, query string, args ...interface{}) error {
	tenantID, err := s.tenantOf(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin update rollout tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenantLocal(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}
	res, err := tx.ExecContext(ctx, query, append([]interface{}{id}, args...)...)
	if err != nil {
		return fmt.Errorf("database: failed to update rollout %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return business.ErrRolloutNotFound
	}
	return tx.Commit()
}

// UpdateRolloutProgress implements business.RolloutStore. A nil haltedAt keeps
// any halted_at already recorded.
func (s *DatabaseRolloutStore) UpdateRolloutProgress(ctx context.Context, id string, status business.RolloutStatus, currentRing string, ringsCompleted int, haltedAt *time.Time, errorMsg string) error {
	return s.updateInTenant(ctx, id, `
		UPDATE cfgms_rollout_records
		SET status = $2, current_ring = $3, rings_completed = $4,
		    halted_at = COALESCE($5, halted_at), error_message = $6
		WHERE id = $1`,
		string(status), currentRing, ringsCompleted, haltedAt, errorMsg)
}

// AppendDeferredStewards implements business.RolloutStore. The append is a
// single UPDATE, so concurrent appends from different nodes do not lose IDs.
func (s *DatabaseRolloutStore) AppendDeferredStewards(ctx context.Context, rolloutID string, stewardIDs []string) error {
	ids, err := json.Marshal(nonNilStrings(stewardIDs))
	if err != nil {
		return fmt.Errorf("database: failed to marshal deferred stewards: %w", err)
	}
	return s.updateInTenant(ctx, rolloutID, `
		UPDATE cfgms_rollout_records
		SET deferred_stewards = deferred_stewards || $2::jsonb
		WHERE id = $1`, ids)
}

// ListRolloutsByTenant implements business.RolloutStore.
func (s *DatabaseRolloutStore) ListRolloutsByTenant(ctx context.Context, tenantID string) ([]*business.RolloutRecord, error) {
	return s.queryRollouts(ctx,
		`SELECT `+rolloutColumns+` FROM cfgms_rollout_records WHERE tenant_id = $1 ORDER BY started_at, id`, tenantID)
}

// ListInProgressRollouts implements business.RolloutStore. It reads across
// tenants without a tenant context, which the read policy permits.
func (s *DatabaseRolloutStore) ListInProgressRollouts(ctx context.Context) ([]*business.RolloutRecord, error) {
	return s.queryRollouts(ctx,
		`SELECT `+rolloutColumns+` FROM cfgms_rollout_records WHERE status = $1 ORDER BY started_at, id`,
		string(business.RolloutStatusInProgress))
}

func (s *DatabaseRolloutStore) queryRollouts(ctx context.Context, query string, args ...interface{}) ([]*business.RolloutRecord, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list rollouts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*business.RolloutRecord
	for rows.Next() {
		r, err := scanRollout(rows)
		if err != nil {
			return nil, fmt.Errorf("database: failed to scan rollout: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: failed to list rollouts: %w", err)
	}
	return out, nil
}

// HealthCheck implements business.RolloutStore.
func (s *DatabaseRolloutStore) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Initialize implements business.RolloutStore. The schema is created by
// NewDatabaseRolloutStore, so there is nothing left to prepare.
func (s *DatabaseRolloutStore) Initialize(_ context.Context) error { return nil }

// Close is a no-op: the connection pool is owned and closed by DatabaseProvider
// (ADR-031 Decision 6).
func (s *DatabaseRolloutStore) Close() error { return nil }

// nonNilStrings returns ss, or an empty slice for nil, so it marshals to a JSON
// array rather than null.
func nonNilStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}
