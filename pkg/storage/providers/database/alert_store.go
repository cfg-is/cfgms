// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.AlertStore = (*DatabaseAlertStore)(nil)

// DatabaseAlertStore implements AlertStore using PostgreSQL.
type DatabaseAlertStore struct {
	db      *sql.DB
	mu      sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseAlertStore opens a PostgreSQL-backed AlertStore at dsn.
func NewDatabaseAlertStore(dsn string, config map[string]interface{}) (*DatabaseAlertStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	maxOpenConns := getIntFromConfig(config, "max_open_connections", 25)
	maxIdleConns := getIntFromConfig(config, "max_idle_connections", 5)
	connMaxLifetime := time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &DatabaseAlertStore{db: db, schemas: NewDatabaseSchemas()}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialise alert store schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseAlertStore) initSchema() error {
	ctx := context.Background()
	const lockID = 16923850 // unique advisory lock ID for the alert_states schema

	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("failed to acquire alert store schema lock: %w", err)
	}
	defer func() {
		_, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID)
	}()

	return s.schemas.CreateAlertStatesTable(ctx, s.db)
}

// Close closes the underlying database connection.
func (s *DatabaseAlertStore) Close() error {
	return s.db.Close()
}

// AcknowledgeAlert implements AlertStore.AcknowledgeAlert.
func (s *DatabaseAlertStore) AcknowledgeAlert(ctx context.Context, tenantID, alertID, principal string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_alert_states
			(id, tenant_id, alert_id, acknowledged, acknowledged_by, acknowledged_at, silenced, silenced_by, silenced_until)
		VALUES ($1, $2, $3, TRUE, $4, $5, FALSE, '', '0001-01-01 00:00:00+00')
		ON CONFLICT (tenant_id, alert_id) DO UPDATE SET
			acknowledged    = TRUE,
			acknowledged_by = EXCLUDED.acknowledged_by,
			acknowledged_at = EXCLUDED.acknowledged_at`,
		id, tenantID, alertID, principal, at.UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to acknowledge alert: %w", err)
	}
	return nil
}

// SilenceAlert implements AlertStore.SilenceAlert.
func (s *DatabaseAlertStore) SilenceAlert(ctx context.Context, tenantID, alertID, principal string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_alert_states
			(id, tenant_id, alert_id, acknowledged, acknowledged_by, acknowledged_at, silenced, silenced_by, silenced_until)
		VALUES ($1, $2, $3, FALSE, '', '0001-01-01 00:00:00+00', TRUE, $4, $5)
		ON CONFLICT (tenant_id, alert_id) DO UPDATE SET
			silenced       = TRUE,
			silenced_by    = EXCLUDED.silenced_by,
			silenced_until = EXCLUDED.silenced_until`,
		id, tenantID, alertID, principal, until.UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to silence alert: %w", err)
	}
	return nil
}

// GetAlertState implements AlertStore.GetAlertState.
// Returns nil, nil when the alertID has never been touched.
func (s *DatabaseAlertStore) GetAlertState(ctx context.Context, tenantID, alertID string) (*business.AlertState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRowContext(ctx, `
		SELECT tenant_id, alert_id, acknowledged, acknowledged_by, acknowledged_at,
		       silenced, silenced_by, silenced_until
		FROM cfgms_alert_states
		WHERE tenant_id = $1 AND alert_id = $2`,
		tenantID, alertID,
	)
	st, err := scanAlertState(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get alert state: %w", err)
	}
	return st, nil
}

// ListAlertStates implements AlertStore.ListAlertStates.
// Returns an empty (non-nil) slice when no states exist for tenantID.
func (s *DatabaseAlertStore) ListAlertStates(ctx context.Context, tenantID string) ([]*business.AlertState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT tenant_id, alert_id, acknowledged, acknowledged_by, acknowledged_at,
		       silenced, silenced_by, silenced_until
		FROM cfgms_alert_states
		WHERE tenant_id = $1
		ORDER BY alert_id ASC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list alert states: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make([]*business.AlertState, 0)
	for rows.Next() {
		st, err := scanAlertState(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, st)
	}
	return result, rows.Err()
}

// alertStateScanner abstracts *sql.Row and *sql.Rows for scanAlertState.
type alertStateScanner interface {
	Scan(dest ...interface{}) error
}

func scanAlertState(row alertStateScanner) (*business.AlertState, error) {
	var st business.AlertState
	var acknowledgedAt sql.NullTime
	var silencedUntil sql.NullTime

	if err := row.Scan(
		&st.TenantID,
		&st.AlertID,
		&st.Acknowledged,
		&st.AcknowledgedBy,
		&acknowledgedAt,
		&st.Silenced,
		&st.SilencedBy,
		&silencedUntil,
	); err != nil {
		return nil, err
	}
	if acknowledgedAt.Valid {
		st.AcknowledgedAt = acknowledgedAt.Time
	}
	if silencedUntil.Valid {
		st.SilencedUntil = silencedUntil.Time
	}
	return &st, nil
}
