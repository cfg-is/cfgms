// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"fmt"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// Compile-time assertion.
var _ certinterfaces.SigningTrustAckStore = (*DatabaseSigningTrustAckStore)(nil)

// DatabaseSigningTrustAckStore implements certinterfaces.SigningTrustAckStore
// using PostgreSQL, so an acknowledgement recorded on one controller node is
// readable from every other node and survives restarts.
type DatabaseSigningTrustAckStore struct {
	db *sql.DB
}

// NewDatabaseSigningTrustAckStore initialises the schema on the given shared
// connection pool and returns a ready-to-use SigningTrustAckStore.
func NewDatabaseSigningTrustAckStore(db *sql.DB, config map[string]interface{}) (*DatabaseSigningTrustAckStore, error) {
	if err := NewDatabaseSchemas().CreateSigningTrustAckTable(context.Background(), db); err != nil {
		return nil, fmt.Errorf("database: failed to initialise signing trust ack schema: %w", err)
	}
	return &DatabaseSigningTrustAckStore{db: db}, nil
}

// Close is a no-op — DatabaseProvider.Close() owns the shared pool's lifecycle.
func (s *DatabaseSigningTrustAckStore) Close() error {
	return nil
}

// RecordAck implements certinterfaces.SigningTrustAckStore.RecordAck. The
// first AcknowledgedAt wins; the timestamp comes from the database clock so
// every node records against the same time source.
func (s *DatabaseSigningTrustAckStore) RecordAck(ctx context.Context, stewardID, serial string) error {
	if stewardID == "" {
		return fmt.Errorf("database: signing trust ack steward ID cannot be empty")
	}
	if serial == "" {
		return fmt.Errorf("database: signing trust ack serial cannot be empty")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_signing_trust_acks (steward_id, serial, acknowledged_at)
		VALUES ($1, $2, now())
		ON CONFLICT (steward_id, serial) DO NOTHING`, stewardID, serial)
	if err != nil {
		return fmt.Errorf("database: failed to record signing trust ack: %w", err)
	}
	return nil
}

// GetAck implements certinterfaces.SigningTrustAckStore.GetAck.
func (s *DatabaseSigningTrustAckStore) GetAck(ctx context.Context, stewardID, serial string) (*certinterfaces.SigningTrustAck, error) {
	if stewardID == "" || serial == "" {
		return nil, fmt.Errorf("database: signing trust ack steward ID and serial cannot be empty")
	}
	ack := &certinterfaces.SigningTrustAck{}
	err := s.db.QueryRowContext(ctx, `
		SELECT steward_id, serial, acknowledged_at
		FROM cfgms_signing_trust_acks WHERE steward_id = $1 AND serial = $2`,
		stewardID, serial).Scan(&ack.StewardID, &ack.Serial, &ack.AcknowledgedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to load signing trust ack: %w", err)
	}
	return ack, nil
}

// ListAcked implements certinterfaces.SigningTrustAckStore.ListAcked.
func (s *DatabaseSigningTrustAckStore) ListAcked(ctx context.Context, serial string) ([]certinterfaces.SigningTrustAck, error) {
	if serial == "" {
		return nil, fmt.Errorf("database: signing trust ack serial cannot be empty")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT steward_id, serial, acknowledged_at
		FROM cfgms_signing_trust_acks WHERE serial = $1 ORDER BY steward_id`, serial)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list signing trust acks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []certinterfaces.SigningTrustAck{}
	for rows.Next() {
		var a certinterfaces.SigningTrustAck
		if err := rows.Scan(&a.StewardID, &a.Serial, &a.AcknowledgedAt); err != nil {
			return nil, fmt.Errorf("database: failed to scan signing trust ack: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: failed to iterate signing trust acks: %w", err)
	}
	return out, nil
}
