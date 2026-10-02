// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements certinterfaces.SigningCursorStore using PostgreSQL
// (Issue #3852, ADR-031 Decision 1: the config-signing rotation cursor must
// be cluster-visible so concurrent rotations from different controller nodes
// converge on one cursor instead of diverging).
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// signingCursorRowID is the fixed primary key of the single row this store
// ever holds — one controller CA, one signing cursor.
const signingCursorRowID = "default"

// Compile-time assertion.
var _ certinterfaces.SigningCursorStore = (*DatabaseSigningCursorStore)(nil)

// DatabaseSigningCursorStore implements certinterfaces.SigningCursorStore using
// PostgreSQL. TransitionCursor's guard-and-write is a single atomic
// INSERT ... ON CONFLICT ... WHERE statement (see TransitionCursor),
// following the same no-application-mutex pattern as DatabaseLeaseStore:
// PostgreSQL's own row locking on the ON CONFLICT target serializes
// concurrent callers, including callers on different controller nodes.
type DatabaseSigningCursorStore struct {
	db *sql.DB
}

// NewDatabaseSigningCursorStore initialises the schema on the given shared
// connection pool and returns a ready-to-use SigningCursorStore.
func NewDatabaseSigningCursorStore(db *sql.DB, config map[string]interface{}) (*DatabaseSigningCursorStore, error) {
	store := &DatabaseSigningCursorStore{db: db}
	if err := NewDatabaseSchemas().CreateSigningCursorTable(context.Background(), db); err != nil {
		return nil, fmt.Errorf("database: failed to initialise signing cursor schema: %w", err)
	}
	return store, nil
}

// Close is a no-op — DatabaseProvider.Close() owns the shared pool's lifecycle.
func (s *DatabaseSigningCursorStore) Close() error {
	return nil
}

// LoadCursor implements certinterfaces.SigningCursorStore.LoadCursor.
func (s *DatabaseSigningCursorStore) LoadCursor(ctx context.Context) (*certinterfaces.SigningCertCursor, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT current_serial, rotating_serial, overlap_window_days, rotated_at, retired_at
		FROM cfgms_signing_cursor WHERE id = $1`, signingCursorRowID)
	return scanCursor(row)
}

func scanCursor(row *sql.Row) (*certinterfaces.SigningCertCursor, error) {
	cursor := &certinterfaces.SigningCertCursor{}
	var rotatingSerial sql.NullString
	var retiredAt sql.NullTime
	err := row.Scan(&cursor.CurrentSerial, &rotatingSerial, &cursor.OverlapWindowDays, &cursor.RotatedAt, &retiredAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("database: failed to load signing cursor: %w", err)
	}
	cursor.RotatingSerial = rotatingSerial.String
	if retiredAt.Valid {
		cursor.RetiredAt = &retiredAt.Time
	}
	return cursor, nil
}

// TransitionCursor implements certinterfaces.SigningCursorStore.TransitionCursor.
//
// The guard ("no rotation in progress, or force") and the write are one
// statement: the UPDATE branch of INSERT ... ON CONFLICT ... DO UPDATE only
// fires when its WHERE condition holds, so a concurrent caller that loses the
// race gets zero affected rows rather than overwriting the winner — the same
// idiom DatabaseLeaseStore.AcquireOrRenew uses for the same reason. The first
// ever row (no conflict) always succeeds unconditionally: nothing is "in
// progress" until a cursor exists.
//
// now() is used for RotatedAt so every node's guard evaluation compares
// against the same database clock, rather than each node's own wall clock —
// mirroring DatabaseLeaseStore's "one clock only" rule.
func (s *DatabaseSigningCursorStore) TransitionCursor(ctx context.Context, newSerial string, overlapDays int, force bool) (*certinterfaces.SigningCertCursor, error) {
	if newSerial == "" {
		return nil, fmt.Errorf("database: new signing serial cannot be empty")
	}

	const query = `
		INSERT INTO cfgms_signing_cursor (id, current_serial, rotating_serial, overlap_window_days, rotated_at, retired_at)
		VALUES ($1, $2, NULL, $3, now(), NULL)
		ON CONFLICT (id) DO UPDATE SET
			rotating_serial     = cfgms_signing_cursor.current_serial,
			current_serial      = EXCLUDED.current_serial,
			overlap_window_days = EXCLUDED.overlap_window_days,
			rotated_at          = now(),
			retired_at          = NULL
		WHERE $4::boolean
		   OR cfgms_signing_cursor.rotating_serial IS NULL
		   OR cfgms_signing_cursor.rotated_at < now() - make_interval(days => cfgms_signing_cursor.overlap_window_days)
		RETURNING current_serial, rotating_serial, overlap_window_days, rotated_at, retired_at
	`

	row := s.db.QueryRowContext(ctx, query, signingCursorRowID, newSerial, overlapDays, force)
	cursor, err := scanCursor(row)
	if err == nil && cursor != nil {
		return cursor, nil
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to transition signing cursor: %w", err)
	}

	// The WHERE clause evaluated false: a rotation is already in progress and
	// force was not set. Read back the contested row so the caller's error
	// message can name it, mirroring DatabaseLeaseStore.AcquireOrRenew's
	// "read back the contested lease" pattern.
	current, loadErr := s.LoadCursor(ctx)
	if loadErr != nil {
		return nil, fmt.Errorf("database: failed to read contested signing cursor: %w", loadErr)
	}
	if current == nil {
		return nil, fmt.Errorf("database: signing cursor transition rejected but no cursor row exists")
	}
	return nil, fmt.Errorf(
		"%w: rotating serial %q is still within %d-day overlap window (rotated %s ago)",
		certinterfaces.ErrSigningRotationInProgress,
		current.RotatingSerial,
		current.OverlapWindowDays,
		time.Since(current.RotatedAt).Truncate(time.Second),
	)
}
