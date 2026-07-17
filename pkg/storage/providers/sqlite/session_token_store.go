// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/session"
)

// SQLiteSessionTokenStore implements pkg/session.Store using SQLite.
// The primary key is SHA-256(token) hex; the raw token is never stored or logged.
// Multiple rows may share a session_id (current token + prior-token grace slot after Renew).
// Delete removes all rows for a session_id, making revocation visible across restarts and nodes.
type SQLiteSessionTokenStore struct {
	db *sql.DB
}

// Compile-time assertion.
var _ session.Store = (*SQLiteSessionTokenStore)(nil)

// NewSessionTokenStore wraps an already-opened, schema-initialised *sql.DB as a session.Store.
// The caller retains ownership of db and must call db.Close() when done.
func NewSessionTokenStore(db *sql.DB) *SQLiteSessionTokenStore {
	return &SQLiteSessionTokenStore{db: db}
}

// Close closes the underlying database connection. Only call this when the
// store owns its *sql.DB exclusively (i.e. created via CreateSessionTokenStore,
// not via NewSessionTokenStore with a shared handle).
func (s *SQLiteSessionTokenStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Set stores or updates the Session under the given token hash (SHA-256 hex).
// The raw token is never passed to this method; callers must hash via session.HashToken.
//
// Set always inserts with hash_expires_at = NULL (no per-hash expiry). On conflict,
// session data is updated but hash_expires_at is left untouched so that a grace expiry
// stamped by StampGraceExpiry is not erased by a subsequent LastActivity sync.
func (s *SQLiteSessionTokenStore) Set(ctx context.Context, tokenHash string, sess *session.Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO session_token_records
			(token_hash, session_id, principal_id, connection_name, tenant_id,
			 issued_at, last_activity, absolute_expires_at, hash_expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT(token_hash) DO UPDATE SET
			session_id          = excluded.session_id,
			principal_id        = excluded.principal_id,
			connection_name     = excluded.connection_name,
			tenant_id           = excluded.tenant_id,
			issued_at           = excluded.issued_at,
			last_activity       = excluded.last_activity,
			absolute_expires_at = excluded.absolute_expires_at`,
		tokenHash,
		sess.ID,
		sess.PrincipalID,
		sess.ConnectionName,
		sess.TenantID,
		formatTime(sess.IssuedAt),
		formatTime(sess.LastActivity),
		formatTime(sess.AbsoluteExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("sqlite: session token set failed: %w", err)
	}
	return nil
}

// Get returns the Session for the given token hash.
// Returns ErrSessionNotFound when the hash is absent (including after Delete)
// or when the hash has passed its per-hash expiry set by StampGraceExpiry.
func (s *SQLiteSessionTokenStore) Get(ctx context.Context, tokenHash string) (*session.Session, error) {
	now := formatTime(time.Now().UTC())
	var sess session.Session
	var issuedAt, lastActivity, absoluteExpiresAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT session_id, principal_id, connection_name, tenant_id,
		       issued_at, last_activity, absolute_expires_at
		FROM session_token_records
		WHERE token_hash = ?
		  AND (hash_expires_at IS NULL OR hash_expires_at > ?)`, tokenHash, now,
	).Scan(
		&sess.ID, &sess.PrincipalID, &sess.ConnectionName, &sess.TenantID,
		&issuedAt, &lastActivity, &absoluteExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: session token get failed: %w", err)
	}
	sess.IssuedAt = parseTime(issuedAt)
	sess.LastActivity = parseTime(lastActivity)
	sess.AbsoluteExpiresAt = parseTime(absoluteExpiresAt)
	return &sess, nil
}

// Delete removes all token-hash rows associated with the given session ID,
// invalidating the current token and any in-grace prior token simultaneously.
// Returns ErrSessionNotFound when no rows matched (session was not in the store).
func (s *SQLiteSessionTokenStore) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM session_token_records WHERE session_id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: session token delete failed: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return session.ErrSessionNotFound
	}
	return nil
}

// ListAll returns one Session per unique session_id, de-duplicating rows that share
// a session_id (current token + grace slot). Grace-expired rows (hash_expires_at < now)
// are excluded. The returned slice is ordered by insertion order (ascending rowid).
// ListAll does not filter by session idle/absolute expiry; the caller (Manager.List) does.
func (s *SQLiteSessionTokenStore) ListAll(ctx context.Context) ([]*session.Session, error) {
	now := formatTime(time.Now().UTC())
	rows, err := s.db.QueryContext(ctx, `
		SELECT token_hash, session_id, principal_id, connection_name, tenant_id,
		       issued_at, last_activity, absolute_expires_at
		FROM session_token_records
		WHERE hash_expires_at IS NULL OR hash_expires_at > ?
		ORDER BY rowid`, now)
	if err != nil {
		return nil, fmt.Errorf("sqlite: session token list failed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	seen := make(map[string]struct{})
	var sessions []*session.Session
	for rows.Next() {
		var tokenHash string
		var sess session.Session
		var issuedAt, lastActivity, absoluteExpiresAt string
		if err := rows.Scan(
			&tokenHash, &sess.ID, &sess.PrincipalID, &sess.ConnectionName, &sess.TenantID,
			&issuedAt, &lastActivity, &absoluteExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("sqlite: session token list scan failed: %w", err)
		}
		if _, dup := seen[sess.ID]; dup {
			continue
		}
		seen[sess.ID] = struct{}{}
		sess.IssuedAt = parseTime(issuedAt)
		sess.LastActivity = parseTime(lastActivity)
		sess.AbsoluteExpiresAt = parseTime(absoluteExpiresAt)
		cp := sess
		sessions = append(sessions, &cp)
	}
	return sessions, rows.Err()
}

// StampGraceExpiry sets the per-hash expiry on a prior-token grace entry.
// Called by manager.Renew (via the graceStamper type assertion) after rotation
// so that the old hash is rejected by cluster peers and after controller restarts
// once the grace window elapses. The manager's in-memory grace tracking (ms.prevExpiry)
// continues to be authoritative on the issuing node.
func (s *SQLiteSessionTokenStore) StampGraceExpiry(ctx context.Context, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE session_token_records SET hash_expires_at = ? WHERE token_hash = ?`,
		formatTime(expiresAt.UTC()), tokenHash)
	return err
}
