// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	"github.com/cfgis/cfgms/pkg/session"
)

// DatabaseSessionTokenStore implements pkg/session.Store using PostgreSQL.
// The primary key is SHA-256(token) hex; the raw token is never stored.
// Multiple rows may share a session_id (current token + prior-token grace slot after Renew).
// Delete removes all rows for a session_id, making revocation visible across all cluster nodes.
//
// This store is distinct from DatabaseSessionStore (which backs business.SessionStore
// using HMAC-keyed session IDs for admin-facing records). This store receives a
// pre-hashed tokenHash from session.Manager and stores it as-is.
type DatabaseSessionTokenStore struct {
	db *sql.DB
}

// Compile-time assertions.
var (
	_ session.Store  = (*DatabaseSessionTokenStore)(nil)
	_ graceStamperDB = (*DatabaseSessionTokenStore)(nil)
)

// graceStamperDB is the unexported alias for the graceStamper interface defined in
// pkg/session/manager.go. We satisfy it here without importing the unexported type.
type graceStamperDB interface {
	StampGraceExpiry(ctx context.Context, tokenHash string, expiresAt time.Time) error
}

// NewDatabaseSessionTokenStore opens a pooled Postgres connection, initialises the
// session_token_store schema under an advisory lock, and returns a ready-to-use store.
// config may contain the standard connection-pool keys used by the rest of this package:
// "max_open_connections", "max_idle_connections", "connection_max_lifetime_minutes".
func NewDatabaseSessionTokenStore(db *sql.DB, config map[string]interface{}) (*DatabaseSessionTokenStore, error) {
	store := &DatabaseSessionTokenStore{db: db}
	if err := store.initializeSchema(); err != nil {
		return nil, fmt.Errorf("database: failed to initialise session token store schema: %w", err)
	}
	return store, nil

}

// initializeSchema creates the session_token_store table under a Postgres advisory lock
// so concurrent controller nodes starting in parallel do not race on DDL.
// BackfillSessionTokenStoreContinuity is called after CREATE to add device-continuity
// columns (Issue #2788) on existing deployments; ADD COLUMN IF NOT EXISTS makes it idempotent.
func (s *DatabaseSessionTokenStore) initializeSchema() error {
	ctx := context.Background()
	const lockID = 12345678
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("failed to acquire session token store schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	schemas := NewDatabaseSchemas()
	if err := schemas.CreateSessionTokenStoreTable(ctx, s.db); err != nil {
		return err
	}
	return schemas.BackfillSessionTokenStoreContinuity(ctx, s.db)
}

// Close releases the database connection pool.
// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseSessionTokenStore) Close() error {
	return nil
}

// Set stores or updates the Session under the given token hash (SHA-256 hex).
// The raw token is never passed to this method; session.Manager always passes
// the pre-hashed value. On conflict, session data fields are updated but
// hash_expires_at is preserved so a grace expiry stamped by StampGraceExpiry
// is not overwritten by a subsequent LastActivity sync.
func (s *DatabaseSessionTokenStore) Set(ctx context.Context, tokenHash string, sess *session.Session) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: session token set: failed to begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, sess.TenantID); err != nil {
		return fmt.Errorf("database: session token set: failed to set tenant context: %w", err)
	}

	var lastProvenAt interface{}
	if !sess.LastProvenAt.IsZero() {
		lastProvenAt = roundToStorablePrecision(sess.LastProvenAt.UTC())
	}
	var credentialID interface{}
	if len(sess.CredentialID) > 0 {
		credentialID = sess.CredentialID
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO session_token_store
			(token_hash, session_id, principal_id, connection_name, tenant_id,
			 issued_at, last_activity, absolute_expires_at, hash_expires_at,
			 assurance, bound_ip, last_proven_at, credential_id, root_scoped, channel)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $10, $11, $12, $13, $14)
		ON CONFLICT(token_hash) DO UPDATE SET
			session_id          = EXCLUDED.session_id,
			principal_id        = EXCLUDED.principal_id,
			connection_name     = EXCLUDED.connection_name,
			tenant_id           = EXCLUDED.tenant_id,
			issued_at           = EXCLUDED.issued_at,
			last_activity       = EXCLUDED.last_activity,
			absolute_expires_at = EXCLUDED.absolute_expires_at,
			assurance           = EXCLUDED.assurance,
			bound_ip            = EXCLUDED.bound_ip,
			last_proven_at      = EXCLUDED.last_proven_at,
			credential_id       = EXCLUDED.credential_id,
			root_scoped         = EXCLUDED.root_scoped,
			channel             = EXCLUDED.channel`,
		tokenHash,
		sess.ID,
		sess.PrincipalID,
		sess.ConnectionName,
		sess.TenantID,
		roundToStorablePrecision(sess.IssuedAt.UTC()),
		roundToStorablePrecision(sess.LastActivity.UTC()),
		roundToStorablePrecision(sess.AbsoluteExpiresAt.UTC()),
		int(sess.Assurance),
		sess.BoundIP,
		lastProvenAt,
		credentialID,
		sess.RootScoped,
		sess.Channel,
	)
	if err != nil {
		return fmt.Errorf("database: session token set failed: %w", err)
	}
	return tx.Commit()
}

// Get returns the Session for the given token hash.
// Returns ErrSessionNotFound when the hash is absent or when hash_expires_at has passed.
func (s *DatabaseSessionTokenStore) Get(ctx context.Context, tokenHash string) (*session.Session, error) {
	var sess session.Session
	var assurance int
	var lastProvenAt sql.NullTime
	var credentialID []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT session_id, principal_id, connection_name, tenant_id,
		       issued_at, last_activity, absolute_expires_at,
		       assurance, bound_ip, last_proven_at, credential_id, root_scoped, channel
		FROM session_token_store
		WHERE token_hash = $1
		  AND (hash_expires_at IS NULL OR hash_expires_at > NOW())`,
		tokenHash,
	).Scan(
		&sess.ID, &sess.PrincipalID, &sess.ConnectionName, &sess.TenantID,
		&sess.IssuedAt, &sess.LastActivity, &sess.AbsoluteExpiresAt,
		&assurance, &sess.BoundIP, &lastProvenAt, &credentialID, &sess.RootScoped, &sess.Channel,
	)
	if err == sql.ErrNoRows {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: session token get failed: %w", err)
	}
	sess.IssuedAt = sess.IssuedAt.UTC()
	sess.LastActivity = sess.LastActivity.UTC()
	sess.AbsoluteExpiresAt = sess.AbsoluteExpiresAt.UTC()
	sess.Assurance = session.AssuranceLevel(assurance)
	if lastProvenAt.Valid {
		sess.LastProvenAt = lastProvenAt.Time.UTC()
	}
	if len(credentialID) > 0 {
		sess.CredentialID = credentialID
	}
	return &sess, nil
}

// GetByID returns any live session record for the given session ID.
// Used by Revoke's cache-miss branch to verify a session's Channel before deleting it.
// Returns ErrSessionNotFound when no non-expired record exists for id.
func (s *DatabaseSessionTokenStore) GetByID(ctx context.Context, id string) (*session.Session, error) {
	var sess session.Session
	var assurance int
	var lastProvenAt sql.NullTime
	var credentialID []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT session_id, principal_id, connection_name, tenant_id,
		       issued_at, last_activity, absolute_expires_at,
		       assurance, bound_ip, last_proven_at, credential_id, root_scoped, channel
		FROM session_token_store
		WHERE session_id = $1
		  AND (hash_expires_at IS NULL OR hash_expires_at > NOW())
		LIMIT 1`,
		id,
	).Scan(
		&sess.ID, &sess.PrincipalID, &sess.ConnectionName, &sess.TenantID,
		&sess.IssuedAt, &sess.LastActivity, &sess.AbsoluteExpiresAt,
		&assurance, &sess.BoundIP, &lastProvenAt, &credentialID, &sess.RootScoped, &sess.Channel,
	)
	if err == sql.ErrNoRows {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: session token get by id failed: %w", err)
	}
	sess.IssuedAt = sess.IssuedAt.UTC()
	sess.LastActivity = sess.LastActivity.UTC()
	sess.AbsoluteExpiresAt = sess.AbsoluteExpiresAt.UTC()
	sess.Assurance = session.AssuranceLevel(assurance)
	if lastProvenAt.Valid {
		sess.LastProvenAt = lastProvenAt.Time.UTC()
	}
	if len(credentialID) > 0 {
		sess.CredentialID = credentialID
	}
	return &sess, nil
}

// Delete removes all token-hash rows for the given session ID, invalidating both the
// current token and any in-grace prior-token entry simultaneously.
// Returns ErrSessionNotFound when no rows matched (session was not in the store).
func (s *DatabaseSessionTokenStore) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM session_token_store WHERE session_id = $1`, id)
	if err != nil {
		return fmt.Errorf("database: session token delete failed: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("database: session token delete: rows affected: %w", err)
	}
	if n == 0 {
		return session.ErrSessionNotFound
	}
	return nil
}

// ListAll returns one Session per unique session_id, de-duplicating rows that share a
// session_id (current token + grace slot). Grace-expired rows are excluded.
// Ordered by issued_at ascending. Does not filter by idle/absolute expiry; Manager.List does.
func (s *DatabaseSessionTokenStore) ListAll(ctx context.Context) ([]*session.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT token_hash, session_id, principal_id, connection_name, tenant_id,
		       issued_at, last_activity, absolute_expires_at,
		       assurance, bound_ip, last_proven_at, credential_id, root_scoped, channel
		FROM session_token_store
		WHERE hash_expires_at IS NULL OR hash_expires_at > NOW()
		ORDER BY issued_at`)
	if err != nil {
		return nil, fmt.Errorf("database: session token list failed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	seen := make(map[string]struct{})
	var sessions []*session.Session
	for rows.Next() {
		var tokenHash string
		var sess session.Session
		var assurance int
		var lastProvenAt sql.NullTime
		var credentialID []byte
		if err := rows.Scan(
			&tokenHash, &sess.ID, &sess.PrincipalID, &sess.ConnectionName, &sess.TenantID,
			&sess.IssuedAt, &sess.LastActivity, &sess.AbsoluteExpiresAt,
			&assurance, &sess.BoundIP, &lastProvenAt, &credentialID, &sess.RootScoped, &sess.Channel,
		); err != nil {
			return nil, fmt.Errorf("database: session token list scan failed: %w", err)
		}
		if _, dup := seen[sess.ID]; dup {
			continue
		}
		seen[sess.ID] = struct{}{}
		sess.IssuedAt = sess.IssuedAt.UTC()
		sess.LastActivity = sess.LastActivity.UTC()
		sess.AbsoluteExpiresAt = sess.AbsoluteExpiresAt.UTC()
		sess.Assurance = session.AssuranceLevel(assurance)
		if lastProvenAt.Valid {
			sess.LastProvenAt = lastProvenAt.Time.UTC()
		}
		if len(credentialID) > 0 {
			sess.CredentialID = credentialID
		}
		cp := sess
		sessions = append(sessions, &cp)
	}
	return sessions, rows.Err()
}

// StampGraceExpiry sets the per-hash expiry on a prior-token grace entry.
// Called by manager.Renew (via the graceStamper type assertion in manager.go:249)
// after token rotation so that the old hash is rejected by cluster peers once the
// grace window elapses. The manager's in-memory prevExpiry continues to be authoritative
// on the issuing node; this column makes the expiry durable and visible to peer nodes.
func (s *DatabaseSessionTokenStore) StampGraceExpiry(ctx context.Context, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE session_token_store SET hash_expires_at = $1 WHERE token_hash = $2`,
		roundToStorablePrecision(expiresAt.UTC()), tokenHash)
	if err != nil {
		return fmt.Errorf("database: session token stamp grace expiry failed: %w", err)
	}
	return nil
}

// roundToStorablePrecision quantizes t to microsecond precision, matching the
// precision of a Postgres TIMESTAMP WITH TIME ZONE column. Postgres itself rounds
// (not truncates) any sub-microsecond remainder on write, so a value that already
// carries only microsecond precision round-trips unchanged; without this, a
// nanosecond-precision Go time.Time written here reads back rounded by Postgres,
// diverging from the in-memory value the caller still holds.
func roundToStorablePrecision(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.Round(time.Microsecond)
}
