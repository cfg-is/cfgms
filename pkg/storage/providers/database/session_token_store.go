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

// Set creates the Session under the given token hash (SHA-256 hex); it is used only
// when a session is first issued. The raw token is never passed to this method;
// session.Manager always passes the pre-hashed value. Writes to an existing session
// must use Update so they cannot resurrect a revoked session.
func (s *DatabaseSessionTokenStore) Set(ctx context.Context, tokenHash string, sess *session.Session) error {
	return s.write(ctx, tokenHash, sess, false)
}

// Update writes to an existing session (activity sync, token rotation, elevation).
// It takes a transaction-scoped advisory lock keyed on the session ID — the same lock
// Delete takes — and only then checks for a live row and writes. The lock serializes
// Update against Delete of the same session across all controller nodes, and because
// the check runs after the lock is acquired (READ COMMITTED) it observes any committed
// Delete. When no live row remains it returns ErrSessionNotFound and writes nothing.
// On conflict hash_expires_at is preserved so a grace expiry stamped by
// StampGraceExpiry is not overwritten by a subsequent LastActivity sync.
func (s *DatabaseSessionTokenStore) Update(ctx context.Context, tokenHash string, sess *session.Session) error {
	return s.write(ctx, tokenHash, sess, true)
}

// lockSession takes a transaction-scoped advisory lock serializing writers and
// deleters of one session ID. It is released automatically at commit or rollback.
func lockSession(ctx context.Context, tx *sql.Tx, sessionID string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, sessionID)
	return err
}

func (s *DatabaseSessionTokenStore) write(ctx context.Context, tokenHash string, sess *session.Session, requireLive bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: session token write: failed to begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, sess.TenantID); err != nil {
		return fmt.Errorf("database: session token write: failed to set tenant context: %w", err)
	}
	if requireLive {
		if err := lockSession(ctx, tx, sess.ID); err != nil {
			return fmt.Errorf("database: session token write: failed to lock session: %w", err)
		}
	}
	if err := writeRow(ctx, tx, tokenHash, sess, requireLive); err != nil {
		return err
	}
	return tx.Commit()
}

// Rotate atomically makes newHash the session's current token and records prevExpiry
// as the grace expiry of prevHash. Like Update and Delete it first takes the
// transaction-scoped advisory lock for the session ID, so it is serialized with a
// concurrent Delete across all nodes; the guarded UPDATE of prevHash then matches only
// while prevHash is the session's current token and the session still has that row.
func (s *DatabaseSessionTokenStore) Rotate(ctx context.Context, prevHash, newHash string, sess *session.Session, prevExpiry time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: session token rotate: failed to begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, sess.TenantID); err != nil {
		return fmt.Errorf("database: session token rotate: failed to set tenant context: %w", err)
	}
	if err := lockSession(ctx, tx, sess.ID); err != nil {
		return fmt.Errorf("database: session token rotate: failed to lock session: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE session_token_store SET hash_expires_at = $1
		WHERE token_hash = $2 AND session_id = $3 AND hash_expires_at IS NULL`,
		roundToStorablePrecision(prevExpiry.UTC()), prevHash, sess.ID)
	if err != nil {
		return fmt.Errorf("database: session token rotate failed: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		var one int
		err := tx.QueryRowContext(ctx, `
			SELECT 1 FROM session_token_store
			WHERE session_id = $1 AND (hash_expires_at IS NULL OR hash_expires_at > NOW()) LIMIT 1`,
			sess.ID).Scan(&one)
		if err == sql.ErrNoRows {
			return session.ErrSessionNotFound
		}
		if err != nil {
			return fmt.Errorf("database: session token rotate: liveness check failed: %w", err)
		}
		return session.ErrTokenRotated
	}
	if err := writeRow(ctx, tx, newHash, sess, false); err != nil {
		return err
	}
	return tx.Commit()
}

// writeRow upserts one token-hash row inside tx. When requireLive is set the insert is
// guarded by an EXISTS check for a live row of the same session; the caller must already
// hold the session's advisory lock.
func writeRow(ctx context.Context, tx *sql.Tx, tokenHash string, sess *session.Session, requireLive bool) error {
	guard := ""
	if requireLive {
		guard = ` WHERE EXISTS (SELECT 1 FROM session_token_store
			WHERE session_id = $2 AND (hash_expires_at IS NULL OR hash_expires_at > NOW()))`
	}

	ts := computeStorableSessionTimestamps(sess)

	var credentialID interface{}
	if len(sess.CredentialID) > 0 {
		credentialID = sess.CredentialID
	}
	var loginCredentialID interface{}
	if len(sess.LoginCredentialID) > 0 {
		loginCredentialID = sess.LoginCredentialID
	}

	// The only dynamic fragment is the constant guard above; all values are bound parameters.
	result, err := tx.ExecContext(ctx, `
		INSERT INTO session_token_store
			(token_hash, session_id, principal_id, connection_name, tenant_id,
			 issued_at, last_activity, absolute_expires_at, hash_expires_at,
			 assurance, bound_ip, last_proven_at, credential_id, login_credential_id, root_scoped, channel)
		SELECT $1::text, $2::text, $3::text, $4::text, $5::text, $6::timestamptz, $7::timestamptz,
		       $8::timestamptz, NULL, $9::int, $10::text, $11::timestamptz, $12::bytea, $13::bytea, $14::boolean, $15::text`+guard+`
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
			login_credential_id = EXCLUDED.login_credential_id,
			root_scoped         = EXCLUDED.root_scoped,
			channel             = EXCLUDED.channel`,
		tokenHash,
		sess.ID,
		sess.PrincipalID,
		sess.ConnectionName,
		sess.TenantID,
		ts.issuedAt,
		ts.lastActivity,
		ts.absoluteExpiresAt,
		int(sess.Assurance),
		sess.BoundIP,
		ts.lastProvenAt,
		credentialID,
		loginCredentialID,
		sess.RootScoped,
		sess.Channel,
	)
	if err != nil {
		return fmt.Errorf("database: session token write failed: %w", err)
	}
	if requireLive {
		if n, _ := result.RowsAffected(); n == 0 {
			return session.ErrSessionNotFound
		}
	}
	return nil
}

// Get returns the Session for the given token hash.
// Returns ErrSessionNotFound when the hash is absent or when hash_expires_at has passed.
func (s *DatabaseSessionTokenStore) Get(ctx context.Context, tokenHash string) (*session.Session, error) {
	var sess session.Session
	var assurance int
	var lastProvenAt sql.NullTime
	var credentialID []byte
	var loginCredentialID []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT session_id, principal_id, connection_name, tenant_id,
		       issued_at, last_activity, absolute_expires_at,
		       assurance, bound_ip, last_proven_at, credential_id, login_credential_id, root_scoped, channel
		FROM session_token_store
		WHERE token_hash = $1
		  AND (hash_expires_at IS NULL OR hash_expires_at > NOW())`,
		tokenHash,
	).Scan(
		&sess.ID, &sess.PrincipalID, &sess.ConnectionName, &sess.TenantID,
		&sess.IssuedAt, &sess.LastActivity, &sess.AbsoluteExpiresAt,
		&assurance, &sess.BoundIP, &lastProvenAt, &credentialID, &loginCredentialID, &sess.RootScoped, &sess.Channel,
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
	if len(loginCredentialID) > 0 {
		sess.LoginCredentialID = loginCredentialID
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
	var loginCredentialID []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT session_id, principal_id, connection_name, tenant_id,
		       issued_at, last_activity, absolute_expires_at,
		       assurance, bound_ip, last_proven_at, credential_id, login_credential_id, root_scoped, channel
		FROM session_token_store
		WHERE session_id = $1
		  AND (hash_expires_at IS NULL OR hash_expires_at > NOW())
		LIMIT 1`,
		id,
	).Scan(
		&sess.ID, &sess.PrincipalID, &sess.ConnectionName, &sess.TenantID,
		&sess.IssuedAt, &sess.LastActivity, &sess.AbsoluteExpiresAt,
		&assurance, &sess.BoundIP, &lastProvenAt, &credentialID, &loginCredentialID, &sess.RootScoped, &sess.Channel,
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
	if len(loginCredentialID) > 0 {
		sess.LoginCredentialID = loginCredentialID
	}
	return &sess, nil
}

// Delete removes all token-hash rows for the given session ID, invalidating both the
// current token and any in-grace prior-token entry simultaneously.
// Returns ErrSessionNotFound when no rows matched (session was not in the store).
func (s *DatabaseSessionTokenStore) Delete(ctx context.Context, id string) error {
	// Determine the tenant from an existing row first (needed for RLS on the DELETE).
	var tenantID string
	err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id FROM session_token_store WHERE session_id = $1 LIMIT 1`, id).Scan(&tenantID)
	if err == sql.ErrNoRows {
		return session.ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("database: session token delete: failed to fetch tenant: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: session token delete: failed to begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("database: session token delete: failed to set tenant context: %w", err)
	}

	if err := lockSession(ctx, tx, id); err != nil {
		return fmt.Errorf("database: session token delete: failed to lock session: %w", err)
	}

	result, err := tx.ExecContext(ctx,
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
	return tx.Commit()
}

// ListAll returns one Session per unique session_id, de-duplicating rows that share a
// session_id (current token + grace slot). Grace-expired rows are excluded.
// Ordered by issued_at ascending. Does not filter by idle/absolute expiry; Manager.List does.
func (s *DatabaseSessionTokenStore) ListAll(ctx context.Context) ([]*session.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT token_hash, session_id, principal_id, connection_name, tenant_id,
		       issued_at, last_activity, absolute_expires_at,
		       assurance, bound_ip, last_proven_at, credential_id, login_credential_id, root_scoped, channel
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
		var loginCredentialID []byte
		if err := rows.Scan(
			&tokenHash, &sess.ID, &sess.PrincipalID, &sess.ConnectionName, &sess.TenantID,
			&sess.IssuedAt, &sess.LastActivity, &sess.AbsoluteExpiresAt,
			&assurance, &sess.BoundIP, &lastProvenAt, &credentialID, &loginCredentialID, &sess.RootScoped, &sess.Channel,
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
		if len(loginCredentialID) > 0 {
			sess.LoginCredentialID = loginCredentialID
		}
		cp := sess
		sessions = append(sessions, &cp)
	}
	return sessions, rows.Err()
}

// StampGraceExpiry sets the per-hash expiry on a prior-token grace entry.
// Rotate stamps the rotated-away hash atomically with writing its successor; this
// method remains for administrative use and tests.
func (s *DatabaseSessionTokenStore) StampGraceExpiry(ctx context.Context, tokenHash string, expiresAt time.Time) error {
	// Determine the tenant from the existing row first (needed for RLS on the UPDATE).
	var tenantID string
	err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id FROM session_token_store WHERE token_hash = $1`, tokenHash).Scan(&tenantID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("database: session token stamp grace expiry: failed to fetch tenant: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: session token stamp grace expiry: failed to begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("database: session token stamp grace expiry: failed to set tenant context: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE session_token_store SET hash_expires_at = $1 WHERE token_hash = $2`,
		roundToStorablePrecision(expiresAt.UTC()), tokenHash); err != nil {
		return fmt.Errorf("database: session token stamp grace expiry failed: %w", err)
	}
	return tx.Commit()
}

// storableSessionTimestamps holds sess's write-path timestamp fields rounded to
// microsecond precision, matching a Postgres TIMESTAMP WITH TIME ZONE column.
// lastProvenAt is nil (not a zero time.Time) when sess.LastProvenAt is unset, so it
// can be passed directly as a nullable SQL parameter.
type storableSessionTimestamps struct {
	issuedAt          time.Time
	lastActivity      time.Time
	absoluteExpiresAt time.Time
	lastProvenAt      interface{}
}

// computeStorableSessionTimestamps rounds sess's timestamp fields for the write path
// without mutating sess itself. sess is reachable from session.Manager's in-memory
// index (registered under its per-session lock only after Set returns, in the Issue
// path — see manager.go's issue()), so writing back into sess's fields from here would
// race a concurrent reader/writer that holds that lock instead of this call's caller.
//
// Postgres itself rounds (not truncates) any sub-microsecond remainder when a
// TIMESTAMP WITH TIME ZONE value is written, so the value a subsequent Get returns is
// already at microsecond precision regardless of what this function computes — this
// rounding does not change what ends up durably stored (verified against a real
// Postgres instance: neutralizing roundToStorablePrecision to an identity function
// left every round-trip read unchanged). What it fixes is comparing that stored value
// against an in-memory time.Time that still carries nanosecond precision, which never
// round-trips exactly on Postgres.
func computeStorableSessionTimestamps(sess *session.Session) storableSessionTimestamps {
	var lastProvenAt interface{}
	if !sess.LastProvenAt.IsZero() {
		lastProvenAt = roundToStorablePrecision(sess.LastProvenAt.UTC())
	}
	return storableSessionTimestamps{
		issuedAt:          roundToStorablePrecision(sess.IssuedAt.UTC()),
		lastActivity:      roundToStorablePrecision(sess.LastActivity.UTC()),
		absoluteExpiresAt: roundToStorablePrecision(sess.AbsoluteExpiresAt.UTC()),
		lastProvenAt:      lastProvenAt,
	}
}

// roundToStorablePrecision quantizes t to microsecond precision, matching the
// precision of a Postgres TIMESTAMP WITH TIME ZONE column.
func roundToStorablePrecision(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.Round(time.Microsecond)
}
