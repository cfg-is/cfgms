// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements SessionStore using PostgreSQL with HMAC-hashed tokens and RLS.
package database

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// DatabaseSessionStore implements business.SessionStore using PostgreSQL.
// Bearer tokens are stored as HMAC-SHA256 hashes; plaintext tokens are never written to the DB.
// Per-query RLS is enforced by calling set_config('app.current_tenant', $tenantID, true)
// inside each transaction before executing the actual SQL.
type DatabaseSessionStore struct {
	db      *sql.DB
	hmacKey []byte
}

// Compile-time check.
var _ business.SessionStore = (*DatabaseSessionStore)(nil)

// NewDatabaseSessionStore opens a pooled Postgres connection, initialises the schema, and
// returns a ready-to-use SessionStore. config["session_hmac_key"] is required; the constructor
// returns an error when it is absent or empty to prevent silent insecure fallback.
func NewDatabaseSessionStore(db *sql.DB, config map[string]interface{}) (*DatabaseSessionStore, error) {
	keyStr, ok := config["session_hmac_key"].(string)
	if !ok || keyStr == "" {
		return nil, fmt.Errorf("database: session_hmac_key is required in session store config; provide a securely-generated random key")
	}

	store := &DatabaseSessionStore{db: db, hmacKey: []byte(keyStr)}
	if err := store.initializeSchema(); err != nil {
		return nil, fmt.Errorf("database: failed to initialise session store schema: %w", err)
	}
	return store, nil
}

// initializeSchema creates the sessions table if it does not exist.
func (s *DatabaseSessionStore) initializeSchema() error {
	ctx := context.Background()
	const lockID = 98765431
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("failed to acquire session schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateSessionsTable(ctx, s.db)
}

// Initialize is a no-op; schema is applied in the constructor.
func (s *DatabaseSessionStore) Initialize(_ context.Context) error { return nil }

// Close releases the database connection.
// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseSessionStore) Close() error {
	return nil
}

// hashToken returns the HMAC-SHA256 hex digest of the given token.
func (s *DatabaseSessionStore) hashToken(token string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// setTenantLocal sets app.current_tenant scoped to the current transaction.
func setTenantLocal(ctx context.Context, tx *sql.Tx, tenantID string) error {
	_, err := tx.ExecContext(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID)
	return err
}

// CreateSession inserts a new durable session.  Only Persistent=true sessions are accepted.
func (s *DatabaseSessionStore) CreateSession(ctx context.Context, session *business.Session) error {
	if session == nil {
		return fmt.Errorf("database: session cannot be nil")
	}
	if !session.Persistent {
		return fmt.Errorf("database: session %s is not persistent: durable SessionStore only accepts Persistent=true sessions", session.SessionID)
	}
	if err := session.Validate(); err != nil {
		return fmt.Errorf("database: invalid session: %w", err)
	}

	hash := s.hashToken(session.SessionID)

	clientInfoJSON, err := json.Marshal(session.ClientInfo)
	if err != nil {
		return fmt.Errorf("database: failed to marshal client_info: %w", err)
	}
	metaJSON, err := json.Marshal(stringMapToInterfaceDB(session.Metadata))
	if err != nil {
		return fmt.Errorf("database: failed to marshal metadata: %w", err)
	}
	sessionDataJSON, err := json.Marshal(session.SessionData)
	if err != nil {
		return fmt.Errorf("database: failed to marshal session_data: %w", err)
	}
	secCtxJSON, err := json.Marshal(session.SecurityContext)
	if err != nil {
		return fmt.Errorf("database: failed to marshal security_context: %w", err)
	}
	flagsJSON, err := json.Marshal(session.ComplianceFlags)
	if err != nil {
		return fmt.Errorf("database: failed to marshal compliance_flags: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin create session tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, session.TenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO sessions
			(session_id_hash, user_id, tenant_id, session_type,
			 created_at, last_activity, expires_at, status, persistent,
			 client_info, metadata, session_data, security_context, compliance_flags,
			 created_by, modified_at, modified_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		hash,
		session.UserID,
		session.TenantID,
		string(session.SessionType),
		session.CreatedAt,
		session.LastActivity,
		session.ExpiresAt,
		string(session.Status),
		session.Persistent,
		clientInfoJSON,
		metaJSON,
		sessionDataJSON,
		secCtxJSON,
		flagsJSON,
		session.CreatedBy,
		pgNullTime(session.ModifiedAt),
		session.ModifiedBy,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			return fmt.Errorf("database: session %s already exists", session.SessionID)
		}
		return fmt.Errorf("database: failed to create session: %w", err)
	}
	return tx.Commit()
}

// GetSession retrieves a session by its original bearer token.
// The returned session.SessionID contains the stored HMAC hash, not the plaintext token.
func (s *DatabaseSessionStore) GetSession(ctx context.Context, sessionID string) (*business.Session, error) {
	hash := s.hashToken(sessionID)
	row := s.db.QueryRowContext(ctx, `
		SELECT session_id_hash, user_id, tenant_id, session_type,
		       created_at, last_activity, expires_at, status, persistent,
		       client_info, metadata, session_data, security_context, compliance_flags,
		       created_by, modified_at, modified_by
		FROM sessions WHERE session_id_hash = $1`, hash)
	return scanDBSession(row)
}

// UpdateSession replaces all mutable fields of an existing session.
func (s *DatabaseSessionStore) UpdateSession(ctx context.Context, sessionID string, session *business.Session) error {
	if session == nil {
		return fmt.Errorf("database: session cannot be nil")
	}

	now := time.Now().UTC()
	session.ModifiedAt = &now

	hash := s.hashToken(sessionID)

	clientInfoJSON, _ := json.Marshal(session.ClientInfo)
	metaJSON, _ := json.Marshal(stringMapToInterfaceDB(session.Metadata))
	sessionDataJSON, _ := json.Marshal(session.SessionData)
	secCtxJSON, _ := json.Marshal(session.SecurityContext)
	flagsJSON, _ := json.Marshal(session.ComplianceFlags)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin update session tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, session.TenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE sessions
		SET user_id = $2, tenant_id = $3, session_type = $4,
		    last_activity = $5, expires_at = $6, status = $7, persistent = $8,
		    client_info = $9, metadata = $10, session_data = $11,
		    security_context = $12, compliance_flags = $13,
		    modified_at = $14, modified_by = $15
		WHERE session_id_hash = $1`,
		hash,
		session.UserID,
		session.TenantID,
		string(session.SessionType),
		session.LastActivity,
		session.ExpiresAt,
		string(session.Status),
		session.Persistent,
		clientInfoJSON,
		metaJSON,
		sessionDataJSON,
		secCtxJSON,
		flagsJSON,
		pgNullTime(session.ModifiedAt),
		session.ModifiedBy,
	)
	if err != nil {
		return fmt.Errorf("database: failed to update session: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("database: session not found")
	}
	return tx.Commit()
}

// DeleteSession removes a session by its original bearer token.
func (s *DatabaseSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	hash := s.hashToken(sessionID)
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE session_id_hash = $1`, hash)
	if err != nil {
		return fmt.Errorf("database: failed to delete session: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("database: session not found")
	}
	return nil
}

// ListSessions returns sessions matching the filter.
func (s *DatabaseSessionStore) ListSessions(ctx context.Context, filter *business.SessionFilter) ([]*business.Session, error) {
	query, args, tenantID := buildDBSessionQuery(filter)

	if tenantID != "" {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("database: failed to begin list sessions tx: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := setTenantLocal(ctx, tx, tenantID); err != nil {
			return nil, fmt.Errorf("database: failed to set tenant context: %w", err)
		}
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("database: failed to list sessions: %w", err)
		}
		defer func() { _ = rows.Close() }()
		result, scanErr := scanDBSessionRows(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		return result, tx.Commit()
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanDBSessionRows(rows)
}

// SetSessionTTL extends or shortens the session expiry time.
func (s *DatabaseSessionStore) SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	hash := s.hashToken(sessionID)
	newExpiry := time.Now().UTC().Add(ttl)
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET expires_at = $2, modified_at = $3 WHERE session_id_hash = $1`,
		hash, newExpiry, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("database: failed to set session TTL: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("database: session not found")
	}
	return nil
}

// CleanupExpiredSessions removes sessions whose expires_at is in the past.
func (s *DatabaseSessionStore) CleanupExpiredSessions(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < $1`, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("database: failed to cleanup expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GetSessionsByUser returns all sessions for a user.
func (s *DatabaseSessionStore) GetSessionsByUser(ctx context.Context, userID string) ([]*business.Session, error) {
	return s.ListSessions(ctx, &business.SessionFilter{UserID: userID})
}

// GetSessionsByTenant returns all sessions for a tenant, enforcing tenant isolation via RLS.
func (s *DatabaseSessionStore) GetSessionsByTenant(ctx context.Context, tenantID string) ([]*business.Session, error) {
	return s.ListSessions(ctx, &business.SessionFilter{TenantID: tenantID})
}

// GetSessionsByType returns all sessions of a given type.
func (s *DatabaseSessionStore) GetSessionsByType(ctx context.Context, sessionType business.SessionType) ([]*business.Session, error) {
	return s.ListSessions(ctx, &business.SessionFilter{Type: sessionType})
}

// GetActiveSessionsCount returns the number of non-expired active sessions.
func (s *DatabaseSessionStore) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE status = $1 AND expires_at > $2`,
		string(business.SessionStatusActive), time.Now().UTC(),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("database: failed to count active sessions: %w", err)
	}
	return count, nil
}

// HealthCheck verifies the database is reachable.
func (s *DatabaseSessionStore) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// GetStats returns aggregate statistics about stored sessions.
func (s *DatabaseSessionStore) GetStats(ctx context.Context) (*business.RuntimeStoreStats, error) {
	stats := &business.RuntimeStoreStats{
		SessionsByType:   make(map[string]int64),
		SessionsByStatus: make(map[string]int64),
	}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&stats.TotalSessions); err != nil {
		return nil, fmt.Errorf("database: failed to count sessions: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT session_type, COUNT(*) FROM sessions GROUP BY session_type`)
	if err != nil {
		return nil, fmt.Errorf("database: failed to aggregate by type: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		var v int64
		if err := rows.Scan(&k, &v); err == nil {
			stats.SessionsByType[k] = v
		}
	}

	rows2, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM sessions GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("database: failed to aggregate by status: %w", err)
	}
	defer func() { _ = rows2.Close() }()
	for rows2.Next() {
		var k string
		var v int64
		if err := rows2.Scan(&k, &v); err == nil {
			stats.SessionsByStatus[k] = v
		}
	}

	if v, ok := stats.SessionsByStatus[string(business.SessionStatusActive)]; ok {
		stats.ActiveSessions = v
	}
	return stats, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func buildDBSessionQuery(filter *business.SessionFilter) (string, []interface{}, string) {
	base := `SELECT session_id_hash, user_id, tenant_id, session_type,
	                created_at, last_activity, expires_at, status, persistent,
	                client_info, metadata, session_data, security_context, compliance_flags,
	                created_by, modified_at, modified_by
	         FROM sessions`

	if filter == nil {
		return base + " ORDER BY created_at DESC", nil, ""
	}

	var conditions []string
	var args []interface{}
	argN := 0
	tenantID := filter.TenantID

	if filter.UserID != "" {
		argN++
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argN))
		args = append(args, filter.UserID)
	}
	if filter.TenantID != "" {
		argN++
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argN))
		args = append(args, filter.TenantID)
	}
	if filter.Type != "" {
		argN++
		conditions = append(conditions, fmt.Sprintf("session_type = $%d", argN))
		args = append(args, string(filter.Type))
	}
	if filter.Status != "" {
		argN++
		conditions = append(conditions, fmt.Sprintf("status = $%d", argN))
		args = append(args, string(filter.Status))
	}
	if filter.CreatedAfter != nil {
		argN++
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argN))
		args = append(args, *filter.CreatedAfter)
	}
	if filter.CreatedBefore != nil {
		argN++
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argN))
		args = append(args, *filter.CreatedBefore)
	}

	query := base
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		argN++
		query += fmt.Sprintf(" LIMIT $%d", argN)
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		argN++
		query += fmt.Sprintf(" OFFSET $%d", argN)
		args = append(args, filter.Offset)
	}

	return query, args, tenantID
}

func scanDBSession(row *sql.Row) (*business.Session, error) {
	sess := &business.Session{}
	var (
		sessionTypeStr, statusStr                                        string
		clientInfoJSON, metaJSON, sessionDataJSON, secCtxJSON, flagsJSON []byte
		createdAt, lastActivity, expiresAt                               time.Time
		modifiedAt                                                       sql.NullTime
	)
	err := row.Scan(
		&sess.SessionID, &sess.UserID, &sess.TenantID, &sessionTypeStr,
		&createdAt, &lastActivity, &expiresAt, &statusStr, &sess.Persistent,
		&clientInfoJSON, &metaJSON, &sessionDataJSON, &secCtxJSON, &flagsJSON,
		&sess.CreatedBy, &modifiedAt, &sess.ModifiedBy,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("database: session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan session: %w", err)
	}
	return populateDBSession(sess, sessionTypeStr, statusStr, createdAt, lastActivity, expiresAt, modifiedAt,
		clientInfoJSON, metaJSON, sessionDataJSON, secCtxJSON, flagsJSON)
}

func scanDBSessionRows(rows *sql.Rows) ([]*business.Session, error) {
	var sessions []*business.Session
	for rows.Next() {
		sess := &business.Session{}
		var (
			sessionTypeStr, statusStr                                        string
			clientInfoJSON, metaJSON, sessionDataJSON, secCtxJSON, flagsJSON []byte
			createdAt, lastActivity, expiresAt                               time.Time
			modifiedAt                                                       sql.NullTime
		)
		if err := rows.Scan(
			&sess.SessionID, &sess.UserID, &sess.TenantID, &sessionTypeStr,
			&createdAt, &lastActivity, &expiresAt, &statusStr, &sess.Persistent,
			&clientInfoJSON, &metaJSON, &sessionDataJSON, &secCtxJSON, &flagsJSON,
			&sess.CreatedBy, &modifiedAt, &sess.ModifiedBy,
		); err != nil {
			return nil, fmt.Errorf("database: failed to scan session row: %w", err)
		}
		populated, err := populateDBSession(sess, sessionTypeStr, statusStr, createdAt, lastActivity, expiresAt, modifiedAt,
			clientInfoJSON, metaJSON, sessionDataJSON, secCtxJSON, flagsJSON)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, populated)
	}
	return sessions, rows.Err()
}

func populateDBSession(
	sess *business.Session,
	sessionTypeStr, statusStr string,
	createdAt, lastActivity, expiresAt time.Time,
	modifiedAt sql.NullTime,
	clientInfoJSON, metaJSON, sessionDataJSON, secCtxJSON, flagsJSON []byte,
) (*business.Session, error) {
	sess.SessionType = business.SessionType(sessionTypeStr)
	sess.Status = business.SessionStatus(statusStr)
	sess.CreatedAt = createdAt
	sess.LastActivity = lastActivity
	sess.ExpiresAt = expiresAt
	if modifiedAt.Valid {
		t := modifiedAt.Time
		sess.ModifiedAt = &t
	}

	if len(clientInfoJSON) > 0 {
		ci := &business.ClientInfo{}
		if err := json.Unmarshal(clientInfoJSON, ci); err == nil {
			sess.ClientInfo = ci
		}
	}

	var meta map[string]string
	if err := json.Unmarshal(metaJSON, &meta); err == nil {
		sess.Metadata = meta
	}

	if len(sessionDataJSON) > 0 {
		var sd interface{}
		if err := json.Unmarshal(sessionDataJSON, &sd); err == nil {
			sess.SessionData = sd
		}
	}

	var secCtx map[string]interface{}
	if err := json.Unmarshal(secCtxJSON, &secCtx); err == nil {
		sess.SecurityContext = secCtx
	}

	var flags []string
	if err := json.Unmarshal(flagsJSON, &flags); err == nil {
		sess.ComplianceFlags = flags
	}

	return sess, nil
}

// pgNullTime converts a *time.Time to sql.NullTime for PostgreSQL nullable columns.
func pgNullTime(t *time.Time) sql.NullTime {
	if t == nil || t.IsZero() {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// stringMapToInterfaceDB converts map[string]string to map[string]interface{} for JSON marshaling.
func stringMapToInterfaceDB(m map[string]string) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
