// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements SessionStore using SQLite (durable Persistent=true sessions only)
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// SQLiteSessionStore implements interfaces.SessionStore using SQLite.
// Only sessions with Persistent=true should be written here; ephemeral sessions
// (Persistent=false) belong in pkg/cache.
type SQLiteSessionStore struct {
	db *sql.DB
}

// Initialize is a no-op; schema is applied in openAndInit.
func (s *SQLiteSessionStore) Initialize(_ context.Context) error { return nil }

// Close closes the database connection.
func (s *SQLiteSessionStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateSession inserts a new durable session. Only Persistent=true sessions may be stored here;
// ephemeral sessions (Persistent=false) belong in pkg/cache.
func (s *SQLiteSessionStore) CreateSession(ctx context.Context, session *interfaces.Session) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	if !session.Persistent {
		return fmt.Errorf("session %s is not persistent: durable SessionStore only accepts Persistent=true sessions", session.SessionID)
	}
	if err := session.Validate(); err != nil {
		return fmt.Errorf("invalid session: %w", err)
	}

	clientInfoJSON, err := marshalClientInfo(session.ClientInfo)
	if err != nil {
		return err
	}
	metaJSON, err := marshalJSON(stringMapToInterface(session.Metadata))
	if err != nil {
		return err
	}
	sessionDataJSON, err := marshalSessionData(session.SessionData)
	if err != nil {
		return err
	}
	secCtxJSON, err := marshalJSON(session.SecurityContext)
	if err != nil {
		return err
	}
	flags, err := marshalJSONSlice(session.ComplianceFlags)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sessions
			(session_id, user_id, tenant_id, session_type,
			 created_at, last_activity, expires_at, status, persistent,
			 client_info, metadata, session_data, security_context, compliance_flags,
			 created_by, modified_at, modified_by)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		session.SessionID,
		session.UserID,
		session.TenantID,
		string(session.SessionType),
		formatTime(session.CreatedAt),
		formatTime(session.LastActivity),
		formatTime(session.ExpiresAt),
		string(session.Status),
		boolToInt(session.Persistent),
		clientInfoJSON,
		metaJSON,
		sessionDataJSON,
		secCtxJSON,
		flags,
		session.CreatedBy,
		nullTime(session.ModifiedAt),
		session.ModifiedBy,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("session %s already exists", session.SessionID)
		}
		return fmt.Errorf("failed to create session %s: %w", session.SessionID, err)
	}
	return nil
}

// GetSession retrieves a session by ID.
func (s *SQLiteSessionStore) GetSession(ctx context.Context, sessionID string) (*interfaces.Session, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT session_id, user_id, tenant_id, session_type,
		       created_at, last_activity, expires_at, status, persistent,
		       client_info, metadata, session_data, security_context, compliance_flags,
		       created_by, modified_at, modified_by
		FROM sessions WHERE session_id = ?`, sessionID)
	return scanSession(row)
}

// UpdateSession replaces all mutable fields of an existing session.
func (s *SQLiteSessionStore) UpdateSession(ctx context.Context, sessionID string, session *interfaces.Session) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}

	now := nowUTC()
	session.ModifiedAt = &now
	session.SessionID = sessionID

	clientInfoJSON, err := marshalClientInfo(session.ClientInfo)
	if err != nil {
		return err
	}
	metaJSON, err := marshalJSON(stringMapToInterface(session.Metadata))
	if err != nil {
		return err
	}
	sessionDataJSON, err := marshalSessionData(session.SessionData)
	if err != nil {
		return err
	}
	secCtxJSON, err := marshalJSON(session.SecurityContext)
	if err != nil {
		return err
	}
	flags, err := marshalJSONSlice(session.ComplianceFlags)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions
		SET user_id = ?, tenant_id = ?, session_type = ?,
		    last_activity = ?, expires_at = ?, status = ?, persistent = ?,
		    client_info = ?, metadata = ?, session_data = ?,
		    security_context = ?, compliance_flags = ?,
		    modified_at = ?, modified_by = ?
		WHERE session_id = ?`,
		session.UserID,
		session.TenantID,
		string(session.SessionType),
		formatTime(session.LastActivity),
		formatTime(session.ExpiresAt),
		string(session.Status),
		boolToInt(session.Persistent),
		clientInfoJSON,
		metaJSON,
		sessionDataJSON,
		secCtxJSON,
		flags,
		nullTime(session.ModifiedAt),
		session.ModifiedBy,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to update session %s: %w", sessionID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session %s not found", sessionID)
	}
	return nil
}

// DeleteSession removes a session by ID.
func (s *SQLiteSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE session_id = ?`, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session %s: %w", sessionID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session %s not found", sessionID)
	}
	return nil
}

// ListSessions returns sessions matching the filter.
func (s *SQLiteSessionStore) ListSessions(ctx context.Context, filter *interfaces.SessionFilter) ([]*interfaces.Session, error) {
	query, args := buildSessionQuery(filter)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []*interfaces.Session
	for rows.Next() {
		sess, err := scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

// SetSessionTTL updates the expiry time of a session.
func (s *SQLiteSessionStore) SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	newExpiry := nowUTC().Add(ttl)
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET expires_at = ?, modified_at = ? WHERE session_id = ?`,
		formatTime(newExpiry), formatTime(nowUTC()), sessionID)
	if err != nil {
		return fmt.Errorf("failed to set session TTL: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session %s not found", sessionID)
	}
	return nil
}

// CleanupExpiredSessions removes sessions whose expires_at is in the past.
// Returns the number of sessions deleted.
func (s *SQLiteSessionStore) CleanupExpiredSessions(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at < ?`, formatTime(nowUTC()))
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GetSessionsByUser returns all sessions for a user.
func (s *SQLiteSessionStore) GetSessionsByUser(ctx context.Context, userID string) ([]*interfaces.Session, error) {
	return s.ListSessions(ctx, &interfaces.SessionFilter{UserID: userID})
}

// GetSessionsByTenant returns all sessions for a tenant.
func (s *SQLiteSessionStore) GetSessionsByTenant(ctx context.Context, tenantID string) ([]*interfaces.Session, error) {
	return s.ListSessions(ctx, &interfaces.SessionFilter{TenantID: tenantID})
}

// GetSessionsByType returns all sessions of a specific type.
func (s *SQLiteSessionStore) GetSessionsByType(ctx context.Context, sessionType interfaces.SessionType) ([]*interfaces.Session, error) {
	return s.ListSessions(ctx, &interfaces.SessionFilter{Type: sessionType})
}

// GetActiveSessionsCount returns the number of non-expired active sessions.
func (s *SQLiteSessionStore) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE status = ? AND expires_at > ?`,
		string(interfaces.SessionStatusActive), formatTime(nowUTC()),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}
	return count, nil
}

// HealthCheck verifies the database is reachable.
func (s *SQLiteSessionStore) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// GetStats returns aggregate statistics about stored sessions.
func (s *SQLiteSessionStore) GetStats(ctx context.Context) (*interfaces.RuntimeStoreStats, error) {
	stats := &interfaces.RuntimeStoreStats{
		SessionsByType:   make(map[string]int64),
		SessionsByStatus: make(map[string]int64),
	}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&stats.TotalSessions); err != nil {
		return nil, fmt.Errorf("failed to count total sessions: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT session_type, COUNT(*) FROM sessions GROUP BY session_type`)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate sessions by type: %w", err)
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
		return nil, fmt.Errorf("failed to aggregate sessions by status: %w", err)
	}
	defer func() { _ = rows2.Close() }()
	for rows2.Next() {
		var k string
		var v int64
		if err := rows2.Scan(&k, &v); err == nil {
			stats.SessionsByStatus[k] = v
		}
	}

	if v, ok := stats.SessionsByStatus[string(interfaces.SessionStatusActive)]; ok {
		stats.ActiveSessions = v
	}

	return stats, nil
}

// ---- helpers ----------------------------------------------------------------

func buildSessionQuery(filter *interfaces.SessionFilter) (string, []interface{}) {
	base := `SELECT session_id, user_id, tenant_id, session_type,
	                created_at, last_activity, expires_at, status, persistent,
	                client_info, metadata, session_data, security_context, compliance_flags,
	                created_by, modified_at, modified_by
	         FROM sessions`

	if filter == nil {
		return base + ` ORDER BY created_at DESC`, nil
	}

	var conditions []string
	var args []interface{}

	if filter.UserID != "" {
		conditions = append(conditions, `user_id = ?`)
		args = append(args, filter.UserID)
	}
	if filter.TenantID != "" {
		conditions = append(conditions, `tenant_id = ?`)
		args = append(args, filter.TenantID)
	}
	if filter.Type != "" {
		conditions = append(conditions, `session_type = ?`)
		args = append(args, string(filter.Type))
	}
	if filter.Status != "" {
		conditions = append(conditions, `status = ?`)
		args = append(args, string(filter.Status))
	}
	if filter.CreatedAfter != nil {
		conditions = append(conditions, `created_at >= ?`)
		args = append(args, formatTime(*filter.CreatedAfter))
	}
	if filter.CreatedBefore != nil {
		conditions = append(conditions, `created_at <= ?`)
		args = append(args, formatTime(*filter.CreatedBefore))
	}

	query := base
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY created_at DESC`

	if filter.Limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(` OFFSET %d`, filter.Offset)
	}

	return query, args
}

func scanSession(row *sql.Row) (*interfaces.Session, error) {
	sess := &interfaces.Session{}
	var (
		sessionTypeStr, statusStr                                    string
		createdStr, lastActivityStr, expiresStr                      string
		clientInfoStr, metaStr, sessionDataStr, secCtxStr, flagsStr  string
		persistentInt                                                 int
		modifiedAt                                                    sql.NullString
	)
	err := row.Scan(
		&sess.SessionID, &sess.UserID, &sess.TenantID, &sessionTypeStr,
		&createdStr, &lastActivityStr, &expiresStr, &statusStr, &persistentInt,
		&clientInfoStr, &metaStr, &sessionDataStr, &secCtxStr, &flagsStr,
		&sess.CreatedBy, &modifiedAt, &sess.ModifiedBy,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}
	return populateSession(sess, sessionTypeStr, statusStr, createdStr, lastActivityStr, expiresStr,
		persistentInt, clientInfoStr, metaStr, sessionDataStr, secCtxStr, flagsStr, modifiedAt)
}

func scanSessionRow(rows *sql.Rows) (*interfaces.Session, error) {
	sess := &interfaces.Session{}
	var (
		sessionTypeStr, statusStr                                    string
		createdStr, lastActivityStr, expiresStr                      string
		clientInfoStr, metaStr, sessionDataStr, secCtxStr, flagsStr  string
		persistentInt                                                 int
		modifiedAt                                                    sql.NullString
	)
	if err := rows.Scan(
		&sess.SessionID, &sess.UserID, &sess.TenantID, &sessionTypeStr,
		&createdStr, &lastActivityStr, &expiresStr, &statusStr, &persistentInt,
		&clientInfoStr, &metaStr, &sessionDataStr, &secCtxStr, &flagsStr,
		&sess.CreatedBy, &modifiedAt, &sess.ModifiedBy,
	); err != nil {
		return nil, fmt.Errorf("failed to scan session row: %w", err)
	}
	return populateSession(sess, sessionTypeStr, statusStr, createdStr, lastActivityStr, expiresStr,
		persistentInt, clientInfoStr, metaStr, sessionDataStr, secCtxStr, flagsStr, modifiedAt)
}

func populateSession(
	sess *interfaces.Session,
	sessionTypeStr, statusStr,
	createdStr, lastActivityStr, expiresStr string,
	persistentInt int,
	clientInfoStr, metaStr, sessionDataStr, secCtxStr, flagsStr string,
	modifiedAt sql.NullString,
) (*interfaces.Session, error) {
	sess.SessionType = interfaces.SessionType(sessionTypeStr)
	sess.Status = interfaces.SessionStatus(statusStr)
	sess.CreatedAt = parseTime(createdStr)
	sess.LastActivity = parseTime(lastActivityStr)
	sess.ExpiresAt = parseTime(expiresStr)
	sess.Persistent = persistentInt != 0
	sess.ModifiedAt = parseNullTime(modifiedAt)

	// ClientInfo
	if clientInfoStr != "" && clientInfoStr != "{}" {
		ci := &interfaces.ClientInfo{}
		if err := json.Unmarshal([]byte(clientInfoStr), ci); err == nil {
			sess.ClientInfo = ci
		}
	}

	// Metadata (map[string]string)
	meta, err := unmarshalJSONStringMap(metaStr)
	if err == nil {
		sess.Metadata = meta
	}

	// SessionData (arbitrary interface{})
	if sessionDataStr != "" && sessionDataStr != "{}" && sessionDataStr != "null" {
		var sd interface{}
		if err := json.Unmarshal([]byte(sessionDataStr), &sd); err == nil {
			sess.SessionData = sd
		}
	}

	// SecurityContext
	secCtx, _ := unmarshalJSONMap(secCtxStr)
	sess.SecurityContext = secCtx

	// ComplianceFlags
	flags, _ := unmarshalJSONSlice(flagsStr)
	sess.ComplianceFlags = flags

	return sess, nil
}

func marshalClientInfo(ci *interfaces.ClientInfo) (string, error) {
	if ci == nil {
		return "{}", nil
	}
	b, err := json.Marshal(ci)
	if err != nil {
		return "", fmt.Errorf("failed to marshal client info: %w", err)
	}
	return string(b), nil
}

func marshalSessionData(data interface{}) (string, error) {
	if data == nil {
		return "{}", nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}
	return string(b), nil
}

func stringMapToInterface(m map[string]string) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ensure SQLiteSessionStore satisfies the interface at compile time
var _ interfaces.SessionStore = (*SQLiteSessionStore)(nil)
