// Package database implements database-based runtime storage
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/lib/pq"
)

// DatabaseRuntimeStore implements RuntimeStore interface using PostgreSQL
type DatabaseRuntimeStore struct {
	db             *sql.DB
	tableName      string
	stateTableName string
}

// createTables creates the necessary tables for runtime storage
func (s *DatabaseRuntimeStore) createTables() error {
	// Create sessions table
	sessionTableSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			session_id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL,
			tenant_id VARCHAR(255) NOT NULL,
			session_type VARCHAR(50) NOT NULL,
			status VARCHAR(50) NOT NULL,
			persistent BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			last_activity TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			client_info JSONB,
			metadata JSONB,
			session_data JSONB,
			security_context JSONB,
			compliance_flags TEXT[],
			created_by VARCHAR(255),
			modified_at TIMESTAMP WITH TIME ZONE,
			modified_by VARCHAR(255)
		)`, s.tableName)

	if _, err := s.db.Exec(sessionTableSQL); err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}

	// Create indexes for efficient queries
	indexes := []string{
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_user_id ON %s (user_id)", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_tenant_id ON %s (tenant_id)", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_type ON %s (session_type)", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_status ON %s (status)", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_expires_at ON %s (expires_at)", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_persistent ON %s (persistent)", s.tableName, s.tableName),
	}

	for _, indexSQL := range indexes {
		if _, err := s.db.Exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	// Create runtime state table
	stateTableSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			key VARCHAR(255) PRIMARY KEY,
			value JSONB NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`, s.stateTableName)

	if _, err := s.db.Exec(stateTableSQL); err != nil {
		return fmt.Errorf("failed to create runtime state table: %w", err)
	}

	return nil
}

// Session Management Implementation

// CreateSession stores a session in the database (only if persistent=true)
func (s *DatabaseRuntimeStore) CreateSession(ctx context.Context, session *interfaces.Session) error {
	if err := session.Validate(); err != nil {
		return fmt.Errorf("session validation failed: %w", err)
	}

	// Only store persistent sessions in database
	if !session.Persistent {
		return fmt.Errorf("database runtime store only handles persistent sessions")
	}

	// Marshal JSON fields
	clientInfoJSON, err := json.Marshal(session.ClientInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal client info: %w", err)
	}

	metadataJSON, err := json.Marshal(session.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	sessionDataJSON, err := json.Marshal(session.SessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	securityContextJSON, err := json.Marshal(session.SecurityContext)
	if err != nil {
		return fmt.Errorf("failed to marshal security context: %w", err)
	}

	// Insert session
	query := fmt.Sprintf(`
		INSERT INTO %s (
			session_id, user_id, tenant_id, session_type, status, persistent,
			created_at, last_activity, expires_at, client_info, metadata,
			session_data, security_context, compliance_flags, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`, s.tableName)

	_, err = s.db.ExecContext(ctx, query,
		session.SessionID, session.UserID, session.TenantID, session.SessionType, session.Status,
		session.Persistent, session.CreatedAt, session.LastActivity, session.ExpiresAt,
		clientInfoJSON, metadataJSON, sessionDataJSON, securityContextJSON,
		pq.Array(session.ComplianceFlags), session.CreatedBy)

	if err != nil {
		return fmt.Errorf("failed to insert session: %w", err)
	}

	return nil
}

// GetSession retrieves a session by ID
func (s *DatabaseRuntimeStore) GetSession(ctx context.Context, sessionID string) (*interfaces.Session, error) {
	query := fmt.Sprintf(`
		SELECT session_id, user_id, tenant_id, session_type, status, persistent,
		       created_at, last_activity, expires_at, client_info, metadata,
		       session_data, security_context, compliance_flags, created_by,
		       modified_at, modified_by
		FROM %s WHERE session_id = $1
	`, s.tableName)

	row := s.db.QueryRowContext(ctx, query, sessionID)

	session := &interfaces.Session{}
	var clientInfoJSON, metadataJSON, sessionDataJSON, securityContextJSON []byte
	var complianceFlags pq.StringArray

	err := row.Scan(
		&session.SessionID, &session.UserID, &session.TenantID, &session.SessionType,
		&session.Status, &session.Persistent, &session.CreatedAt, &session.LastActivity,
		&session.ExpiresAt, &clientInfoJSON, &metadataJSON, &sessionDataJSON,
		&securityContextJSON, &complianceFlags, &session.CreatedBy,
		&session.ModifiedAt, &session.ModifiedBy)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session %s not found", sessionID)
		}
		return nil, fmt.Errorf("failed to query session: %w", err)
	}

	// Unmarshal JSON fields
	if len(clientInfoJSON) > 0 && string(clientInfoJSON) != "null" {
		if err := json.Unmarshal(clientInfoJSON, &session.ClientInfo); err != nil {
			return nil, fmt.Errorf("failed to unmarshal client info: %w", err)
		}
	}

	if len(metadataJSON) > 0 && string(metadataJSON) != "null" {
		if err := json.Unmarshal(metadataJSON, &session.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	if len(sessionDataJSON) > 0 && string(sessionDataJSON) != "null" {
		if err := json.Unmarshal(sessionDataJSON, &session.SessionData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
		}
	}

	if len(securityContextJSON) > 0 && string(securityContextJSON) != "null" {
		if err := json.Unmarshal(securityContextJSON, &session.SecurityContext); err != nil {
			return nil, fmt.Errorf("failed to unmarshal security context: %w", err)
		}
	}

	session.ComplianceFlags = []string(complianceFlags)

	return session, nil
}

// UpdateSession updates an existing session
func (s *DatabaseRuntimeStore) UpdateSession(ctx context.Context, sessionID string, session *interfaces.Session) error {
	if err := session.Validate(); err != nil {
		return fmt.Errorf("session validation failed: %w", err)
	}

	// Only update persistent sessions in database
	if !session.Persistent {
		return fmt.Errorf("database runtime store only handles persistent sessions")
	}

	// Marshal JSON fields
	clientInfoJSON, err := json.Marshal(session.ClientInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal client info: %w", err)
	}

	metadataJSON, err := json.Marshal(session.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	sessionDataJSON, err := json.Marshal(session.SessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	securityContextJSON, err := json.Marshal(session.SecurityContext)
	if err != nil {
		return fmt.Errorf("failed to marshal security context: %w", err)
	}

	now := time.Now()
	session.ModifiedAt = &now

	query := fmt.Sprintf(`
		UPDATE %s SET
			user_id = $2, tenant_id = $3, session_type = $4, status = $5,
			last_activity = $6, expires_at = $7, client_info = $8, metadata = $9,
			session_data = $10, security_context = $11, compliance_flags = $12,
			modified_at = $13, modified_by = $14
		WHERE session_id = $1
	`, s.tableName)

	result, err := s.db.ExecContext(ctx, query,
		sessionID, session.UserID, session.TenantID, session.SessionType, session.Status,
		session.LastActivity, session.ExpiresAt, clientInfoJSON, metadataJSON,
		sessionDataJSON, securityContextJSON, pq.Array(session.ComplianceFlags),
		session.ModifiedAt, session.ModifiedBy)

	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session %s not found", sessionID)
	}

	return nil
}

// DeleteSession removes a session from the database
func (s *DatabaseRuntimeStore) DeleteSession(ctx context.Context, sessionID string) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE session_id = $1", s.tableName)
	
	result, err := s.db.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session %s not found", sessionID)
	}

	return nil
}

// ListSessions returns sessions matching the filter
func (s *DatabaseRuntimeStore) ListSessions(ctx context.Context, filters *interfaces.SessionFilter) ([]*interfaces.Session, error) {
	query := fmt.Sprintf(`
		SELECT session_id, user_id, tenant_id, session_type, status, persistent,
		       created_at, last_activity, expires_at, client_info, metadata,
		       session_data, security_context, compliance_flags, created_by,
		       modified_at, modified_by
		FROM %s WHERE 1=1
	`, s.tableName)

	args := []interface{}{}
	argIndex := 1

	// Build WHERE conditions
	if filters != nil {
		if filters.UserID != "" {
			query += fmt.Sprintf(" AND user_id = $%d", argIndex)
			args = append(args, filters.UserID)
			argIndex++
		}
		if filters.TenantID != "" {
			query += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
			args = append(args, filters.TenantID)
			argIndex++
		}
		if filters.Type != "" {
			query += fmt.Sprintf(" AND session_type = $%d", argIndex)
			args = append(args, filters.Type)
			argIndex++
		}
		if filters.Status != "" {
			query += fmt.Sprintf(" AND status = $%d", argIndex)
			args = append(args, filters.Status)
			argIndex++
		}
		if filters.CreatedAfter != nil {
			query += fmt.Sprintf(" AND created_at > $%d", argIndex)
			args = append(args, *filters.CreatedAfter)
			argIndex++
		}
		if filters.CreatedBefore != nil {
			query += fmt.Sprintf(" AND created_at < $%d", argIndex)
			args = append(args, *filters.CreatedBefore)
			argIndex++
		}
		if filters.IPAddress != "" {
			query += fmt.Sprintf(" AND client_info->>'ip_address' = $%d", argIndex)
			args = append(args, filters.IPAddress)
			argIndex++
		}
	}

	// Add ordering
	query += " ORDER BY created_at DESC"

	// Add pagination
	if filters != nil && filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filters.Limit)
		argIndex++

		if filters.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, filters.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	var sessions []*interfaces.Session
	for rows.Next() {
		session := &interfaces.Session{}
		var clientInfoJSON, metadataJSON, sessionDataJSON, securityContextJSON []byte
		var complianceFlags pq.StringArray

		err := rows.Scan(
			&session.SessionID, &session.UserID, &session.TenantID, &session.SessionType,
			&session.Status, &session.Persistent, &session.CreatedAt, &session.LastActivity,
			&session.ExpiresAt, &clientInfoJSON, &metadataJSON, &sessionDataJSON,
			&securityContextJSON, &complianceFlags, &session.CreatedBy,
			&session.ModifiedAt, &session.ModifiedBy)

		if err != nil {
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}

		// Unmarshal JSON fields
		if len(clientInfoJSON) > 0 && string(clientInfoJSON) != "null" {
			if err := json.Unmarshal(clientInfoJSON, &session.ClientInfo); err != nil {
				return nil, fmt.Errorf("failed to unmarshal client info: %w", err)
			}
		}

		if len(metadataJSON) > 0 && string(metadataJSON) != "null" {
			if err := json.Unmarshal(metadataJSON, &session.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		if len(sessionDataJSON) > 0 && string(sessionDataJSON) != "null" {
			if err := json.Unmarshal(sessionDataJSON, &session.SessionData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
			}
		}

		if len(securityContextJSON) > 0 && string(securityContextJSON) != "null" {
			if err := json.Unmarshal(securityContextJSON, &session.SecurityContext); err != nil {
				return nil, fmt.Errorf("failed to unmarshal security context: %w", err)
			}
		}

		session.ComplianceFlags = []string(complianceFlags)
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating session rows: %w", err)
	}

	return sessions, nil
}

// Session Lifecycle Management

// SetSessionTTL sets the TTL for a session
func (s *DatabaseRuntimeStore) SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	expiresAt := time.Now().Add(ttl)
	query := fmt.Sprintf(`
		UPDATE %s SET expires_at = $1, modified_at = $2 
		WHERE session_id = $3
	`, s.tableName)

	result, err := s.db.ExecContext(ctx, query, expiresAt, time.Now(), sessionID)
	if err != nil {
		return fmt.Errorf("failed to update session TTL: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session %s not found", sessionID)
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions and returns count
func (s *DatabaseRuntimeStore) CleanupExpiredSessions(ctx context.Context) (int, error) {
	query := fmt.Sprintf("DELETE FROM %s WHERE expires_at < $1", s.tableName)
	
	result, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rowsAffected), nil
}

// ListExpiredSessions returns IDs of expired sessions
func (s *DatabaseRuntimeStore) ListExpiredSessions(ctx context.Context, cutoff time.Time) ([]string, error) {
	query := fmt.Sprintf("SELECT session_id FROM %s WHERE expires_at < $1", s.tableName)
	
	rows, err := s.db.QueryContext(ctx, query, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to query expired sessions: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	var sessionIDs []string
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			return nil, fmt.Errorf("failed to scan session ID: %w", err)
		}
		sessionIDs = append(sessionIDs, sessionID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating expired sessions: %w", err)
	}

	return sessionIDs, nil
}

// Runtime State Management

// SetRuntimeState stores runtime state (only for critical state that needs persistence)
func (s *DatabaseRuntimeStore) SetRuntimeState(ctx context.Context, key string, value interface{}) error {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal runtime state value: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (key, value, created_at, modified_at) 
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (key) 
		DO UPDATE SET value = EXCLUDED.value, modified_at = NOW()
	`, s.stateTableName)

	_, err = s.db.ExecContext(ctx, query, key, valueJSON)
	if err != nil {
		return fmt.Errorf("failed to set runtime state: %w", err)
	}

	return nil
}

// GetRuntimeState retrieves runtime state
func (s *DatabaseRuntimeStore) GetRuntimeState(ctx context.Context, key string) (interface{}, error) {
	query := fmt.Sprintf("SELECT value FROM %s WHERE key = $1", s.stateTableName)
	
	var valueJSON []byte
	err := s.db.QueryRowContext(ctx, query, key).Scan(&valueJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("runtime state key %s not found", key)
		}
		return nil, fmt.Errorf("failed to query runtime state: %w", err)
	}

	var value interface{}
	if err := json.Unmarshal(valueJSON, &value); err != nil {
		return nil, fmt.Errorf("failed to unmarshal runtime state value: %w", err)
	}

	return value, nil
}

// DeleteRuntimeState removes runtime state
func (s *DatabaseRuntimeStore) DeleteRuntimeState(ctx context.Context, key string) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE key = $1", s.stateTableName)
	
	result, err := s.db.ExecContext(ctx, query, key)
	if err != nil {
		return fmt.Errorf("failed to delete runtime state: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("runtime state key %s not found", key)
	}

	return nil
}

// ListRuntimeKeys returns runtime state keys with optional prefix filter
func (s *DatabaseRuntimeStore) ListRuntimeKeys(ctx context.Context, prefix string) ([]string, error) {
	var query string
	var args []interface{}

	if prefix == "" {
		query = fmt.Sprintf("SELECT key FROM %s ORDER BY key", s.stateTableName)
	} else {
		query = fmt.Sprintf("SELECT key FROM %s WHERE key LIKE $1 ORDER BY key", s.stateTableName)
		args = append(args, prefix+"%")
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query runtime state keys: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("failed to scan runtime state key: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating runtime state keys: %w", err)
	}

	return keys, nil
}

// Batch Operations

// CreateSessionsBatch creates multiple sessions (only persistent ones)
func (s *DatabaseRuntimeStore) CreateSessionsBatch(ctx context.Context, sessions []*interfaces.Session) error {
	if len(sessions) == 0 {
		return nil
	}

	// Filter for persistent sessions only
	var persistentSessions []*interfaces.Session
	for _, session := range sessions {
		if session.Persistent {
			persistentSessions = append(persistentSessions, session)
		}
	}

	if len(persistentSessions) == 0 {
		return fmt.Errorf("database runtime store only handles persistent sessions")
	}

	// Use transaction for batch insert
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			// Transaction rollback completed or already committed
			_ = err
		}
	}()

	query := fmt.Sprintf(`
		INSERT INTO %s (
			session_id, user_id, tenant_id, session_type, status, persistent,
			created_at, last_activity, expires_at, client_info, metadata,
			session_data, security_context, compliance_flags, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`, s.tableName)

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	for _, session := range persistentSessions {
		if err := session.Validate(); err != nil {
			return fmt.Errorf("session validation failed for %s: %w", session.SessionID, err)
		}

		// Marshal JSON fields
		clientInfoJSON, _ := json.Marshal(session.ClientInfo)
		metadataJSON, _ := json.Marshal(session.Metadata)
		sessionDataJSON, _ := json.Marshal(session.SessionData)
		securityContextJSON, _ := json.Marshal(session.SecurityContext)

		_, err := stmt.ExecContext(ctx,
			session.SessionID, session.UserID, session.TenantID, session.SessionType, session.Status,
			session.Persistent, session.CreatedAt, session.LastActivity, session.ExpiresAt,
			clientInfoJSON, metadataJSON, sessionDataJSON, securityContextJSON,
			pq.Array(session.ComplianceFlags), session.CreatedBy)

		if err != nil {
			return fmt.Errorf("failed to insert session %s: %w", session.SessionID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteSessionsBatch deletes multiple sessions
func (s *DatabaseRuntimeStore) DeleteSessionsBatch(ctx context.Context, sessionIDs []string) error {
	if len(sessionIDs) == 0 {
		return nil
	}

	// Use ANY operator for efficient bulk delete
	query := fmt.Sprintf("DELETE FROM %s WHERE session_id = ANY($1)", s.tableName)
	
	_, err := s.db.ExecContext(ctx, query, pq.Array(sessionIDs))
	if err != nil {
		return fmt.Errorf("failed to delete sessions batch: %w", err)
	}

	return nil
}

// Session Queries

// GetSessionsByUser returns sessions for a specific user
func (s *DatabaseRuntimeStore) GetSessionsByUser(ctx context.Context, userID string) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{UserID: userID}
	return s.ListSessions(ctx, filter)
}

// GetSessionsByTenant returns sessions for a specific tenant
func (s *DatabaseRuntimeStore) GetSessionsByTenant(ctx context.Context, tenantID string) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{TenantID: tenantID}
	return s.ListSessions(ctx, filter)
}

// GetSessionsByType returns sessions of a specific type
func (s *DatabaseRuntimeStore) GetSessionsByType(ctx context.Context, sessionType interfaces.SessionType) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{Type: sessionType}
	return s.ListSessions(ctx, filter)
}

// GetActiveSessionsCount returns the count of active sessions
func (s *DatabaseRuntimeStore) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*) FROM %s 
		WHERE status = 'active' AND expires_at > $1
	`, s.tableName)

	var count int64
	err := s.db.QueryRowContext(ctx, query, time.Now()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}

	return count, nil
}

// Health and Maintenance

// HealthCheck verifies database connectivity
func (s *DatabaseRuntimeStore) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// GetStats returns runtime store statistics
func (s *DatabaseRuntimeStore) GetStats(ctx context.Context) (*interfaces.RuntimeStoreStats, error) {
	stats := &interfaces.RuntimeStoreStats{
		SessionsByType:   make(map[string]int64),
		SessionsByStatus: make(map[string]int64),
		ProviderStats:    make(map[string]interface{}),
	}

	// Get total and active sessions
	query := fmt.Sprintf(`
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN status = 'active' AND expires_at > NOW() THEN 1 END) as active,
			COUNT(CASE WHEN expires_at <= NOW() THEN 1 END) as expired
		FROM %s
	`, s.tableName)

	err := s.db.QueryRowContext(ctx, query).Scan(&stats.TotalSessions, &stats.ActiveSessions, &stats.ExpiredSessions)
	if err != nil {
		return nil, fmt.Errorf("failed to get session counts: %w", err)
	}

	// Get sessions by type
	query = fmt.Sprintf("SELECT session_type, COUNT(*) FROM %s GROUP BY session_type", s.tableName)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions by type: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	for rows.Next() {
		var sessionType string
		var count int64
		if err := rows.Scan(&sessionType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan session type stats: %w", err)
		}
		stats.SessionsByType[sessionType] = count
	}

	// Get sessions by status
	query = fmt.Sprintf("SELECT status, COUNT(*) FROM %s GROUP BY status", s.tableName)
	rows, err = s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions by status: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
	}()

	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan session status stats: %w", err)
		}
		stats.SessionsByStatus[status] = count
	}

	// Get runtime state count
	query = fmt.Sprintf("SELECT COUNT(*) FROM %s", s.stateTableName)
	err = s.db.QueryRowContext(ctx, query).Scan(&stats.RuntimeStateKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to get runtime state count: %w", err)
	}

	// Add provider-specific stats
	stats.ProviderStats["provider_type"] = "database"
	stats.ProviderStats["sessions_table"] = s.tableName
	stats.ProviderStats["state_table"] = s.stateTableName

	return stats, nil
}

// Vacuum performs cleanup/optimization
func (s *DatabaseRuntimeStore) Vacuum(ctx context.Context) error {
	// Clean up expired sessions
	_, err := s.CleanupExpiredSessions(ctx)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	// Run database vacuum on tables
	vacuumQueries := []string{
		fmt.Sprintf("VACUUM ANALYZE %s", s.tableName),
		fmt.Sprintf("VACUUM ANALYZE %s", s.stateTableName),
	}

	for _, query := range vacuumQueries {
		if _, err := s.db.ExecContext(ctx, query); err != nil {
			// Log warning but don't fail (vacuum may require special privileges)
			// In production, this would use proper logging
		}
	}

	return nil
}