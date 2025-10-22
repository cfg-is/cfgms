// Package database implements AuditStore interface using PostgreSQL
package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lib/pq"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// DatabaseAuditStore implements AuditStore using PostgreSQL for persistence
type DatabaseAuditStore struct {
	db      *sql.DB
	config  map[string]interface{}
	mutex   sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseAuditStore creates a new PostgreSQL-based audit store
func NewDatabaseAuditStore(dsn string, config map[string]interface{}) (*DatabaseAuditStore, error) {
	// Open database connection with connection pooling
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool for audit workload
	maxOpenConns := getIntFromConfig(config, "max_open_connections", 50) // Higher for audit writes
	maxIdleConns := getIntFromConfig(config, "max_idle_connections", 10)
	connMaxLifetime := time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	// Test connection
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &DatabaseAuditStore{
		db:      db,
		config:  config,
		schemas: NewDatabaseSchemas(),
	}

	// Initialize database schema
	if err := store.initializeSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return store, nil
}

// initializeSchema creates the necessary database tables and indexes for audit storage
func (s *DatabaseAuditStore) initializeSchema() error {
	ctx := context.Background()

	// Use PostgreSQL advisory lock to prevent concurrent schema initialization
	// Lock ID: 87654321 (different from config store lock)
	const schemaLockID = 87654321

	// Acquire advisory lock - will wait if another instance is initializing
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire audit schema initialization lock: %w", err)
	}

	// Ensure we release the lock when done
	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			// Log but don't fail - lock will be released when connection closes
			// This is non-critical since PostgreSQL will release advisory locks when connection closes
			_ = err // Explicitly ignore error to satisfy linter
		}
	}()

	// Create audit entries table
	if err := s.schemas.CreateAuditEntriesTable(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create audit_entries table: %w", err)
	}

	// Create audit statistics materialized view
	if err := s.schemas.CreateAuditStatsView(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create audit_stats materialized view: %w", err)
	}

	return nil
}

// StoreAuditEntry stores an audit entry in the database
func (s *DatabaseAuditStore) StoreAuditEntry(ctx context.Context, entry *interfaces.AuditEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Validate and prepare audit entry
	if err := s.validateAuditEntry(entry); err != nil {
		return err
	}

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Set metadata
	if entry.ID == "" {
		entry.ID = s.generateAuditID(entry)
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	if entry.Severity == "" {
		entry.Severity = interfaces.AuditSeverityLow
	}
	if entry.UserType == "" {
		entry.UserType = interfaces.AuditUserTypeHuman
	}
	if entry.Version == "" {
		entry.Version = "1.0"
	}

	// Calculate checksum for integrity
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}
	hasher := sha256.New()
	hasher.Write(entryJSON)
	entry.Checksum = hex.EncodeToString(hasher.Sum(nil))

	// Serialize complex fields
	detailsJSON, err := serializeMetadata(entry.Details)
	if err != nil {
		return fmt.Errorf("failed to serialize details: %w", err)
	}

	changesJSON, err := serializeAuditChanges(entry.Changes)
	if err != nil {
		return fmt.Errorf("failed to serialize changes: %w", err)
	}

	// Parse IP address
	var ipAddr net.IP
	if entry.IPAddress != "" {
		ipAddr = net.ParseIP(entry.IPAddress)
	}

	// Insert audit entry
	query := `
		INSERT INTO audit_entries (
			id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
			resource_type, resource_id, resource_name, result, error_code, error_message,
			request_id, ip_address, user_agent, method, path, details, changes, tags,
			severity, source, version, checksum
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26
		)
	`

	_, err = tx.ExecContext(ctx, query,
		entry.ID,
		entry.TenantID,
		entry.Timestamp,
		string(entry.EventType),
		entry.Action,
		entry.UserID,
		string(entry.UserType),
		convertNullString(entry.SessionID),
		entry.ResourceType,
		entry.ResourceID,
		convertNullString(entry.ResourceName),
		string(entry.Result),
		convertNullString(entry.ErrorCode),
		convertNullString(entry.ErrorMessage),
		convertNullString(entry.RequestID),
		ipAddr,
		convertNullString(entry.UserAgent),
		convertNullString(entry.Method),
		convertNullString(entry.Path),
		detailsJSON,
		changesJSON,
		pq.Array(entry.Tags),
		string(entry.Severity),
		entry.Source,
		entry.Version,
		entry.Checksum,
	)

	if err != nil {
		return fmt.Errorf("failed to store audit entry: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetAuditEntry retrieves a specific audit entry by ID
func (s *DatabaseAuditStore) GetAuditEntry(ctx context.Context, id string) (*interfaces.AuditEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
			   resource_type, resource_id, resource_name, result, error_code, error_message,
			   request_id, ip_address, user_agent, method, path, details, changes, tags,
			   severity, source, version, checksum
		FROM audit_entries
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, query, id)

	entry, err := s.scanAuditEntry(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, interfaces.ErrAuditNotFound
		}
		return nil, fmt.Errorf("failed to get audit entry: %w", err)
	}

	return entry, nil
}

// ListAuditEntries lists audit entries matching the filter with optimized database queries
func (s *DatabaseAuditStore) ListAuditEntries(ctx context.Context, filter *interfaces.AuditFilter) ([]*interfaces.AuditEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Build query with filters
	baseQuery := `
		SELECT id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
			   resource_type, resource_id, resource_name, result, error_code, error_message,
			   request_id, ip_address, user_agent, method, path, details, changes, tags,
			   severity, source, version, checksum
		FROM audit_entries
	`

	var args []interface{}
	whereClause, args := buildAuditFilterQuery(filter, args)
	orderClause := buildOrderByClause(filter)
	limitClause := buildLimitOffsetClause(filter)

	query := baseQuery + " " + whereClause + " " + orderClause + limitClause

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*interfaces.AuditEntry

	for rows.Next() {
		entry, err := s.scanAuditEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit entries: %w", err)
	}

	return entries, nil
}

// StoreAuditBatch stores multiple audit entries efficiently in a single transaction
func (s *DatabaseAuditStore) StoreAuditBatch(ctx context.Context, entries []*interfaces.AuditEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction for atomic batch operation
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Prepare statement for batch insert
	query := `
		INSERT INTO audit_entries (
			id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
			resource_type, resource_id, resource_name, result, error_code, error_message,
			request_id, ip_address, user_agent, method, path, details, changes, tags,
			severity, source, version, checksum
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26
		)
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	// Insert each entry
	for _, entry := range entries {
		if err := s.validateAuditEntry(entry); err != nil {
			return fmt.Errorf("failed to validate entry %s: %w", entry.ID, err)
		}

		// Set metadata
		if entry.ID == "" {
			entry.ID = s.generateAuditID(entry)
		}
		if entry.Timestamp.IsZero() {
			entry.Timestamp = time.Now()
		}
		if entry.Severity == "" {
			entry.Severity = interfaces.AuditSeverityLow
		}
		if entry.UserType == "" {
			entry.UserType = interfaces.AuditUserTypeHuman
		}
		if entry.Version == "" {
			entry.Version = "1.0"
		}

		// Calculate checksum
		entryJSON, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal audit entry: %w", err)
		}
		hasher := sha256.New()
		hasher.Write(entryJSON)
		entry.Checksum = hex.EncodeToString(hasher.Sum(nil))

		// Serialize complex fields
		detailsJSON, err := serializeMetadata(entry.Details)
		if err != nil {
			return fmt.Errorf("failed to serialize details: %w", err)
		}

		changesJSON, err := serializeAuditChanges(entry.Changes)
		if err != nil {
			return fmt.Errorf("failed to serialize changes: %w", err)
		}

		// Parse IP address
		var ipAddr net.IP
		if entry.IPAddress != "" {
			ipAddr = net.ParseIP(entry.IPAddress)
		}

		// Execute insert
		_, err = stmt.ExecContext(ctx,
			entry.ID,
			entry.TenantID,
			entry.Timestamp,
			string(entry.EventType),
			entry.Action,
			entry.UserID,
			string(entry.UserType),
			convertNullString(entry.SessionID),
			entry.ResourceType,
			entry.ResourceID,
			convertNullString(entry.ResourceName),
			string(entry.Result),
			convertNullString(entry.ErrorCode),
			convertNullString(entry.ErrorMessage),
			convertNullString(entry.RequestID),
			ipAddr,
			convertNullString(entry.UserAgent),
			convertNullString(entry.Method),
			convertNullString(entry.Path),
			detailsJSON,
			changesJSON,
			pq.Array(entry.Tags),
			string(entry.Severity),
			entry.Source,
			entry.Version,
			entry.Checksum,
		)

		if err != nil {
			return fmt.Errorf("failed to execute batch insert for entry %s: %w", entry.ID, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

// GetAuditsByUser gets audit entries for a specific user
func (s *DatabaseAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		UserIDs:   []string{userID},
		TimeRange: timeRange,
		SortBy:    "timestamp",
		Order:     "desc",
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetAuditsByResource gets audit entries for a specific resource
func (s *DatabaseAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		ResourceTypes: []string{resourceType},
		ResourceIDs:   []string{resourceID},
		TimeRange:     timeRange,
		SortBy:        "timestamp",
		Order:         "desc",
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetAuditsByAction gets audit entries for a specific action
func (s *DatabaseAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		Actions:   []string{action},
		TimeRange: timeRange,
		SortBy:    "timestamp",
		Order:     "desc",
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetFailedActions gets recent failed actions for security monitoring
func (s *DatabaseAuditStore) GetFailedActions(ctx context.Context, timeRange *interfaces.TimeRange, limit int) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		Results:   []interfaces.AuditResult{interfaces.AuditResultFailure, interfaces.AuditResultError, interfaces.AuditResultDenied},
		TimeRange: timeRange,
		Limit:     limit,
		SortBy:    "timestamp",
		Order:     "desc",
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetSuspiciousActivity gets suspicious activity for a tenant
func (s *DatabaseAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	filter := &interfaces.AuditFilter{
		TenantID:   tenantID,
		EventTypes: []interfaces.AuditEventType{interfaces.AuditEventSecurityEvent},
		Severities: []interfaces.AuditSeverity{interfaces.AuditSeverityHigh, interfaces.AuditSeverityCritical},
		TimeRange:  timeRange,
		SortBy:     "timestamp",
		Order:      "desc",
	}
	return s.ListAuditEntries(ctx, filter)
}

// GetAuditStats returns statistics about stored audit entries using optimized database queries
func (s *DatabaseAuditStore) GetAuditStats(ctx context.Context) (*interfaces.AuditStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := &interfaces.AuditStats{
		EntriesByTenant:   make(map[string]int64),
		EntriesByType:     make(map[string]int64),
		EntriesByResult:   make(map[string]int64),
		EntriesBySeverity: make(map[string]int64),
		LastUpdated:       time.Now(),
	}

	// Define time ranges for statistics
	now := time.Now()
	last24h := now.Add(-24 * time.Hour)
	last7d := now.Add(-7 * 24 * time.Hour)
	last30d := now.Add(-30 * 24 * time.Hour)

	// Get overall statistics with a single optimized query
	overallQuery := `
		SELECT 
			COUNT(*) as total_entries,
			MIN(timestamp) as oldest_entry,
			MAX(timestamp) as newest_entry,
			COUNT(CASE WHEN timestamp >= $1 THEN 1 END) as entries_last_24h,
			COUNT(CASE WHEN timestamp >= $2 THEN 1 END) as entries_last_7d,
			COUNT(CASE WHEN timestamp >= $3 THEN 1 END) as entries_last_30d,
			COUNT(CASE WHEN result IN ('failure', 'error', 'denied') AND timestamp >= $1 THEN 1 END) as failed_last_24h,
			COUNT(CASE WHEN event_type = 'security_event' THEN 1 END) as security_events,
			MAX(CASE WHEN event_type = 'security_event' THEN timestamp END) as last_security_incident
		FROM audit_entries
	`

	row := s.db.QueryRowContext(ctx, overallQuery, last24h, last7d, last30d)
	err := row.Scan(
		&stats.TotalEntries,
		&stats.OldestEntry,
		&stats.NewestEntry,
		&stats.EntriesLast24h,
		&stats.EntriesLast7d,
		&stats.EntriesLast30d,
		&stats.FailedActionsLast24h,
		&stats.SuspiciousActivityCount,
		&stats.LastSecurityIncident,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get overall statistics: %w", err)
	}

	// Use prepared statements for efficiency

	// Get statistics by tenant
	tenantQuery := `SELECT tenant_id, COUNT(*) FROM audit_entries GROUP BY tenant_id`
	if err := s.populateStatsMap(ctx, tenantQuery, stats.EntriesByTenant); err != nil {
		return nil, fmt.Errorf("failed to get tenant statistics: %w", err)
	}

	// Get statistics by event type
	typeQuery := `SELECT event_type, COUNT(*) FROM audit_entries GROUP BY event_type`
	if err := s.populateStatsMap(ctx, typeQuery, stats.EntriesByType); err != nil {
		return nil, fmt.Errorf("failed to get event type statistics: %w", err)
	}

	// Get statistics by result
	resultQuery := `SELECT result, COUNT(*) FROM audit_entries GROUP BY result`
	if err := s.populateStatsMap(ctx, resultQuery, stats.EntriesByResult); err != nil {
		return nil, fmt.Errorf("failed to get result statistics: %w", err)
	}

	// Get statistics by severity
	severityQuery := `SELECT severity, COUNT(*) FROM audit_entries GROUP BY severity`
	if err := s.populateStatsMap(ctx, severityQuery, stats.EntriesBySeverity); err != nil {
		return nil, fmt.Errorf("failed to get severity statistics: %w", err)
	}

	// Calculate total size (approximate)
	stats.TotalSize = stats.TotalEntries * 1024 // Approximate 1KB per entry
	if stats.TotalEntries > 0 {
		stats.AverageSize = stats.TotalSize / stats.TotalEntries
	}

	return stats, nil
}

// ArchiveAuditEntries archives old audit entries (for compliance, implement as needed)
func (s *DatabaseAuditStore) ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	// For PostgreSQL, this could move entries to an archive table or partition
	// For now, return 0 as no physical archival is implemented
	return 0, nil
}

// PurgeAuditEntries purges very old audit entries (use with extreme caution)
func (s *DatabaseAuditStore) PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// This is a destructive operation - should be used very carefully
	query := `DELETE FROM audit_entries WHERE timestamp < $1`

	result, err := s.db.ExecContext(ctx, query, beforeDate)
	if err != nil {
		return 0, fmt.Errorf("failed to purge audit entries: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	// Refresh materialized view after purge
	if err := s.schemas.RefreshAuditStatsView(ctx, s.db); err != nil {
		// Log error but don't fail the purge operation
		_ = err
	}

	return rowsAffected, nil
}

// Helper methods

// validateAuditEntry validates an audit entry
func (s *DatabaseAuditStore) validateAuditEntry(entry *interfaces.AuditEntry) error {
	if entry.TenantID == "" {
		return interfaces.ErrTenantIDRequired
	}
	if entry.UserID == "" {
		return interfaces.ErrUserIDRequired
	}
	if entry.Action == "" {
		return interfaces.ErrActionRequired
	}
	if entry.ResourceType == "" {
		return interfaces.ErrResourceTypeRequired
	}
	if entry.ResourceID == "" {
		return interfaces.ErrResourceIDRequired
	}
	if entry.Source == "" {
		return fmt.Errorf("audit entry source is required")
	}

	return nil
}

// generateAuditID generates a unique ID for an audit entry
func (s *DatabaseAuditStore) generateAuditID(entry *interfaces.AuditEntry) string {
	// Create a deterministic ID based on entry contents and timestamp
	data := fmt.Sprintf("%s-%s-%s-%s-%d",
		entry.TenantID, entry.UserID, entry.Action, entry.ResourceID, time.Now().UnixNano())

	hasher := sha256.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))[:16] // Use first 16 characters
}

// scanAuditEntry scans an audit entry from a database row
func (s *DatabaseAuditStore) scanAuditEntry(scanner interface {
	Scan(dest ...interface{}) error
}) (*interfaces.AuditEntry, error) {
	entry := &interfaces.AuditEntry{}
	var eventTypeStr, userTypeStr, resultStr, severityStr string
	var detailsJSON, changesJSON []byte
	var tags pq.StringArray
	var ipAddr net.IP
	var sessionID, resourceName, errorCode, errorMessage, requestID, userAgent, method, path sql.NullString

	err := scanner.Scan(
		&entry.ID,
		&entry.TenantID,
		&entry.Timestamp,
		&eventTypeStr,
		&entry.Action,
		&entry.UserID,
		&userTypeStr,
		&sessionID,
		&entry.ResourceType,
		&entry.ResourceID,
		&resourceName,
		&resultStr,
		&errorCode,
		&errorMessage,
		&requestID,
		&ipAddr,
		&userAgent,
		&method,
		&path,
		&detailsJSON,
		&changesJSON,
		&tags,
		&severityStr,
		&entry.Source,
		&entry.Version,
		&entry.Checksum,
	)

	if err != nil {
		return nil, err
	}

	// Convert string fields to typed enums
	entry.EventType = interfaces.AuditEventType(eventTypeStr)
	entry.UserType = interfaces.AuditUserType(userTypeStr)
	entry.Result = interfaces.AuditResult(resultStr)
	entry.Severity = interfaces.AuditSeverity(severityStr)
	entry.Tags = []string(tags)

	// Convert nullable strings
	if sessionID.Valid {
		entry.SessionID = sessionID.String
	}
	if resourceName.Valid {
		entry.ResourceName = resourceName.String
	}
	if errorCode.Valid {
		entry.ErrorCode = errorCode.String
	}
	if errorMessage.Valid {
		entry.ErrorMessage = errorMessage.String
	}
	if requestID.Valid {
		entry.RequestID = requestID.String
	}
	if userAgent.Valid {
		entry.UserAgent = userAgent.String
	}
	if method.Valid {
		entry.Method = method.String
	}
	if path.Valid {
		entry.Path = path.String
	}

	// Convert IP address
	if ipAddr != nil {
		entry.IPAddress = ipAddr.String()
	}

	// Deserialize JSON fields
	if len(detailsJSON) > 0 {
		details, err := deserializeMetadata(detailsJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize details: %w", err)
		}
		entry.Details = details
	}

	if len(changesJSON) > 0 {
		changes, err := deserializeAuditChanges(changesJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize changes: %w", err)
		}
		entry.Changes = changes
	}

	return entry, nil
}

// populateStatsMap populates a statistics map from a query result
func (s *DatabaseAuditStore) populateStatsMap(ctx context.Context, query string, statsMap map[string]int64) error {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return fmt.Errorf("failed to scan statistics: %w", err)
		}
		statsMap[key] = count
	}

	return rows.Err()
}

// RefreshStatsView refreshes the materialized view for better performance
func (s *DatabaseAuditStore) RefreshStatsView(ctx context.Context) error {
	return s.schemas.RefreshAuditStatsView(ctx, s.db)
}

// Close closes the database connection
func (s *DatabaseAuditStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
