// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package timescale - Query functionality for TimescaleDB logging provider
package timescale

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// QueryTimeRange queries log entries within a time range using optimized TimescaleDB queries
func (p *TimescaleProvider) QueryTimeRange(ctx context.Context, query interfaces.TimeRangeQuery) ([]interfaces.LogEntry, error) {
	if !p.initialized {
		return nil, fmt.Errorf("provider not initialized")
	}

	start := time.Now()
	defer func() {
		p.mutex.Lock()
		p.stats.QueryLatencyMs = float64(time.Since(start).Milliseconds())
		p.mutex.Unlock()
	}()

	// Build SQL query
	sqlQuery, args := p.buildTimeRangeQuery(query)

	p.mutex.RLock()
	db := p.db
	p.mutex.RUnlock()

	// Execute query with timeout
	queryCtx, cancel := context.WithTimeout(ctx, p.config.QueryTimeout)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute time range query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Parse results
	var results []interfaces.LogEntry
	for rows.Next() {
		entry, err := p.scanLogEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan log entry: %w", err)
		}
		results = append(results, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading query results: %w", err)
	}

	// Apply post-processing
	results = p.applyPostProcessing(results, query)

	return results, nil
}

// QueryCount returns count of log entries matching criteria
func (p *TimescaleProvider) QueryCount(ctx context.Context, query interfaces.CountQuery) (int64, error) {
	if !p.initialized {
		return 0, fmt.Errorf("provider not initialized")
	}

	// Build count query
	sqlQuery, args := p.buildCountQuery(query)

	p.mutex.RLock()
	db := p.db
	p.mutex.RUnlock()

	// Execute query with timeout
	queryCtx, cancel := context.WithTimeout(ctx, p.config.QueryTimeout)
	defer cancel()

	var count int64
	err := db.QueryRowContext(queryCtx, sqlQuery, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	return count, nil
}

// QueryLevels queries log entries by log levels
func (p *TimescaleProvider) QueryLevels(ctx context.Context, query interfaces.LevelQuery) ([]interfaces.LogEntry, error) {
	// Convert level query to time range query
	timeRangeQuery := query.TimeRangeQuery

	// Add level filter
	if timeRangeQuery.Filters == nil {
		timeRangeQuery.Filters = make(map[string]interface{})
	}

	if len(query.Levels) > 0 {
		timeRangeQuery.Filters["level"] = query.Levels
	}

	return p.QueryTimeRange(ctx, timeRangeQuery)
}

// ApplyRetentionPolicy removes old log entries based on retention policy
func (p *TimescaleProvider) ApplyRetentionPolicy(ctx context.Context, policy interfaces.RetentionPolicy) error {
	if !p.initialized {
		return fmt.Errorf("provider not initialized")
	}

	// TimescaleDB handles retention automatically via retention policies
	// But we can also manually delete for immediate cleanup
	cutoffTime := time.Now().AddDate(0, 0, -policy.RetentionDays)

	// Build secure delete query
	deleteQuery, err := p.buildSafeQuery(`
		DELETE FROM %s.%s 
		WHERE timestamp < $1
	`)
	if err != nil {
		return fmt.Errorf("failed to build secure delete query: %w", err)
	}

	p.mutex.RLock()
	db := p.db
	p.mutex.RUnlock()

	result, err := db.ExecContext(ctx, deleteQuery, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to apply retention policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	fmt.Printf("Applied retention policy: removed %d old log entries\n", rowsAffected)

	return nil
}

// GetStats returns operational statistics
func (p *TimescaleProvider) GetStats(ctx context.Context) (interfaces.ProviderStats, error) {
	if !p.initialized {
		return interfaces.ProviderStats{}, fmt.Errorf("provider not initialized")
	}

	p.mutex.RLock()
	stats := p.stats
	p.mutex.RUnlock()

	// Query database for additional statistics
	if dbStats, err := p.queryDatabaseStats(ctx); err == nil {
		stats.StorageSize = dbStats.StorageSize
		stats.TotalEntries = dbStats.TotalEntries
		stats.OldestEntry = dbStats.OldestEntry
		stats.LatestEntry = dbStats.LatestEntry
	}

	return stats, nil
}

// Flush is a no-op for TimescaleDB provider (writes are immediate)
func (p *TimescaleProvider) Flush(ctx context.Context) error {
	// TimescaleDB writes are committed immediately, no buffering
	return nil
}

// buildTimeRangeQuery constructs an SQL query for time range queries
func (p *TimescaleProvider) buildTimeRangeQuery(query interfaces.TimeRangeQuery) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	// M-INPUT-3: Schema and table names already validated during initialization
	// This provides defense-in-depth against SQL injection even though identifiers come from config
	tableName := fmt.Sprintf("%s.%s", p.config.SchemaName, p.config.TableName)

	// Base SELECT
	sqlQuery := fmt.Sprintf(`
		SELECT 
			timestamp, level, message, service_name, component,
			tenant_id, session_id, correlation_id, trace_id, span_id,
			fields, created_at
		FROM %s
	`, tableName)

	// Time range conditions
	if !query.StartTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIndex))
		args = append(args, query.StartTime)
		argIndex++
	}

	if !query.EndTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIndex))
		args = append(args, query.EndTime)
		argIndex++
	}

	// Apply filters
	for key, value := range query.Filters {
		condition, arg := p.buildFilterCondition(key, value, argIndex)
		if condition != "" {
			conditions = append(conditions, condition)
			if arg != nil {
				args = append(args, arg)
				argIndex++
			}
		}
	}

	// Add WHERE clause
	if len(conditions) > 0 {
		sqlQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	// Add ORDER BY
	orderBy := "timestamp"
	if query.OrderBy != "" && query.OrderBy != "timestamp" {
		orderBy = query.OrderBy
	}

	direction := "ASC"
	if query.SortDesc {
		direction = "DESC"
	}

	sqlQuery += fmt.Sprintf(" ORDER BY %s %s", orderBy, direction)

	// Add LIMIT
	if query.Limit > 0 {
		sqlQuery += fmt.Sprintf(" LIMIT %d", query.Limit)
	}

	return sqlQuery, args
}

// buildCountQuery constructs an SQL count query
func (p *TimescaleProvider) buildCountQuery(query interfaces.CountQuery) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	tableName := fmt.Sprintf("%s.%s", p.config.SchemaName, p.config.TableName)

	// Base SELECT COUNT
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)

	// Time range conditions
	if !query.StartTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIndex))
		args = append(args, query.StartTime)
		argIndex++
	}

	if !query.EndTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIndex))
		args = append(args, query.EndTime)
		argIndex++
	}

	// Apply filters
	for key, value := range query.Filters {
		condition, arg := p.buildFilterCondition(key, value, argIndex)
		if condition != "" {
			conditions = append(conditions, condition)
			if arg != nil {
				args = append(args, arg)
				argIndex++
			}
		}
	}

	// Add WHERE clause
	if len(conditions) > 0 {
		sqlQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	return sqlQuery, args
}

// buildFilterCondition constructs a SQL condition for a filter
func (p *TimescaleProvider) buildFilterCondition(key string, value interface{}, argIndex int) (string, interface{}) {
	switch key {
	case "level":
		return p.buildLevelCondition(value, argIndex)
	case "service_name", "component", "tenant_id", "session_id", "correlation_id", "trace_id", "span_id":
		return p.buildStringCondition(key, value, argIndex)
	case "message":
		return p.buildMessageCondition(value, argIndex)
	default:
		// Handle JSONB field queries
		return p.buildJSONBCondition(key, value, argIndex)
	}
}

// buildLevelCondition builds condition for log level filtering
func (p *TimescaleProvider) buildLevelCondition(value interface{}, argIndex int) (string, interface{}) {
	switch v := value.(type) {
	case string:
		return fmt.Sprintf("level = $%d", argIndex), v
	case []string:
		if len(v) == 0 {
			return "", nil
		}
		// Use PostgreSQL ANY with array parameter for cleaner SQL
		return fmt.Sprintf("level = ANY($%d)", argIndex), pq.Array(v)
	case []interface{}:
		if len(v) == 0 {
			return "", nil
		}
		// Convert to string slice
		stringValues := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				stringValues = append(stringValues, str)
			}
		}
		if len(stringValues) == 0 {
			return "", nil
		}
		// Use PostgreSQL ANY with array parameter for cleaner SQL
		return fmt.Sprintf("level = ANY($%d)", argIndex), pq.Array(stringValues)
	}
	return "", nil
}

// buildStringCondition builds condition for string field filtering
func (p *TimescaleProvider) buildStringCondition(field string, value interface{}, argIndex int) (string, interface{}) {
	if str, ok := value.(string); ok {
		return fmt.Sprintf("%s = $%d", field, argIndex), str
	}
	return "", nil
}

// buildMessageCondition builds condition for message text search
func (p *TimescaleProvider) buildMessageCondition(value interface{}, argIndex int) (string, interface{}) {
	if str, ok := value.(string); ok {
		// Use PostgreSQL full-text search
		return fmt.Sprintf("to_tsvector('english', message) @@ plainto_tsquery('english', $%d)", argIndex), str
	}
	return "", nil
}

// buildJSONBCondition builds condition for JSONB field queries
func (p *TimescaleProvider) buildJSONBCondition(key string, value interface{}, argIndex int) (string, interface{}) {
	// Use JSONB containment operator
	filter := map[string]interface{}{key: value}
	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("fields @> $%d::jsonb", argIndex), string(filterJSON)
}

// scanLogEntry scans a SQL row into a LogEntry struct
func (p *TimescaleProvider) scanLogEntry(rows *sql.Rows) (interfaces.LogEntry, error) {
	var entry interfaces.LogEntry
	var fieldsJSON string
	var createdAt time.Time // Temporary field for database timestamp

	err := rows.Scan(
		&entry.Timestamp,
		&entry.Level,
		&entry.Message,
		&entry.ServiceName,
		&entry.Component,
		&entry.TenantID,
		&entry.SessionID,
		&entry.CorrelationID,
		&entry.TraceID,
		&entry.SpanID,
		&fieldsJSON,
		&createdAt, // Scan created_at but don't store in entry
	)

	if err != nil {
		return entry, err
	}

	// Parse JSONB fields
	if fieldsJSON != "" && fieldsJSON != "{}" {
		if err := json.Unmarshal([]byte(fieldsJSON), &entry.Fields); err != nil {
			// If JSON parsing fails, create empty map
			entry.Fields = make(map[string]interface{})
		}
	} else {
		entry.Fields = make(map[string]interface{})
	}

	return entry, nil
}

// applyPostProcessing applies client-side filtering and sorting
func (p *TimescaleProvider) applyPostProcessing(results []interfaces.LogEntry, query interfaces.TimeRangeQuery) []interfaces.LogEntry {
	// Additional client-side sorting if needed
	if query.OrderBy != "" && query.OrderBy != "timestamp" {
		sort.Slice(results, func(i, j int) bool {
			// Custom sorting logic for non-timestamp fields
			switch query.OrderBy {
			case "level":
				levelOrder := map[string]int{
					"DEBUG": 1, "INFO": 2, "WARN": 3, "ERROR": 4, "FATAL": 5,
				}
				if query.SortDesc {
					return levelOrder[results[i].Level] > levelOrder[results[j].Level]
				}
				return levelOrder[results[i].Level] < levelOrder[results[j].Level]
			default:
				// Default to timestamp sorting
				if query.SortDesc {
					return results[i].Timestamp.After(results[j].Timestamp)
				}
				return results[i].Timestamp.Before(results[j].Timestamp)
			}
		})
	}

	return results
}

// queryDatabaseStats queries the database for storage statistics
func (p *TimescaleProvider) queryDatabaseStats(ctx context.Context) (*interfaces.ProviderStats, error) {
	stats := &interfaces.ProviderStats{}

	// Build secure table name and query
	tableName, err := p.buildSafeQuery("%s.%s")
	if err != nil {
		return nil, fmt.Errorf("failed to build secure table name: %w", err)
	}

	// Query basic statistics
	// #nosec G201 - tableName is validated via buildSafeQuery above
	statsQuery := fmt.Sprintf(`
		SELECT 
			COUNT(*) as total_entries,
			MIN(timestamp) as oldest_entry,
			MAX(timestamp) as latest_entry,
			pg_total_relation_size('%s') as storage_size
		FROM %s
	`, tableName, tableName)

	var totalEntries int64
	var oldestEntry, latestEntry sql.NullTime
	var storageSize int64

	err = p.db.QueryRowContext(ctx, statsQuery).Scan(
		&totalEntries,
		&oldestEntry,
		&latestEntry,
		&storageSize,
	)

	if err != nil {
		return nil, err
	}

	stats.TotalEntries = totalEntries
	stats.StorageSize = storageSize

	if oldestEntry.Valid {
		stats.OldestEntry = oldestEntry.Time
	}
	if latestEntry.Valid {
		stats.LatestEntry = latestEntry.Time
	}

	return stats, nil
}
