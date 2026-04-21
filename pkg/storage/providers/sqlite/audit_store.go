// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements AuditStore using SQLite (append-only)
package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteAuditStore implements business.AuditStore using SQLite.
// Entries are append-only: StoreAuditEntry returns ErrImmutable if an entry with the
// same ID already exists. ArchiveAuditEntries and PurgeAuditEntries both return
// ErrImmutable to enforce the immutability contract at the SQLite tier.
type SQLiteAuditStore struct {
	db *sql.DB
}

// StoreAuditEntry appends a single audit entry. The entry's checksum is computed and
// set here if empty. Returns ErrImmutable if an entry with that ID already exists.
func (s *SQLiteAuditStore) StoreAuditEntry(ctx context.Context, entry *business.AuditEntry) error {
	if entry == nil {
		return fmt.Errorf("audit entry cannot be nil")
	}
	if entry.ID == "" {
		return fmt.Errorf("audit entry ID cannot be empty")
	}

	if entry.Checksum == "" {
		entry.Checksum = computeChecksum(entry)
	}

	details, err := marshalJSON(entry.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}
	changesJSON := "{}"
	if entry.Changes != nil {
		b, err := json.Marshal(entry.Changes)
		if err != nil {
			return fmt.Errorf("failed to marshal changes: %w", err)
		}
		changesJSON = string(b)
	}
	tags, err := marshalJSONSlice(entry.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_entries
			(id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
			 resource_type, resource_id, resource_name, result, error_code, error_message,
			 request_id, ip_address, user_agent, method, path,
			 details, changes, tags, severity, source, version, checksum,
			 sequence_number, previous_checksum)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		entry.ID,
		entry.TenantID,
		formatTime(entry.Timestamp),
		string(entry.EventType),
		entry.Action,
		entry.UserID,
		string(entry.UserType),
		entry.SessionID,
		entry.ResourceType,
		entry.ResourceID,
		entry.ResourceName,
		string(entry.Result),
		entry.ErrorCode,
		entry.ErrorMessage,
		entry.RequestID,
		entry.IPAddress,
		entry.UserAgent,
		entry.Method,
		entry.Path,
		details,
		changesJSON,
		tags,
		string(entry.Severity),
		entry.Source,
		entry.Version,
		entry.Checksum,
		entry.SequenceNumber,
		entry.PreviousChecksum,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return business.ErrImmutable
		}
		return fmt.Errorf("failed to store audit entry %s: %w", entry.ID, err)
	}
	return nil
}

// GetAuditEntry retrieves a single audit entry by ID.
func (s *SQLiteAuditStore) GetAuditEntry(ctx context.Context, id string) (*business.AuditEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
		       resource_type, resource_id, resource_name, result, error_code, error_message,
		       request_id, ip_address, user_agent, method, path,
		       details, changes, tags, severity, source, version, checksum,
		       sequence_number, previous_checksum
		FROM audit_entries WHERE id = ?`, id)
	return scanAuditEntry(row)
}

// GetLastAuditEntry returns the most recently written entry for tenantID by sequence_number,
// or nil if no entries exist for that tenant.
func (s *SQLiteAuditStore) GetLastAuditEntry(ctx context.Context, tenantID string) (*business.AuditEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
		       resource_type, resource_id, resource_name, result, error_code, error_message,
		       request_id, ip_address, user_agent, method, path,
		       details, changes, tags, severity, source, version, checksum,
		       sequence_number, previous_checksum
		FROM audit_entries
		WHERE tenant_id = ?
		ORDER BY sequence_number DESC
		LIMIT 1`, tenantID)
	entry, err := scanAuditEntry(row)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	return entry, nil
}

// ListAuditEntries returns audit entries matching the filter.
func (s *SQLiteAuditStore) ListAuditEntries(ctx context.Context, filter *business.AuditFilter) ([]*business.AuditEntry, error) {
	query, args := buildAuditQuery(filter)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*business.AuditEntry
	for rows.Next() {
		e, err := scanAuditRow(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// StoreAuditBatch appends multiple entries in a single transaction.
func (s *SQLiteAuditStore) StoreAuditBatch(ctx context.Context, entries []*business.AuditEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, e := range entries {
		if err := s.storeAuditEntryTx(ctx, tx, e); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetAuditsByUser returns audit entries for a specific user within an optional time range.
func (s *SQLiteAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		UserIDs:   []string{userID},
		TimeRange: timeRange,
	})
}

// GetAuditsByResource returns audit entries for a specific resource.
func (s *SQLiteAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		ResourceTypes: []string{resourceType},
		ResourceIDs:   []string{resourceID},
		TimeRange:     timeRange,
	})
}

// GetAuditsByAction returns audit entries for a specific action.
func (s *SQLiteAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		Actions:   []string{action},
		TimeRange: timeRange,
	})
}

// GetFailedActions returns the most recent failed audit entries.
func (s *SQLiteAuditStore) GetFailedActions(ctx context.Context, timeRange *business.TimeRange, limit int) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		Results:   []business.AuditResult{business.AuditResultFailure, business.AuditResultError, business.AuditResultDenied},
		TimeRange: timeRange,
		Limit:     limit,
	})
}

// GetSuspiciousActivity returns high/critical severity security events for a tenant.
func (s *SQLiteAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.ListAuditEntries(ctx, &business.AuditFilter{
		TenantID:   tenantID,
		EventTypes: []business.AuditEventType{business.AuditEventSecurityEvent},
		Severities: []business.AuditSeverity{business.AuditSeverityHigh, business.AuditSeverityCritical},
		TimeRange:  timeRange,
	})
}

// GetAuditStats returns aggregate statistics about stored audit entries.
func (s *SQLiteAuditStore) GetAuditStats(ctx context.Context) (*business.AuditStats, error) {
	stats := &business.AuditStats{
		EntriesByTenant:   make(map[string]int64),
		EntriesByType:     make(map[string]int64),
		EntriesByResult:   make(map[string]int64),
		EntriesBySeverity: make(map[string]int64),
		LastUpdated:       nowUTC(),
	}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_entries`).Scan(&stats.TotalEntries); err != nil {
		return nil, fmt.Errorf("failed to count audit entries: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT event_type, COUNT(*) FROM audit_entries GROUP BY event_type`)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate by event_type: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		var v int64
		if err := rows.Scan(&k, &v); err == nil {
			stats.EntriesByType[k] = v
		}
	}

	rows2, err := s.db.QueryContext(ctx, `SELECT result, COUNT(*) FROM audit_entries GROUP BY result`)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate by result: %w", err)
	}
	defer func() { _ = rows2.Close() }()
	for rows2.Next() {
		var k string
		var v int64
		if err := rows2.Scan(&k, &v); err == nil {
			stats.EntriesByResult[k] = v
		}
	}

	rows3, err := s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM audit_entries GROUP BY severity`)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate by severity: %w", err)
	}
	defer func() { _ = rows3.Close() }()
	for rows3.Next() {
		var k string
		var v int64
		if err := rows3.Scan(&k, &v); err == nil {
			stats.EntriesBySeverity[k] = v
		}
	}

	return stats, nil
}

// Close releases the underlying database connection.
func (s *SQLiteAuditStore) Close() error {
	return s.db.Close()
}

// ArchiveAuditEntries returns ErrImmutable — audit entries are immutable at this tier.
func (s *SQLiteAuditStore) ArchiveAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, business.ErrImmutable
}

// PurgeAuditEntries returns ErrImmutable — audit entries are immutable at this tier.
func (s *SQLiteAuditStore) PurgeAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, business.ErrImmutable
}

// ---- helpers ----------------------------------------------------------------

func (s *SQLiteAuditStore) storeAuditEntryTx(ctx context.Context, tx *sql.Tx, entry *business.AuditEntry) error {
	if entry.Checksum == "" {
		entry.Checksum = computeChecksum(entry)
	}
	details, err := marshalJSON(entry.Details)
	if err != nil {
		return fmt.Errorf("audit: failed to marshal details: %w", err)
	}
	changesJSON := "{}"
	if entry.Changes != nil {
		b, err := json.Marshal(entry.Changes)
		if err != nil {
			return fmt.Errorf("audit: failed to marshal changes: %w", err)
		}
		changesJSON = string(b)
	}
	tags, err := marshalJSONSlice(entry.Tags)
	if err != nil {
		return fmt.Errorf("audit: failed to marshal tags: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_entries
			(id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
			 resource_type, resource_id, resource_name, result, error_code, error_message,
			 request_id, ip_address, user_agent, method, path,
			 details, changes, tags, severity, source, version, checksum,
			 sequence_number, previous_checksum)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		entry.ID, entry.TenantID, formatTime(entry.Timestamp),
		string(entry.EventType), entry.Action, entry.UserID, string(entry.UserType), entry.SessionID,
		entry.ResourceType, entry.ResourceID, entry.ResourceName,
		string(entry.Result), entry.ErrorCode, entry.ErrorMessage,
		entry.RequestID, entry.IPAddress, entry.UserAgent, entry.Method, entry.Path,
		details, changesJSON, tags,
		string(entry.Severity), entry.Source, entry.Version, entry.Checksum,
		entry.SequenceNumber, entry.PreviousChecksum,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return business.ErrImmutable
		}
		return fmt.Errorf("failed to store audit entry %s in batch: %w", entry.ID, err)
	}
	return nil
}

func buildAuditQuery(filter *business.AuditFilter) (string, []interface{}) {
	base := `SELECT id, tenant_id, timestamp, event_type, action, user_id, user_type, session_id,
	                resource_type, resource_id, resource_name, result, error_code, error_message,
	                request_id, ip_address, user_agent, method, path,
	                details, changes, tags, severity, source, version, checksum,
	                sequence_number, previous_checksum
	         FROM audit_entries`

	if filter == nil {
		return base + ` ORDER BY timestamp DESC`, nil
	}

	var conditions []string
	var args []interface{}

	if filter.TenantID != "" {
		conditions = append(conditions, `tenant_id = ?`)
		args = append(args, filter.TenantID)
	}
	if len(filter.EventTypes) > 0 {
		ps := make([]string, len(filter.EventTypes))
		for i, et := range filter.EventTypes {
			ps[i] = "?"
			args = append(args, string(et))
		}
		conditions = append(conditions, `event_type IN (`+strings.Join(ps, ",")+`)`)
	}
	if len(filter.Actions) > 0 {
		ps := make([]string, len(filter.Actions))
		for i, a := range filter.Actions {
			ps[i] = "?"
			args = append(args, a)
		}
		conditions = append(conditions, `action IN (`+strings.Join(ps, ",")+`)`)
	}
	if len(filter.UserIDs) > 0 {
		ps := make([]string, len(filter.UserIDs))
		for i, u := range filter.UserIDs {
			ps[i] = "?"
			args = append(args, u)
		}
		conditions = append(conditions, `user_id IN (`+strings.Join(ps, ",")+`)`)
	}
	if len(filter.Results) > 0 {
		ps := make([]string, len(filter.Results))
		for i, r := range filter.Results {
			ps[i] = "?"
			args = append(args, string(r))
		}
		conditions = append(conditions, `result IN (`+strings.Join(ps, ",")+`)`)
	}
	if len(filter.Severities) > 0 {
		ps := make([]string, len(filter.Severities))
		for i, sv := range filter.Severities {
			ps[i] = "?"
			args = append(args, string(sv))
		}
		conditions = append(conditions, `severity IN (`+strings.Join(ps, ",")+`)`)
	}
	if len(filter.ResourceTypes) > 0 {
		ps := make([]string, len(filter.ResourceTypes))
		for i, rt := range filter.ResourceTypes {
			ps[i] = "?"
			args = append(args, rt)
		}
		conditions = append(conditions, `resource_type IN (`+strings.Join(ps, ",")+`)`)
	}
	if len(filter.ResourceIDs) > 0 {
		ps := make([]string, len(filter.ResourceIDs))
		for i, ri := range filter.ResourceIDs {
			ps[i] = "?"
			args = append(args, ri)
		}
		conditions = append(conditions, `resource_id IN (`+strings.Join(ps, ",")+`)`)
	}
	if filter.TimeRange != nil {
		if filter.TimeRange.Start != nil {
			conditions = append(conditions, `timestamp >= ?`)
			args = append(args, formatTime(*filter.TimeRange.Start))
		}
		if filter.TimeRange.End != nil {
			conditions = append(conditions, `timestamp <= ?`)
			args = append(args, formatTime(*filter.TimeRange.End))
		}
	}

	query := base
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}

	sortCol := "timestamp"
	switch filter.SortBy {
	case "severity":
		sortCol = "severity"
	case "user_id":
		sortCol = "user_id"
	}
	order := "DESC"
	if filter.Order == "asc" {
		order = "ASC"
	}
	query += fmt.Sprintf(` ORDER BY %s %s`, sortCol, order)

	if filter.Limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(` OFFSET %d`, filter.Offset)
	}

	return query, args
}

func scanAuditEntry(row *sql.Row) (*business.AuditEntry, error) {
	e := &business.AuditEntry{}
	var tsStr, detailsStr, changesStr, tagsStr string

	err := row.Scan(
		&e.ID, &e.TenantID, &tsStr,
		&e.EventType, &e.Action, &e.UserID, &e.UserType, &e.SessionID,
		&e.ResourceType, &e.ResourceID, &e.ResourceName,
		&e.Result, &e.ErrorCode, &e.ErrorMessage,
		&e.RequestID, &e.IPAddress, &e.UserAgent, &e.Method, &e.Path,
		&detailsStr, &changesStr, &tagsStr,
		&e.Severity, &e.Source, &e.Version, &e.Checksum,
		&e.SequenceNumber, &e.PreviousChecksum,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("audit entry not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan audit entry: %w", err)
	}
	return populateAuditEntry(e, tsStr, detailsStr, changesStr, tagsStr)
}

func scanAuditRow(rows *sql.Rows) (*business.AuditEntry, error) {
	e := &business.AuditEntry{}
	var tsStr, detailsStr, changesStr, tagsStr string

	if err := rows.Scan(
		&e.ID, &e.TenantID, &tsStr,
		&e.EventType, &e.Action, &e.UserID, &e.UserType, &e.SessionID,
		&e.ResourceType, &e.ResourceID, &e.ResourceName,
		&e.Result, &e.ErrorCode, &e.ErrorMessage,
		&e.RequestID, &e.IPAddress, &e.UserAgent, &e.Method, &e.Path,
		&detailsStr, &changesStr, &tagsStr,
		&e.Severity, &e.Source, &e.Version, &e.Checksum,
		&e.SequenceNumber, &e.PreviousChecksum,
	); err != nil {
		return nil, fmt.Errorf("failed to scan audit row: %w", err)
	}
	return populateAuditEntry(e, tsStr, detailsStr, changesStr, tagsStr)
}

func populateAuditEntry(e *business.AuditEntry, tsStr, detailsStr, changesStr, tagsStr string) (*business.AuditEntry, error) {
	e.Timestamp = parseTime(tsStr)

	details, err := unmarshalJSONMap(detailsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit entry details: %w", err)
	}
	e.Details = details

	if changesStr != "" && changesStr != "{}" {
		var changes business.AuditChanges
		if err := json.Unmarshal([]byte(changesStr), &changes); err == nil {
			e.Changes = &changes
		}
	}

	tags, err := unmarshalJSONSlice(tagsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit entry tags: %w", err)
	}
	e.Tags = tags

	return e, nil
}

func computeChecksum(entry *business.AuditEntry) string {
	h := sha256.New()
	// sha256.Hash.Write never returns an error; the return values are intentionally ignored.
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s",
		entry.ID, entry.TenantID, entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.Action, entry.UserID, entry.ResourceID)
	return hex.EncodeToString(h.Sum(nil))
}

// ensure SQLiteAuditStore satisfies the interface at compile time
var _ business.AuditStore = (*SQLiteAuditStore)(nil)
