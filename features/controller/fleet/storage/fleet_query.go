// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package storage provides fleet query capabilities for steward DNA records.
//
// FleetQuery enables the controller to search stewards persisted in the DNA
// storage backend. Filter fields map directly to indexed SQL columns so large
// fleets can be searched efficiently without full-table scans.

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// FleetFilter defines the filter criteria for querying steward DNA records.
// All non-empty fields are ANDed together in the SQL WHERE clause.
// Each field maps to a dedicated indexed column in dna_history.
type FleetFilter struct {
	// TenantID restricts results to a specific tenant (maps to idx_dna_tenant).
	TenantID string
	// OS restricts results to a specific operating system (maps to idx_dna_os).
	OS string
	// Architecture restricts results by CPU architecture (maps to idx_dna_architecture).
	Architecture string
	// Status restricts results by steward status, e.g. "online" (maps to idx_dna_status).
	Status string
	// DeviceIDs restricts results to specific device IDs.
	DeviceIDs []string
	// Limit caps the number of results returned (0 = no limit).
	Limit int
	// Offset skips the first N results for pagination.
	Offset int
}

// FleetRecord is a lightweight steward record returned by fleet queries.
// It contains the indexed fleet fields plus the latest DNA snapshot.
type FleetRecord struct {
	DeviceID     string        `json:"device_id"`
	TenantID     string        `json:"tenant_id"`
	OS           string        `json:"os"`
	Architecture string        `json:"architecture"`
	Hostname     string        `json:"hostname"`
	Status       string        `json:"status"`
	Version      int64         `json:"version"`
	StoredAt     time.Time     `json:"stored_at"`
	DNA          *commonpb.DNA `json:"dna,omitempty"`
}

// FleetQueryResult holds the result of a fleet query.
type FleetQueryResult struct {
	Records    []*FleetRecord `json:"records"`
	TotalCount int64          `json:"total_count"`
	Filter     *FleetFilter   `json:"filter"`
}

// QueryFleet queries the storage backend for steward DNA records matching the
// given filter. Each non-empty filter field maps to an indexed column, so the
// query is efficient even for fleets with tens of thousands of devices.
//
// Only the latest DNA record per device is returned.
func (m *Manager) QueryFleet(ctx context.Context, filter *FleetFilter) (*FleetQueryResult, error) {
	if filter == nil {
		filter = &FleetFilter{}
	}

	sqliteBackend, ok := m.storage.(*SQLiteBackend)
	if !ok {
		return nil, fmt.Errorf("fleet query requires SQLite backend")
	}

	return sqliteBackend.QueryFleet(ctx, filter)
}

// QueryFleet executes the fleet query against the SQLite backend.
func (b *SQLiteBackend) QueryFleet(ctx context.Context, filter *FleetFilter) (*FleetQueryResult, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	// Build WHERE clause from filter fields (parameterized to prevent SQL injection)
	var conditions []string
	var args []interface{}

	// Subquery: keep only the latest version per device
	baseQuery := `
		WITH latest AS (
			SELECT device_id, MAX(version) AS max_version
			FROM dna_history
			GROUP BY device_id
		)
		SELECT h.device_id, h.tenant_id, h.os, h.architecture, h.hostname,
		       h.status, h.version, h.timestamp, h.dna_json
		FROM dna_history h
		INNER JOIN latest l ON h.device_id = l.device_id AND h.version = l.max_version
	`

	if filter.TenantID != "" {
		conditions = append(conditions, "h.tenant_id = ?")
		args = append(args, filter.TenantID)
	}
	if filter.OS != "" {
		conditions = append(conditions, "h.os = ?")
		args = append(args, filter.OS)
	}
	if filter.Architecture != "" {
		conditions = append(conditions, "h.architecture = ?")
		args = append(args, filter.Architecture)
	}
	if filter.Status != "" {
		conditions = append(conditions, "h.status = ?")
		args = append(args, filter.Status)
	}
	if len(filter.DeviceIDs) > 0 {
		placeholders := make([]string, len(filter.DeviceIDs))
		for i, id := range filter.DeviceIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		conditions = append(conditions, "h.device_id IN ("+strings.Join(placeholders, ",")+")")
	}

	query := baseQuery
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY h.device_id"

	// Count query for pagination metadata
	countQuery := `SELECT COUNT(*) FROM (` + query + `) sub`
	var totalCount int64
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := b.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&totalCount); err != nil {
		return nil, fmt.Errorf("failed to count fleet query results: %w", err)
	}

	// Apply pagination. LIMIT/OFFSET are formatted as integers (%d) which is
	// type-safe — Go's type system prevents string injection through int values.
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute fleet query: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Close() error is non-actionable after row iteration completes

	var records []*FleetRecord
	for rows.Next() {
		var rec FleetRecord
		var storedAt time.Time
		var dnaJSON string

		if err := rows.Scan(
			&rec.DeviceID,
			&rec.TenantID,
			&rec.OS,
			&rec.Architecture,
			&rec.Hostname,
			&rec.Status,
			&rec.Version,
			&storedAt,
			&dnaJSON,
		); err != nil {
			return nil, fmt.Errorf("failed to scan fleet record: %w", err)
		}
		rec.StoredAt = storedAt

		// Deserialize DNA from JSON
		var dna commonpb.DNA
		if err := json.Unmarshal([]byte(dnaJSON), &dna); err != nil {
			b.logger.Warn("Failed to unmarshal DNA JSON for fleet record",
				"device_id", rec.DeviceID, "error", err)
		} else {
			rec.DNA = &dna
		}

		records = append(records, &rec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("fleet query row iteration error: %w", err)
	}

	return &FleetQueryResult{
		Records:    records,
		TotalCount: totalCount,
		Filter:     filter,
	}, nil
}

// ListAllDeviceIDs returns the device IDs of all stewards in storage.
// Used during controller startup to warm the in-memory registry.
func (m *Manager) ListAllDeviceIDs(ctx context.Context) ([]string, error) {
	sqliteBackend, ok := m.storage.(*SQLiteBackend)
	if !ok {
		return nil, fmt.Errorf("ListAllDeviceIDs requires SQLite backend")
	}
	return sqliteBackend.listAllDeviceIDs(ctx)
}

// listAllDeviceIDs queries the distinct device IDs stored in dna_history.
func (b *SQLiteBackend) listAllDeviceIDs(ctx context.Context) ([]string, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	rows, err := b.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM dna_history`)
	if err != nil {
		return nil, fmt.Errorf("failed to list device IDs: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Close() error is non-actionable after row iteration completes

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan device ID: %w", err)
		}
		ids = append(ids, id)
	}

	return ids, rows.Err()
}

// GetLatestByDeviceID retrieves the most recent DNA record for a device using
// SQL rather than the indexer, suitable for startup warm-loading.
func (b *SQLiteBackend) GetLatestByDeviceID(ctx context.Context, deviceID string) (*DNARecord, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	row := b.db.QueryRowContext(ctx, `
		SELECT device_id, tenant_id, os, architecture, hostname, status,
		       version, timestamp, dna_json, content_hash,
		       original_size, compressed_size, compression_ratio, shard_id
		FROM dna_history
		WHERE device_id = ?
		ORDER BY version DESC
		LIMIT 1
	`, deviceID)

	var rec DNARecord
	var storedAt time.Time
	var dnaJSON string
	if err := row.Scan(
		&rec.DeviceID,
		&rec.TenantID,
		new(string), // os — available in DNA.Attributes
		new(string), // architecture
		new(string), // hostname
		&rec.Status,
		&rec.Version,
		&storedAt,
		&dnaJSON,
		&rec.ContentHash,
		&rec.OriginalSize,
		&rec.CompressedSize,
		&rec.CompressionRatio,
		&rec.ShardID,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no DNA record found for device %s", deviceID)
		}
		return nil, fmt.Errorf("failed to retrieve latest DNA for device %s: %w", deviceID, err)
	}
	rec.StoredAt = storedAt

	var dna commonpb.DNA
	if err := json.Unmarshal([]byte(dnaJSON), &dna); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNA JSON for device %s: %w", deviceID, err)
	}
	rec.DNA = &dna

	return &rec, nil
}
