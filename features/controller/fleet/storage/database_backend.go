// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package storage provides PostgreSQL-backed fleet query operations for DNA records.

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

// listAllDeviceIDs returns the distinct device IDs stored in the PostgreSQL dna_history table.
// Used during controller startup to warm the in-memory steward registry.
func (b *DatabaseBackend) listAllDeviceIDs(ctx context.Context) ([]string, error) {
	rows, err := b.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM dna_history`)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list device IDs: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Close() error is non-actionable after row iteration completes

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("database: failed to scan device ID: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetLatestByDeviceID retrieves the most recent DNA record for a device, reading
// directly from the PostgreSQL store rather than the in-memory index. This is the
// path LoadFromStorage uses to warm the steward registry on startup.
func (b *DatabaseBackend) GetLatestByDeviceID(ctx context.Context, deviceID string) (*DNARecord, error) {
	row := b.db.QueryRowContext(ctx, `
		SELECT device_id, tenant_id, os, architecture, hostname, status,
		       version, timestamp, dna_json, content_hash,
		       original_size, compressed_size, compression_ratio, shard_id
		FROM dna_history
		WHERE device_id = $1
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
			return nil, fmt.Errorf("database: no DNA record found for device %s", deviceID)
		}
		return nil, fmt.Errorf("database: failed to retrieve latest DNA for device %s: %w", deviceID, err)
	}
	rec.StoredAt = storedAt

	var dna commonpb.DNA
	if err := json.Unmarshal([]byte(dnaJSON), &dna); err != nil {
		return nil, fmt.Errorf("database: failed to unmarshal DNA JSON for device %s: %w", deviceID, err)
	}
	rec.DNA = &dna

	return &rec, nil
}

// setDeviceTenant upserts (device_id, tenant_id) into the device_tenant table.
func (b *DatabaseBackend) setDeviceTenant(ctx context.Context, deviceID, tenantID string) error {
	_, err := b.db.ExecContext(ctx,
		`INSERT INTO device_tenant (device_id, tenant_id) VALUES ($1, $2)
		 ON CONFLICT(device_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id`,
		deviceID, tenantID)
	if err != nil {
		return fmt.Errorf("database: failed to set device tenant for %s: %w", deviceID, err)
	}
	return nil
}

// getDeviceTenant retrieves the tenant for a device from device_tenant.
func (b *DatabaseBackend) getDeviceTenant(ctx context.Context, deviceID string) (tenantID string, found bool, err error) {
	err = b.db.QueryRowContext(ctx,
		`SELECT tenant_id FROM device_tenant WHERE device_id = $1`, deviceID).Scan(&tenantID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("database: failed to get device tenant for %s: %w", deviceID, err)
	}
	return tenantID, true, nil
}

// listDeviceTenants returns all (device_id, tenant_id) pairs from device_tenant.
func (b *DatabaseBackend) listDeviceTenants(ctx context.Context) (map[string]string, error) {
	rows, err := b.db.QueryContext(ctx, `SELECT device_id, tenant_id FROM device_tenant`)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list device tenants: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Close() error is non-actionable after row iteration completes

	result := make(map[string]string)
	for rows.Next() {
		var did, tid string
		if err := rows.Scan(&did, &tid); err != nil {
			return nil, fmt.Errorf("database: failed to scan device tenant: %w", err)
		}
		result[did] = tid
	}
	return result, rows.Err()
}

// ping issues a trivial SELECT to confirm the PostgreSQL connection is live.
func (b *DatabaseBackend) ping(ctx context.Context) error {
	var one int
	if err := b.db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return fmt.Errorf("database: ping failed: %w", err)
	}
	return nil
}

// QueryFleet executes a fleet query against the PostgreSQL backend.
// Each non-empty filter field maps to an indexed column so the query
// remains efficient at fleet scale.
func (b *DatabaseBackend) QueryFleet(ctx context.Context, filter *FleetFilter) (*FleetQueryResult, error) {
	if filter == nil {
		filter = &FleetFilter{}
	}

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

	var conditions []string
	var args []interface{}
	argIdx := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("h.tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID)
		argIdx++
	}
	if filter.OS != "" {
		conditions = append(conditions, fmt.Sprintf("h.os = $%d", argIdx))
		args = append(args, filter.OS)
		argIdx++
	}
	if filter.Architecture != "" {
		conditions = append(conditions, fmt.Sprintf("h.architecture = $%d", argIdx))
		args = append(args, filter.Architecture)
		argIdx++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("h.status = $%d", argIdx))
		args = append(args, filter.Status)
		argIdx++
	}
	if len(filter.DeviceIDs) > 0 {
		placeholders := make([]string, len(filter.DeviceIDs))
		for i, id := range filter.DeviceIDs {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, id)
			argIdx++
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
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	var totalCount int64
	if err := b.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&totalCount); err != nil {
		return nil, fmt.Errorf("database: failed to count fleet query results: %w", err)
	}

	// Apply pagination using integer formatting (type-safe; prevents injection).
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("database: failed to execute fleet query: %w", err)
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
			return nil, fmt.Errorf("database: failed to scan fleet record: %w", err)
		}
		rec.StoredAt = storedAt

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
		return nil, fmt.Errorf("database: fleet query row iteration error: %w", err)
	}

	return &FleetQueryResult{
		Records:    records,
		TotalCount: totalCount,
		Filter:     filter,
	}, nil
}
