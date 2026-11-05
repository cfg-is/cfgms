// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlstore

import (
	"context"
	"database/sql"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// StatsErrors holds the provider-specific error text for each GetStats step. Each is
// prefixed to the wrapped driver error as "<text>: <err>".
type StatsErrors struct {
	Total    string
	ByType   string
	ByStatus string
}

// SessionStats computes aggregate statistics over a sessions table that has session_type
// and status columns. The SQL carries no placeholders, so it is identical in every dialect.
func SessionStats(ctx context.Context, db *sql.DB, errs StatsErrors) (*business.RuntimeStoreStats, error) {
	stats := &business.RuntimeStoreStats{
		SessionsByType:   make(map[string]int64),
		SessionsByStatus: make(map[string]int64),
	}

	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&stats.TotalSessions); err != nil {
		return nil, fmt.Errorf("%s: %w", errs.Total, err)
	}
	if err := countGroups(ctx, db, `SELECT session_type, COUNT(*) FROM sessions GROUP BY session_type`,
		stats.SessionsByType, errs.ByType); err != nil {
		return nil, err
	}
	if err := countGroups(ctx, db, `SELECT status, COUNT(*) FROM sessions GROUP BY status`,
		stats.SessionsByStatus, errs.ByStatus); err != nil {
		return nil, err
	}

	if v, ok := stats.SessionsByStatus[string(business.SessionStatusActive)]; ok {
		stats.ActiveSessions = v
	}
	return stats, nil
}

// countGroups fills dst from a two-column (key, count) query. A row that fails to scan is
// skipped, matching the behaviour both providers had before the code was shared.
func countGroups(ctx context.Context, db *sql.DB, query string, dst map[string]int64, errText string) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("%s: %w", errText, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		var v int64
		if err := rows.Scan(&k, &v); err == nil {
			dst[k] = v
		}
	}
	return nil
}
