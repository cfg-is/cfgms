// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
)

const (
	defaultHistoryDays   = 90
	defaultTombstoneDays = 97 // history + 7 days grace for tombstones
)

// RunRetentionGC executes one retention GC sweep against the observation log
// and derived tables. It enforces the never-prune-current invariant across
// every projection table (entity, edge, drift, claim-scope) and applies
// per-tenant-subtree policy overrides from eg_retention_policy (most-specific
// prefix wins per ADR-023 §7).
//
// Sweep order:
//  1. Tombstone removal: fully delete retracted subjects whose absence row
//     predates the effective tombstone horizon.
//  2. History pruning: remove non-pinned log rows older than the effective
//     history depth for each subject's current owning tenant.
//  3. Orphan cleanup: remove payload_content rows unreferenced by the log.
func (p *SQLiteEntityGraphProvider) RunRetentionGC(ctx context.Context, policy interfaces.RetentionPolicy) error {
	historyDays := policy.HistoryDays
	if historyDays <= 0 {
		historyDays = defaultHistoryDays
	}
	tombstoneDays := policy.TombstoneDays
	if tombstoneDays <= 0 {
		tombstoneDays = historyDays + 7
	}

	overrides, err := p.loadRetentionOverrides(ctx)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: retention gc: load overrides: %w", err)
	}

	now := time.Now().UTC()

	if err := p.sweepTombstones(ctx, now, historyDays, tombstoneDays, overrides); err != nil {
		return fmt.Errorf("entitygraph/sqlite: retention gc: sweep tombstones: %w", err)
	}
	if err := p.pruneHistory(ctx, now, historyDays, tombstoneDays, overrides); err != nil {
		return fmt.Errorf("entitygraph/sqlite: retention gc: prune history: %w", err)
	}
	if err := p.sweepOrphanPayloads(ctx); err != nil {
		return fmt.Errorf("entitygraph/sqlite: retention gc: orphan payloads: %w", err)
	}
	return nil
}

// SetRetentionPolicy upserts a per-tenant-subtree retention policy override.
// HistoryDays=0 and TombstoneDays=0 removes the override for the given tenant.
func (p *SQLiteEntityGraphProvider) SetRetentionPolicy(ctx context.Context, policy interfaces.RetentionPolicy) error {
	if policy.TenantPath == "" {
		return fmt.Errorf("entitygraph/sqlite: SetRetentionPolicy: TenantPath must not be empty")
	}
	if policy.HistoryDays == 0 && policy.TombstoneDays == 0 {
		_, err := p.db.ExecContext(ctx,
			`DELETE FROM eg_retention_policy WHERE tenant_path = ?`, policy.TenantPath)
		return err
	}
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO eg_retention_policy (tenant_path, history_days, tombstone_days)
		 VALUES (?, ?, ?)
		 ON CONFLICT(tenant_path) DO UPDATE SET
		   history_days   = excluded.history_days,
		   tombstone_days = excluded.tombstone_days`,
		policy.TenantPath, policy.HistoryDays, policy.TombstoneDays,
	)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: SetRetentionPolicy: %w", err)
	}
	return nil
}

type retentionOverride struct {
	tenantPath    string
	historyDays   int
	tombstoneDays int
}

// loadRetentionOverrides loads all per-tenant-subtree policy rows.
func (p *SQLiteEntityGraphProvider) loadRetentionOverrides(ctx context.Context) ([]retentionOverride, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT tenant_path, history_days, tombstone_days FROM eg_retention_policy`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: load retention overrides: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []retentionOverride
	for rows.Next() {
		var r retentionOverride
		if err := rows.Scan(&r.tenantPath, &r.historyDays, &r.tombstoneDays); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// effectivePolicyDays returns (historyDays, tombstoneDays) for owningTenant,
// applying the most-specific matching override (longest prefix) from overrides.
func effectivePolicyDays(owningTenant string, defaultHistory, defaultTombstone int, overrides []retentionOverride) (int, int) {
	bestLen := -1
	h, ts := defaultHistory, defaultTombstone
	for _, r := range overrides {
		if r.tenantPath == owningTenant || strings.HasPrefix(owningTenant, r.tenantPath+"/") {
			if len(r.tenantPath) > bestLen {
				bestLen = len(r.tenantPath)
				if r.historyDays > 0 {
					h = r.historyDays
				}
				if r.tombstoneDays > 0 {
					ts = r.tombstoneDays
				}
			}
		}
	}
	return h, ts
}

// sweepTombstones fully removes subjects whose most-recent log row is 'absence'
// and whose absence timestamp predates the effective tombstone horizon.
// Removal covers eg_observation_log, eg_entity_current, eg_entity_index,
// eg_edge_projection, and eg_drift_projection.
func (p *SQLiteEntityGraphProvider) sweepTombstones(ctx context.Context, now time.Time, defaultHistory, defaultTombstone int, overrides []retentionOverride) error {
	// Load candidates: subjects whose latest observation is an absence,
	// along with the absence timestamp and current owning_tenant.
	rows, err := p.db.QueryContext(ctx, `
		SELECT l.subject,
		       l.observed_at,
		       COALESCE(ei.owning_tenant, '') AS owning_tenant
		FROM eg_observation_log l
		LEFT JOIN eg_entity_index ei ON ei.subject = l.subject
		WHERE l.id = (
		    SELECT MAX(l2.id) FROM eg_observation_log l2 WHERE l2.subject = l.subject
		)
		  AND l.kind = 'absence'
	`)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: tombstone candidates: %w", err)
	}

	type candidate struct {
		subject      string
		observedAt   string
		owningTenant string
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.subject, &c.observedAt, &c.owningTenant); err != nil {
			_ = rows.Close()
			return err
		}
		candidates = append(candidates, c)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, c := range candidates {
		_, tombDays := effectivePolicyDays(c.owningTenant, defaultHistory, defaultTombstone, overrides)
		horizon := now.AddDate(0, 0, -tombDays)

		absenceTime, parseErr := time.Parse(time.RFC3339Nano, c.observedAt)
		if parseErr != nil {
			continue
		}
		if !absenceTime.Before(horizon) {
			continue
		}

		// Fully delete all rows for this subject.
		for _, q := range []struct {
			desc  string
			query string
		}{
			{"log", `DELETE FROM eg_observation_log WHERE subject = ?`},
			{"current", `DELETE FROM eg_entity_current WHERE subject = ?`},
			{"index", `DELETE FROM eg_entity_index WHERE subject = ?`},
			{"drift", `DELETE FROM eg_drift_projection WHERE subject = ?`},
		} {
			if _, err := p.db.ExecContext(ctx, q.query, c.subject); err != nil {
				return fmt.Errorf("entitygraph/sqlite: tombstone delete %s for %s: %w", q.desc, c.subject, err)
			}
		}
		// Remove edge projections referencing this subject as either endpoint.
		if _, err := p.db.ExecContext(ctx,
			`DELETE FROM eg_edge_projection WHERE from_subject = ? OR to_subject = ?`,
			c.subject, c.subject,
		); err != nil {
			return fmt.Errorf("entitygraph/sqlite: tombstone delete edges for %s: %w", c.subject, err)
		}
		// Remove log rows whose edge-subject string contains this subject as either endpoint.
		// Edge subject format: "edge_type|from_eid|to_eid".
		if _, err := p.db.ExecContext(ctx,
			`DELETE FROM eg_observation_log
			 WHERE subject LIKE ? OR subject LIKE ?`,
			"%|"+c.subject+"|%", "%|"+c.subject,
		); err != nil {
			return fmt.Errorf("entitygraph/sqlite: tombstone delete edge-log for %s: %w", c.subject, err)
		}
	}
	return nil
}

// pruneHistory removes non-pinned observation log rows that are older than
// the effective history depth for each subject's owning tenant. The
// never-prune-current invariant is enforced by excluding:
//
//   - log rows referenced by eg_entity_current.log_seq (latest current-state)
//   - log rows referenced by eg_edge_projection.log_seq (latest edge state)
//   - the latest drift-diff log row for subjects with a non-resolved drift record
func (p *SQLiteEntityGraphProvider) pruneHistory(ctx context.Context, now time.Time, defaultHistory, defaultTombstone int, overrides []retentionOverride) error {
	// Collect all pinned log IDs (never-prune-current invariant).
	pinned, err := p.loadPinnedLogSeqs(ctx)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: prune history: load pinned seqs: %w", err)
	}

	// Load all subjects with their current owning_tenant.
	// Subjects absent from eg_entity_index (e.g. edge subjects) use the default policy.
	subjectTenants, err := p.loadAllLogSubjects(ctx)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: prune history: load subjects: %w", err)
	}

	// Build a map of subject → owning_tenant for quick lookup.
	tenantBySubject, err := p.loadSubjectOwners(ctx)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: prune history: load owners: %w", err)
	}

	// Process each subject independently so per-tenant policies apply correctly.
	for _, subject := range subjectTenants {
		owningTenant := tenantBySubject[subject]
		histDays, _ := effectivePolicyDays(owningTenant, defaultHistory, defaultTombstone, overrides)
		cutoff := now.AddDate(0, 0, -histDays)
		cutoffStr := rfc3339(cutoff)

		// Collect pinned IDs for this subject.
		var pinList []int64
		for seq := range pinned {
			if pinned[seq] == subject {
				pinList = append(pinList, seq)
			}
		}

		if len(pinList) == 0 {
			if _, err := p.db.ExecContext(ctx,
				`DELETE FROM eg_observation_log WHERE subject = ? AND observed_at < ?`,
				subject, cutoffStr,
			); err != nil {
				return fmt.Errorf("entitygraph/sqlite: prune subject %q: %w", subject, err)
			}
		} else {
			// Build NOT IN (...) clause with positional placeholders.
			args := make([]interface{}, 0, 2+len(pinList))
			args = append(args, subject, cutoffStr)
			placeholders := make([]string, len(pinList))
			for i, seq := range pinList {
				placeholders[i] = "?"
				args = append(args, seq)
			}
			// #nosec G202 -- placeholders are only "?" literals, not from external input.
			query := `DELETE FROM eg_observation_log WHERE subject = ? AND observed_at < ?` +
				` AND id NOT IN (` + strings.Join(placeholders, ",") + `)`
			if _, err := p.db.ExecContext(ctx, query, args...); err != nil {
				return fmt.Errorf("entitygraph/sqlite: prune subject %q: %w", subject, err)
			}
		}
	}
	return nil
}

// loadPinnedLogSeqs returns a map of log_seq → subject for all log rows that
// are currently pinned by a projection table and must never be pruned.
// Pinned sources:
//   - eg_entity_current.log_seq (per subject+source)
//   - eg_edge_projection.log_seq (per edge)
//   - latest drift-diff log_seq for subjects with non-resolved drift records
func (p *SQLiteEntityGraphProvider) loadPinnedLogSeqs(ctx context.Context) (map[int64]string, error) {
	pinned := make(map[int64]string)

	// Entity current projections.
	rows, err := p.db.QueryContext(ctx, `SELECT subject, log_seq FROM eg_entity_current`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: pinned entity seqs: %w", err)
	}
	if err := scanSeqRows(rows, pinned); err != nil {
		return nil, err
	}

	// Edge projection log_seqs — the edge subject is from_subject|edge_type|to_subject,
	// but we use from_subject as the representative key (any non-empty value works).
	rows, err = p.db.QueryContext(ctx,
		`SELECT from_subject || '|' || COALESCE(edge_type,'') || '|' || to_subject, log_seq
		 FROM eg_edge_projection WHERE log_seq > 0`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: pinned edge seqs: %w", err)
	}
	if err := scanSeqRows(rows, pinned); err != nil {
		return nil, err
	}

	// Latest drift-diff rows for subjects with non-resolved drift records.
	rows, err = p.db.QueryContext(ctx, `
		SELECT l.subject, MAX(l.id)
		FROM eg_observation_log l
		JOIN eg_drift_projection dp ON dp.subject = l.subject
		WHERE l.kind = 'drift-diff'
		  AND dp.lifecycle_status != 'resolved'
		GROUP BY l.subject
	`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: pinned drift seqs: %w", err)
	}
	if err := scanSeqRows(rows, pinned); err != nil {
		return nil, err
	}

	return pinned, nil
}

// scanSeqRows scans rows of (subject TEXT, log_seq INTEGER) into pinned.
func scanSeqRows(rows *sql.Rows, pinned map[int64]string) error {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var subject string
		var seq int64
		if err := rows.Scan(&subject, &seq); err != nil {
			return err
		}
		pinned[seq] = subject
	}
	return rows.Err()
}

// loadAllLogSubjects returns the distinct set of subject strings present in
// eg_observation_log — this includes both entity and edge subjects.
func (p *SQLiteEntityGraphProvider) loadAllLogSubjects(ctx context.Context) ([]string, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT DISTINCT subject FROM eg_observation_log`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: load log subjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var subjects []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		subjects = append(subjects, s)
	}
	return subjects, rows.Err()
}

// loadSubjectOwners returns a map of subject → owning_tenant from eg_entity_index.
// Subjects absent from the index (edge subjects, tombstoned entities) are not
// in the map; callers treat them as having an empty owning_tenant (default policy).
func (p *SQLiteEntityGraphProvider) loadSubjectOwners(ctx context.Context) (map[string]string, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT subject, owning_tenant FROM eg_entity_index`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: load subject owners: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]string)
	for rows.Next() {
		var subject, tenant string
		if err := rows.Scan(&subject, &tenant); err != nil {
			return nil, err
		}
		out[subject] = tenant
	}
	return out, rows.Err()
}

// sweepOrphanPayloads removes payload_content rows whose hash is no longer
// referenced by any observation log row. Called after log pruning.
func (p *SQLiteEntityGraphProvider) sweepOrphanPayloads(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, `
		DELETE FROM eg_payload_content
		WHERE payload_hash NOT IN (
		    SELECT DISTINCT payload_hash FROM eg_observation_log
		)
	`)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: sweep orphan payloads: %w", err)
	}
	return nil
}
