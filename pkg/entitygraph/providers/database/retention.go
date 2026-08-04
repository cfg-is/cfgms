// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

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

	// gcAdvisoryLockKey is the PostgreSQL advisory lock key used to prevent
	// concurrent retention sweeps across multiple controller nodes (AC6).
	gcAdvisoryLockKey = 2878_001 // Story #2878 namespace
)

// RunRetentionGC executes one retention GC sweep against the observation log
// and derived tables. It uses a PostgreSQL advisory lock to ensure that only
// one node runs the sweep at a time in a multi-node SaaS deployment (AC6).
// If the lock is held by another node, the sweep is skipped (not an error).
//
// The never-prune-current invariant is enforced across all projection tables.
// Per-tenant-subtree policy overrides from eg_retention_policy are applied,
// with the most-specific matching tenant_path prefix winning (ADR-023 §7).
func (p *DatabaseEntityGraphProvider) RunRetentionGC(ctx context.Context, policy interfaces.RetentionPolicy) error {
	historyDays := policy.HistoryDays
	if historyDays <= 0 {
		historyDays = defaultHistoryDays
	}
	tombstoneDays := policy.TombstoneDays
	if tombstoneDays <= 0 {
		tombstoneDays = historyDays + 7
	}

	// Acquire advisory lock to prevent double-sweep (AC6).
	var lockAcquired bool
	if err := p.db.QueryRowContext(ctx,
		`SELECT pg_try_advisory_lock($1)`, gcAdvisoryLockKey,
	).Scan(&lockAcquired); err != nil {
		return fmt.Errorf("entitygraph/database: retention gc: acquire lock: %w", err)
	}
	if !lockAcquired {
		return nil // another node is running the sweep; this is not an error
	}
	defer func() {
		_, _ = p.db.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gcAdvisoryLockKey)
	}()

	overrides, err := p.dbLoadRetentionOverrides(ctx)
	if err != nil {
		return fmt.Errorf("entitygraph/database: retention gc: load overrides: %w", err)
	}

	now := time.Now().UTC()

	if err := p.dbSweepTombstones(ctx, now, historyDays, tombstoneDays, overrides); err != nil {
		return fmt.Errorf("entitygraph/database: retention gc: sweep tombstones: %w", err)
	}
	if err := p.dbPruneHistory(ctx, now, historyDays, tombstoneDays, overrides); err != nil {
		return fmt.Errorf("entitygraph/database: retention gc: prune history: %w", err)
	}
	if err := p.dbSweepOrphanPayloads(ctx); err != nil {
		return fmt.Errorf("entitygraph/database: retention gc: orphan payloads: %w", err)
	}
	return nil
}

// SetRetentionPolicy upserts a per-tenant-subtree retention policy override.
// HistoryDays=0 and TombstoneDays=0 removes the override for the given tenant.
func (p *DatabaseEntityGraphProvider) SetRetentionPolicy(ctx context.Context, policy interfaces.RetentionPolicy) error {
	if policy.TenantPath == "" {
		return fmt.Errorf("entitygraph/database: SetRetentionPolicy: TenantPath must not be empty")
	}
	if policy.HistoryDays == 0 && policy.TombstoneDays == 0 {
		_, err := p.db.ExecContext(ctx,
			`DELETE FROM eg_retention_policy WHERE tenant_path = $1`, policy.TenantPath)
		return err
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO eg_retention_policy (tenant_path, history_days, tombstone_days)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_path) DO UPDATE SET
		    history_days   = EXCLUDED.history_days,
		    tombstone_days = EXCLUDED.tombstone_days`,
		policy.TenantPath, policy.HistoryDays, policy.TombstoneDays,
	)
	if err != nil {
		return fmt.Errorf("entitygraph/database: SetRetentionPolicy: %w", err)
	}
	return nil
}

type dbRetentionOverride struct {
	tenantPath    string
	historyDays   int
	tombstoneDays int
}

func (p *DatabaseEntityGraphProvider) dbLoadRetentionOverrides(ctx context.Context) ([]dbRetentionOverride, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT tenant_path, history_days, tombstone_days FROM eg_retention_policy`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: load retention overrides: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []dbRetentionOverride
	for rows.Next() {
		var r dbRetentionOverride
		if err := rows.Scan(&r.tenantPath, &r.historyDays, &r.tombstoneDays); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func dbEffectivePolicyDays(owningTenant string, defaultHistory, defaultTombstone int, overrides []dbRetentionOverride) (int, int) {
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

// dbSweepTombstones fully removes subjects whose most-recent log row is 'absence'
// and whose absence timestamp predates the effective tombstone horizon.
func (p *DatabaseEntityGraphProvider) dbSweepTombstones(ctx context.Context, now time.Time, defaultHistory, defaultTombstone int, overrides []dbRetentionOverride) error {
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
		return fmt.Errorf("entitygraph/database: tombstone candidates: %w", err)
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
		_, tombDays := dbEffectivePolicyDays(c.owningTenant, defaultHistory, defaultTombstone, overrides)
		horizon := now.AddDate(0, 0, -tombDays)

		absenceTime, parseErr := time.Parse(time.RFC3339Nano, c.observedAt)
		if parseErr != nil {
			continue
		}
		if !absenceTime.Before(horizon) {
			continue
		}

		for _, q := range []struct {
			desc  string
			query string
		}{
			{"log", `DELETE FROM eg_observation_log WHERE subject = $1`},
			{"current", `DELETE FROM eg_entity_current WHERE subject = $1`},
			{"index", `DELETE FROM eg_entity_index WHERE subject = $1`},
			{"drift", `DELETE FROM eg_drift_projection WHERE subject = $1`},
		} {
			if _, err := p.db.ExecContext(ctx, q.query, c.subject); err != nil {
				return fmt.Errorf("entitygraph/database: tombstone delete %s for %s: %w", q.desc, c.subject, err)
			}
		}
		if _, err := p.db.ExecContext(ctx,
			`DELETE FROM eg_edge_projection WHERE from_subject = $1 OR to_subject = $1`,
			c.subject,
		); err != nil {
			return fmt.Errorf("entitygraph/database: tombstone delete edges for %s: %w", c.subject, err)
		}
		// Remove edge log rows referencing this subject as either endpoint.
		if _, err := p.db.ExecContext(ctx,
			`DELETE FROM eg_observation_log
			 WHERE subject LIKE $1 OR subject LIKE $2`,
			"%|"+c.subject+"|%", "%|"+c.subject,
		); err != nil {
			return fmt.Errorf("entitygraph/database: tombstone delete edge-log for %s: %w", c.subject, err)
		}
	}
	return nil
}

// dbPruneHistory removes non-pinned observation log rows older than the
// effective history depth for each subject's owning tenant.
func (p *DatabaseEntityGraphProvider) dbPruneHistory(ctx context.Context, now time.Time, defaultHistory, defaultTombstone int, overrides []dbRetentionOverride) error {
	pinned, err := p.dbLoadPinnedLogSeqs(ctx)
	if err != nil {
		return fmt.Errorf("entitygraph/database: prune history: load pinned: %w", err)
	}

	subjects, err := p.dbLoadAllLogSubjects(ctx)
	if err != nil {
		return fmt.Errorf("entitygraph/database: prune history: load subjects: %w", err)
	}

	tenantBySubject, err := p.dbLoadSubjectOwners(ctx)
	if err != nil {
		return fmt.Errorf("entitygraph/database: prune history: load owners: %w", err)
	}

	for _, subject := range subjects {
		owningTenant := tenantBySubject[subject]
		histDays, _ := dbEffectivePolicyDays(owningTenant, defaultHistory, defaultTombstone, overrides)
		cutoff := now.AddDate(0, 0, -histDays)
		cutoffStr := cutoff.UTC().Format(time.RFC3339Nano)

		var pinList []int64
		for seq, s := range pinned {
			if s == subject {
				pinList = append(pinList, seq)
			}
		}

		if len(pinList) == 0 {
			if _, err := p.db.ExecContext(ctx,
				`DELETE FROM eg_observation_log WHERE subject = $1 AND observed_at < $2`,
				subject, cutoffStr,
			); err != nil {
				return fmt.Errorf("entitygraph/database: prune subject %q: %w", subject, err)
			}
		} else {
			// Build NOT IN ($3,$4,...) with numeric placeholders.
			args := make([]interface{}, 0, 2+len(pinList))
			args = append(args, subject, cutoffStr)
			placeholders := make([]string, len(pinList))
			for i, seq := range pinList {
				args = append(args, seq)
				placeholders[i] = fmt.Sprintf("$%d", i+3)
			}
			// #nosec G202 -- placeholders are generated only from integer
			// positions; subject, cutoff, and pinned IDs remain bound arguments.
			query := `DELETE FROM eg_observation_log WHERE subject = $1 AND observed_at < $2` +
				` AND id NOT IN (` + strings.Join(placeholders, ",") + `)`
			if _, err := p.db.ExecContext(ctx, query, args...); err != nil {
				return fmt.Errorf("entitygraph/database: prune subject %q: %w", subject, err)
			}
		}
	}
	return nil
}

func (p *DatabaseEntityGraphProvider) dbLoadPinnedLogSeqs(ctx context.Context) (map[int64]string, error) {
	pinned := make(map[int64]string)

	// Entity current projections: eg_entity_current.log_seq.
	rows, err := p.db.QueryContext(ctx, `SELECT subject, log_seq FROM eg_entity_current`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: pinned entity seqs: %w", err)
	}
	if err := dbScanSeqRows(rows, pinned); err != nil {
		return nil, err
	}

	// Edge projections: the database provider does not store log_seq in
	// eg_edge_projection, so we find the most recent log row for each
	// currently-projected edge by joining on edge subject + source.
	rows, err = p.db.QueryContext(ctx, `
		SELECT ep.edge_type || '|' || ep.from_subject || '|' || ep.to_subject AS edge_subj,
		       MAX(l.id) AS max_seq
		FROM eg_edge_projection ep
		JOIN eg_observation_log l
		  ON l.subject = ep.edge_type || '|' || ep.from_subject || '|' || ep.to_subject
		 AND l.source  = ep.source
		GROUP BY ep.from_subject, ep.to_subject, ep.edge_type, ep.source
	`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: pinned edge seqs: %w", err)
	}
	if err := dbScanSeqRows(rows, pinned); err != nil {
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
		return nil, fmt.Errorf("entitygraph/database: pinned drift seqs: %w", err)
	}
	if err := dbScanSeqRows(rows, pinned); err != nil {
		return nil, err
	}

	return pinned, nil
}

func dbScanSeqRows(rows *sql.Rows, pinned map[int64]string) error {
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

func (p *DatabaseEntityGraphProvider) dbLoadAllLogSubjects(ctx context.Context) ([]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT DISTINCT subject FROM eg_observation_log`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: load log subjects: %w", err)
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

func (p *DatabaseEntityGraphProvider) dbLoadSubjectOwners(ctx context.Context) (map[string]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT subject, owning_tenant FROM eg_entity_index`)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: load subject owners: %w", err)
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

func (p *DatabaseEntityGraphProvider) dbSweepOrphanPayloads(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, `
		DELETE FROM eg_payload_content
		WHERE content_hash NOT IN (
		    SELECT DISTINCT payload_hash FROM eg_observation_log
		)
	`)
	if err != nil {
		return fmt.Errorf("entitygraph/database: sweep orphan payloads: %w", err)
	}
	return nil
}
