// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// dbPatternKey derives a canonical storage key from a scope pattern alone
// (without source). Source is a PK column in eg_claim_scope_prior, so it does
// not need to be embedded in the key.
func dbPatternKey(pattern types.ClaimScopePattern) string {
	switch {
	case pattern.Edge != nil:
		e := pattern.Edge
		return "edge\x1f" + e.EdgeType + "\x1f" + e.AnchorEID.String() + "\x1f" + string(e.Direction)
	case pattern.Entity != nil:
		en := pattern.Entity
		return "entity\x1f" + en.EntityType + "\x1f" + en.AuthorityPrefix
	default:
		return "empty"
	}
}

// subjectMatchesEntityScope reports whether a subject string falls within an
// entity scope pattern. Empty EntityType or AuthorityPrefix match all values.
func subjectMatchesEntityScope(subject string, p *types.EntityScopePattern) bool {
	eid, err := types.ParseEID(subject)
	if err != nil {
		return false
	}
	if p.EntityType != "" && eid.AuthorityType() != p.EntityType {
		return false
	}
	if p.AuthorityPrefix != "" && !strings.HasPrefix(subject, p.AuthorityPrefix) {
		return false
	}
	return true
}

// subjectMatchesEdgeScope reports whether an edge subject string falls within an
// edge scope pattern. The anchor EID and traversal direction determine which end
// of the edge is fixed to the anchor.
func subjectMatchesEdgeScope(subject string, p *types.EdgeScopePattern) bool {
	edgeType, fromSubject, toSubject, err := parseEdgeSubject(subject)
	if err != nil {
		return false
	}
	if p.EdgeType != "" && edgeType != p.EdgeType {
		return false
	}
	anchor := p.AnchorEID.String()
	switch p.Direction {
	case types.TraversalOutbound:
		return fromSubject == anchor
	case types.TraversalInbound:
		return toSubject == anchor
	default: // TraversalBoth
		return fromSubject == anchor || toSubject == anchor
	}
}

// collectScopeSubjects returns the set of subjects from observations that match
// the given scope source and pattern. Per-observation source falls back to
// batchSource when empty, mirroring ReportObservations behaviour.
func collectScopeSubjects(batchSource, scopeSource string, pattern types.ClaimScopePattern, observations []types.Observation) map[string]struct{} {
	result := make(map[string]struct{})
	for _, obs := range observations {
		src := obs.Source
		if src == "" {
			src = batchSource
		}
		if src != scopeSource {
			continue
		}
		switch {
		case pattern.Entity != nil && subjectMatchesEntityScope(obs.Subject, pattern.Entity):
			result[obs.Subject] = struct{}{}
		case pattern.Edge != nil && subjectMatchesEdgeScope(obs.Subject, pattern.Edge):
			result[obs.Subject] = struct{}{}
		}
	}
	return result
}

// processClaimScopes applies claim-scope diff-and-retract for every scope
// declared in the batch. It runs inside the same write transaction as the
// observation ingest so that partial retractions can never persist.
//
// Overlapping scopes (same source + pattern key) within one batch are rejected
// immediately per ADR-022 §4.
func processClaimScopes(ctx context.Context, tx *sql.Tx, batchSource string, scopes []types.ClaimScope, observations []types.Observation) error {
	// Detect overlapping scopes before any writes.
	seen := make(map[string]bool, len(scopes))
	for _, cs := range scopes {
		src := cs.Source
		if src == "" {
			src = batchSource
		}
		combined := src + "\x1f" + dbPatternKey(cs.Pattern)
		if seen[combined] {
			return fmt.Errorf("entitygraph/database: overlapping claim scope for source %q pattern key %q", src, dbPatternKey(cs.Pattern))
		}
		seen[combined] = true
	}

	for _, cs := range scopes {
		src := cs.Source
		if src == "" {
			src = batchSource
		}
		scopeKey := dbPatternKey(cs.Pattern)
		asOf := cs.AsOf
		if asOf.IsZero() {
			asOf = time.Now().UTC()
		}

		prior, err := loadPriorSubjects(ctx, tx, src, scopeKey)
		if err != nil {
			return err
		}

		current := collectScopeSubjects(batchSource, src, cs.Pattern, observations)

		// Retract each subject present in the prior set but absent from the
		// current enumeration.
		for subject := range prior {
			if _, ok := current[subject]; ok {
				continue
			}
			if err := retractSubject(ctx, tx, subject, src, cs.Pattern, asOf); err != nil {
				return fmt.Errorf("entitygraph/database: retract subject %q in scope %q: %w", subject, scopeKey, err)
			}
		}

		// AC5: replace prior table in two statements (DELETE + batch INSERT),
		// not an N+1-per-row loop.
		if err := replacePriorSubjects(ctx, tx, src, scopeKey, current); err != nil {
			return fmt.Errorf("entitygraph/database: replace prior subjects for scope %q: %w", scopeKey, err)
		}
	}
	return nil
}

// loadPriorSubjects reads all subjects previously asserted under (source,
// claim_scope_key) from eg_claim_scope_prior.
func loadPriorSubjects(ctx context.Context, tx *sql.Tx, source, scopeKey string) (map[string]struct{}, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT subject FROM eg_claim_scope_prior WHERE source = $1 AND claim_scope_key = $2`,
		source, scopeKey,
	)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: load prior subjects for key %q: %w", scopeKey, err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string]struct{})
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("entitygraph/database: scan prior subject: %w", err)
		}
		result[s] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/database: iterate prior subjects: %w", err)
	}
	return result, nil
}

// replacePriorSubjects replaces the prior subject set for a claim scope using
// two SQL statements — a DELETE to clear the old set and a single multi-value
// INSERT to write the new set. This satisfies AC5 (single indexed batch upsert,
// not N+1 per row).
func replacePriorSubjects(ctx context.Context, tx *sql.Tx, source, scopeKey string, subjects map[string]struct{}) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM eg_claim_scope_prior WHERE source = $1 AND claim_scope_key = $2`,
		source, scopeKey,
	); err != nil {
		return fmt.Errorf("entitygraph/database: delete prior subjects for scope %q: %w", scopeKey, err)
	}
	if len(subjects) == 0 {
		return nil
	}

	list := make([]string, 0, len(subjects))
	for s := range subjects {
		list = append(list, s)
	}

	// Build a single multi-value INSERT: ($1, $2, $3), ($1, $2, $4), ...
	// PostgreSQL permits re-referencing $1 and $2 across value groups.
	args := make([]interface{}, 0, 2+len(list))
	args = append(args, source, scopeKey)
	phParts := make([]string, 0, len(list))
	for i, s := range list {
		phParts = append(phParts, fmt.Sprintf("($1, $2, $%d)", i+3))
		args = append(args, s)
	}
	query := `INSERT INTO eg_claim_scope_prior (source, claim_scope_key, subject)
              VALUES ` + strings.Join(phParts, ", ") + ` ON CONFLICT DO NOTHING`
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("entitygraph/database: batch insert prior subjects for scope %q: %w", scopeKey, err)
	}
	return nil
}

// retractSubject emits an absence observation into the log (making the
// retraction permanently visible in the history stream per ADR-022 §4) and
// removes the subject from its current-state projection.
func retractSubject(ctx context.Context, tx *sql.Tx, subject, source string, pattern types.ClaimScopePattern, asOf time.Time) error {
	if err := appendAbsenceLog(ctx, tx, subject, source, asOf); err != nil {
		return err
	}
	if pattern.Entity != nil {
		return retractEntityProjection(ctx, tx, subject, source)
	}
	return retractEdgeProjection(ctx, tx, subject, source)
}

// appendAbsenceLog writes a single absence observation to eg_observation_log so
// that source-closure events are permanently visible in the history stream
// (ADR-022 §4 / AC4).
func appendAbsenceLog(ctx context.Context, tx *sql.Tx, subject, source string, asOf time.Time) error {
	hash, err := payloadHash(nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_payload_content (content_hash, payload_json)
		 VALUES ($1, '{}')
		 ON CONFLICT (content_hash) DO NOTHING`,
		hash,
	); err != nil {
		return fmt.Errorf("entitygraph/database: insert absence payload: %w", err)
	}
	sc := string(resolveSourceClass(source))
	asOfStr := asOf.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	_, err = tx.ExecContext(ctx,
		`INSERT INTO eg_observation_log
			(subject, source, source_class, observed_at, recorded_at, kind, confidence, claim_scope_key, payload_hash, tenant_path)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, '', $8, '')`,
		subject, source, sc, asOfStr, asOfStr,
		string(types.ObservationKindAbsence), string(types.ConfidenceHigh),
		hash,
	)
	if err != nil {
		return fmt.Errorf("entitygraph/database: append absence log for %q: %w", subject, err)
	}
	return nil
}

// retractEntityProjection removes a source's assertion of an entity from the
// current-state table and rebuilds the entity index for the subject.
func retractEntityProjection(ctx context.Context, tx *sql.Tx, subject, source string) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM eg_entity_current WHERE subject = $1 AND source = $2`, subject, source,
	); err != nil {
		return fmt.Errorf("entitygraph/database: delete entity current for retraction: %w", err)
	}
	return rebuildEntityIndex(ctx, tx, subject)
}

// retractEdgeProjection removes an edge from eg_edge_projection.
func retractEdgeProjection(ctx context.Context, tx *sql.Tx, subject, source string) error {
	edgeType, fromSubject, toSubject, err := parseEdgeSubject(subject)
	if err != nil {
		return fmt.Errorf("entitygraph/database: parse edge subject for retraction: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM eg_edge_projection WHERE from_subject = $1 AND to_subject = $2 AND edge_type = $3 AND source = $4`,
		fromSubject, toSubject, edgeType, source,
	); err != nil {
		return fmt.Errorf("entitygraph/database: delete edge projection for retraction: %w", err)
	}
	return nil
}
