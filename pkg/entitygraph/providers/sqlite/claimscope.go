// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// claimScopeKey builds the eg_claim_scope_prior PRIMARY KEY for a (source,
// pattern) pair. Source is embedded so that two different sources using the same
// pattern do not collide on the table's single-column PRIMARY KEY.
func claimScopeKey(source string, pattern types.ClaimScopePattern) string {
	switch {
	case pattern.Edge != nil:
		e := pattern.Edge
		return source + "\x1fedge\x1f" + e.EdgeType + "\x1f" + e.AnchorEID.String() + "\x1f" + string(e.Direction)
	case pattern.Entity != nil:
		en := pattern.Entity
		return source + "\x1fentity\x1f" + en.EntityType + "\x1f" + en.AuthorityPrefix
	default:
		return source + "\x1fempty"
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
// the given source and pattern. Per-observation source falls back to batchSource
// when empty, mirroring ReportObservations behaviour.
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
		key := claimScopeKey(src, cs.Pattern)
		if seen[key] {
			return fmt.Errorf("entitygraph/sqlite: overlapping claim scope for source %q pattern key %q", src, key)
		}
		seen[key] = true
	}

	for _, cs := range scopes {
		src := cs.Source
		if src == "" {
			src = batchSource
		}
		scopeKey := claimScopeKey(src, cs.Pattern)
		asOf := cs.AsOf
		if asOf.IsZero() {
			asOf = time.Now().UTC()
		}

		prior, err := loadPriorSubjects(ctx, tx, scopeKey)
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
				return fmt.Errorf("entitygraph/sqlite: retract subject %q in scope %q: %w", subject, scopeKey, err)
			}
		}

		// AC5: update the prior-assertion table in a single indexed batch upsert.
		if err := savePriorSubjects(ctx, tx, scopeKey, src, asOf, current); err != nil {
			return fmt.Errorf("entitygraph/sqlite: save prior subjects for scope %q: %w", scopeKey, err)
		}
	}
	return nil
}

// loadPriorSubjects reads the JSON-encoded prior subject set from
// eg_claim_scope_prior for the given scope key.
func loadPriorSubjects(ctx context.Context, tx *sql.Tx, scopeKey string) (map[string]struct{}, error) {
	var subjectsJSON string
	err := tx.QueryRowContext(ctx,
		`SELECT subjects FROM eg_claim_scope_prior WHERE scope_key = ?`, scopeKey,
	).Scan(&subjectsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return make(map[string]struct{}), nil
	}
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: load prior subjects for key %q: %w", scopeKey, err)
	}
	var list []string
	if err := json.Unmarshal([]byte(subjectsJSON), &list); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: decode prior subjects: %w", err)
	}
	result := make(map[string]struct{}, len(list))
	for _, s := range list {
		result[s] = struct{}{}
	}
	return result, nil
}

// savePriorSubjects writes the current subject set to eg_claim_scope_prior
// as a single indexed upsert (AC5: not an N+1-per-row loop). The subjects
// are stored as a JSON array — one row per (source, pattern) scope.
func savePriorSubjects(ctx context.Context, tx *sql.Tx, scopeKey, source string, asOf time.Time, subjects map[string]struct{}) error {
	list := make([]string, 0, len(subjects))
	for s := range subjects {
		list = append(list, s)
	}
	data, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: marshal current subjects: %w", err)
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO eg_claim_scope_prior (scope_key, source, as_of, subjects)
		 VALUES(?, ?, ?, ?)
		 ON CONFLICT(scope_key) DO UPDATE SET
			source   = excluded.source,
			as_of    = excluded.as_of,
			subjects = excluded.subjects`,
		scopeKey, source, rfc3339(asOf), string(data),
	)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: save prior subjects: %w", err)
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
	hash, err := payloadHash(map[string]interface{}{})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO eg_payload_content(payload_hash, payload) VALUES(?, '{}')`, hash,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: insert absence payload: %w", err)
	}
	sc := resolveSourceClass(source)
	_, err = tx.ExecContext(ctx,
		`INSERT INTO eg_observation_log
			(subject, source, source_class, observed_at, recorded_at, kind, confidence, claim_scope_key, payload_hash, tenant_path)
		 VALUES(?, ?, ?, ?, ?, ?, ?, '', ?, '')`,
		subject, source, string(sc),
		rfc3339(asOf), rfc3339(asOf),
		string(types.ObservationKindAbsence), string(types.ConfidenceHigh),
		hash,
	)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: append absence log for %q: %w", subject, err)
	}
	return nil
}

// retractEntityProjection removes a source's assertion of an entity from the
// current-state table and rebuilds the entity index for the subject.
func retractEntityProjection(ctx context.Context, tx *sql.Tx, subject, source string) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM eg_entity_current WHERE subject = ? AND source = ?`, subject, source,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: delete entity current for retraction: %w", err)
	}
	return rebuildEntityIndex(ctx, tx, subject)
}

// retractEdgeProjection removes an edge from eg_edge_projection.
func retractEdgeProjection(ctx context.Context, tx *sql.Tx, subject, source string) error {
	edgeType, fromSubject, toSubject, err := parseEdgeSubject(subject)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: parse edge subject for retraction: %w", err)
	}
	key := edgeProjectionKey(fromSubject, edgeType, toSubject, source)
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM eg_edge_projection WHERE edge_key = ?`, key,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: delete edge projection for retraction: %w", err)
	}
	return nil
}
