// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// updateDriftProjectionFromObservation upserts eg_drift_projection from a
// drift-diff observation. Called from updateEntityProjection when the
// observation kind is ObservationKindDriftDiff. ON CONFLICT preserves the
// existing lifecycle_status so that lifecycle annotations survive re-reports.
func updateDriftProjectionFromObservation(ctx context.Context, tx *sql.Tx, obs types.Observation) error {
	fieldsJSON, err := driftFieldsJSON(obs.Payload)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: encode drift fields: %w", err)
	}
	configRevision := extractString(obs.Payload, "config_revision")

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_drift_projection
			(subject, detected_at, config_revision, lifecycle_status, fields)
		 VALUES(?, ?, ?, 'detected', ?)
		 ON CONFLICT(subject) DO UPDATE SET
			detected_at     = excluded.detected_at,
			config_revision = excluded.config_revision,
			fields          = excluded.fields`,
		obs.Subject, rfc3339(obs.ObservedAt), configRevision, fieldsJSON,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: upsert drift projection: %w", err)
	}
	return nil
}

// applyLifecycleTransitionFromObs updates eg_drift_projection.lifecycle_status
// from the transition field of a lifecycle observation's payload. Used by
// RebuildProjections to replay lifecycle log rows in sequence order.
func applyLifecycleTransitionFromObs(ctx context.Context, tx *sql.Tx, obs types.Observation) error {
	transition, _ := obs.Payload["transition"].(string)
	if transition == "" {
		return nil
	}
	newStatus, err := transitionLifecycleStatus(transition)
	if err != nil {
		return nil // unknown transition: skip gracefully during replay
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE eg_drift_projection SET lifecycle_status = ? WHERE subject = ?`,
		newStatus, obs.Subject,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: apply lifecycle transition: %w", err)
	}
	return nil
}

// driftFieldsJSON marshals the "fields" payload key as a JSON string for
// storage in eg_drift_projection.fields. Returns "[]" for absent or nil fields.
func driftFieldsJSON(payload map[string]interface{}) (string, error) {
	if payload == nil {
		return "[]", nil
	}
	raw, ok := payload["fields"]
	if !ok {
		return "[]", nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("marshal drift fields: %w", err)
	}
	return string(b), nil
}

// parseDriftFields decodes a JSON-encoded DriftField list from the storage
// column. Returns nil for empty or null values.
func parseDriftFields(data string) ([]interfaces.DriftField, error) {
	if data == "" || data == "[]" || data == "null" {
		return nil, nil
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: parse drift fields: %w", err)
	}
	fields := make([]interfaces.DriftField, 0, len(raw))
	for _, r := range raw {
		f := interfaces.DriftField{
			Attribute: extractString(r, "attribute"),
		}
		if v, ok := r["desired"]; ok {
			f.Desired = v
		}
		if v, ok := r["actual"]; ok {
			f.Actual = v
		}
		if v, ok := r["matching"]; ok {
			if b, ok := v.(bool); ok {
				f.Matching = b
			}
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// normalizeDriftLifecycleStatus converts the empty string (rows created with
// DEFAULT ”) to "detected". All other values pass through unchanged.
func normalizeDriftLifecycleStatus(status string) string {
	if status == "" {
		return "detected"
	}
	return status
}

// transitionLifecycleStatus maps a lifecycle transition verb to the resulting
// status string. Returns an error for unrecognized transitions.
func transitionLifecycleStatus(transition string) (string, error) {
	switch transition {
	case "acknowledge":
		return "acknowledged", nil
	case "resolve":
		return "resolved", nil
	case "ignore":
		return "ignored", nil
	default:
		return "", fmt.Errorf("entitygraph/sqlite: unknown lifecycle transition %q", transition)
	}
}

// GetDesiredState returns the most-recent desired-state observation for eid,
// or (nil, nil) when no desired-state record exists yet (pre-STORY-9 state).
func (p *SQLiteEntityGraphProvider) GetDesiredState(ctx context.Context, eid interfaces.EIDRef) (*types.DesiredStateView, error) {
	subject := eid.String()
	var observedAt, payloadJSON string
	err := p.db.QueryRowContext(ctx,
		`SELECT l.observed_at, p.payload
		 FROM eg_observation_log l
		 JOIN eg_payload_content p ON p.payload_hash = l.payload_hash
		 WHERE l.subject = ? AND l.kind = 'desired-state'
		 ORDER BY l.id DESC LIMIT 1`,
		subject,
	).Scan(&observedAt, &payloadJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: get desired state: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: decode desired state: %w", err)
	}
	oa, _ := time.Parse(time.RFC3339Nano, observedAt)

	state := make(map[string]interface{}, len(payload))
	for k, v := range payload {
		if k != "config_revision" {
			state[k] = v
		}
	}
	return &types.DesiredStateView{
		EID:            eid,
		State:          state,
		ConfigRevision: extractString(payload, "config_revision"),
		ObservedAt:     oa,
	}, nil
}

// GetDriftState returns the current drift state for eid from
// eg_drift_projection. Returns a wrapped ErrNotFound when no drift record
// exists for this entity.
func (p *SQLiteEntityGraphProvider) GetDriftState(ctx context.Context, eid interfaces.EIDRef) (*interfaces.DriftState, error) {
	subject := eid.String()
	var detectedAt, configRevision, lifecycleStatus, fieldsData string
	err := p.db.QueryRowContext(ctx,
		`SELECT detected_at, config_revision, lifecycle_status, fields
		 FROM eg_drift_projection WHERE subject = ?`,
		subject,
	).Scan(&detectedAt, &configRevision, &lifecycleStatus, &fieldsData)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("entitygraph/sqlite: drift state for %s: %w", subject, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: get drift state: %w", err)
	}

	da, _ := time.Parse(time.RFC3339Nano, detectedAt)
	fields, err := parseDriftFields(fieldsData)
	if err != nil {
		return nil, err
	}
	return &interfaces.DriftState{
		EID:             eid,
		DetectedAt:      da,
		Fields:          fields,
		ConfigRevision:  configRevision,
		LifecycleStatus: normalizeDriftLifecycleStatus(lifecycleStatus),
	}, nil
}

// ListDrifted returns all drift states from eg_drift_projection matching the
// filter. Returns a non-nil empty slice when no records match.
func (p *SQLiteEntityGraphProvider) ListDrifted(ctx context.Context, filter interfaces.DriftFilter) ([]*interfaces.DriftState, error) {
	useEntityJoin := filter.TenantFilter != "" || filter.Kind != ""

	var conds []string
	var args []interface{}

	if filter.LifecycleStatus != "" {
		if useEntityJoin {
			conds = append(conds, "d.lifecycle_status = ?")
		} else {
			conds = append(conds, "lifecycle_status = ?")
		}
		args = append(args, filter.LifecycleStatus)
	}

	var query string
	if useEntityJoin {
		query = `SELECT d.subject, d.detected_at, d.config_revision, d.lifecycle_status, d.fields
				 FROM eg_drift_projection d
				 JOIN eg_entity_index i ON i.subject = d.subject`
		if filter.TenantFilter != "" {
			conds = append(conds, "(i.owning_tenant = ? OR i.owning_tenant LIKE ?)")
			args = append(args, filter.TenantFilter, filter.TenantFilter+"/%")
		}
		if filter.Kind != "" {
			conds = append(conds, "i.entity_kind = ?")
			args = append(args, filter.Kind)
		}
	} else {
		query = `SELECT subject, detected_at, config_revision, lifecycle_status, fields
				 FROM eg_drift_projection`
	}

	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: list drifted: %w", err)
	}
	defer func() { _ = rows.Close() }()

	states := make([]*interfaces.DriftState, 0)
	for rows.Next() {
		var subject, detectedAt, configRevision, lifecycleStatus, fieldsData string
		if err := rows.Scan(&subject, &detectedAt, &configRevision, &lifecycleStatus, &fieldsData); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan drift state: %w", err)
		}
		eid, err := types.ParseEID(subject)
		if err != nil {
			continue
		}
		da, _ := time.Parse(time.RFC3339Nano, detectedAt)
		fields, err := parseDriftFields(fieldsData)
		if err != nil {
			continue
		}
		states = append(states, &interfaces.DriftState{
			EID:             eid,
			DetectedAt:      da,
			Fields:          fields,
			ConfigRevision:  configRevision,
			LifecycleStatus: normalizeDriftLifecycleStatus(lifecycleStatus),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate drift states: %w", err)
	}
	return states, nil
}

// UpdateDriftLifecycle records a workflow lifecycle transition on a drift record.
// The transition is written to eg_observation_log tagged by actor (not a source
// provenance class) so it appears distinctly in GetHistory alongside state and
// drift-diff observations. The lifecycle_status in eg_drift_projection is updated
// atomically in the same transaction (ADR-022 §6).
func (p *SQLiteEntityGraphProvider) UpdateDriftLifecycle(ctx context.Context, update interfaces.DriftLifecycleUpdate) error {
	newStatus, err := transitionLifecycleStatus(update.Transition)
	if err != nil {
		return err
	}

	subject := update.EID.String()
	at := update.At
	if at.IsZero() {
		at = time.Now().UTC()
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: begin lifecycle tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var prevStatus string
	err = tx.QueryRowContext(ctx,
		`SELECT lifecycle_status FROM eg_drift_projection WHERE subject = ?`, subject,
	).Scan(&prevStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("entitygraph/sqlite: no drift record for %s: %w", subject, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: lookup drift record: %w", err)
	}

	lifecyclePayload := map[string]interface{}{
		"transition":  update.Transition,
		"actor":       update.Actor,
		"prev_status": normalizeDriftLifecycleStatus(prevStatus),
	}
	if update.Note != "" {
		lifecyclePayload["note"] = update.Note
	}

	payloadBytes, err := json.Marshal(lifecyclePayload)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: marshal lifecycle payload: %w", err)
	}
	sum := sha256.Sum256(payloadBytes)
	hash := hex.EncodeToString(sum[:])

	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO eg_payload_content(payload_hash, payload) VALUES(?, ?)`,
		hash, string(payloadBytes),
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: store lifecycle payload: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_observation_log
			(subject, source, source_class, observed_at, recorded_at, kind,
			 confidence, claim_scope_key, payload_hash, tenant_path)
		 VALUES(?, ?, '', ?, ?, 'lifecycle', '', '', ?, '')`,
		subject, update.Actor, rfc3339(at), rfc3339(at), hash,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: append lifecycle log: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE eg_drift_projection SET lifecycle_status = ? WHERE subject = ?`,
		newStatus, subject,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: update lifecycle status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entitygraph/sqlite: commit lifecycle: %w", err)
	}
	return nil
}
