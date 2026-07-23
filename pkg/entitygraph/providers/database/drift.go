// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

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
// drift-diff observation. ON CONFLICT preserves the existing lifecycle_status
// so that lifecycle annotations survive re-reports of the same entity's drift.
func updateDriftProjectionFromObservation(ctx context.Context, tx *sql.Tx, obs types.Observation) error {
	fieldsJSON, err := driftFieldsJSON(obs.Payload)
	if err != nil {
		return fmt.Errorf("entitygraph/database: encode drift fields: %w", err)
	}
	configRevision := stringAttr(obs.Payload, "config_revision")
	observedAt := obs.ObservedAt.UTC().Format(time.RFC3339Nano)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_drift_projection
			(subject, detected_at, config_revision, lifecycle_status, fields_json)
		 VALUES($1, $2, $3, 'detected', $4)
		 ON CONFLICT(subject) DO UPDATE SET
			detected_at     = EXCLUDED.detected_at,
			config_revision = EXCLUDED.config_revision,
			fields_json     = EXCLUDED.fields_json`,
		obs.Subject, observedAt, configRevision, fieldsJSON,
	); err != nil {
		return fmt.Errorf("entitygraph/database: upsert drift projection: %w", err)
	}
	return nil
}

// applyLifecycleTransitionFromObs updates eg_drift_projection.lifecycle_status
// from the transition field in a lifecycle observation's payload. Used by
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
		`UPDATE eg_drift_projection SET lifecycle_status = $1 WHERE subject = $2`,
		newStatus, obs.Subject,
	); err != nil {
		return fmt.Errorf("entitygraph/database: apply lifecycle transition: %w", err)
	}
	return nil
}

// driftFieldsJSON marshals the "fields" payload key as a JSON string. Returns
// "[]" when the key is absent or nil.
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
		return nil, fmt.Errorf("entitygraph/database: parse drift fields: %w", err)
	}
	fields := make([]interfaces.DriftField, 0, len(raw))
	for _, r := range raw {
		f := interfaces.DriftField{
			Attribute: stringAttr(r, "attribute"),
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
		return "", fmt.Errorf("entitygraph/database: unknown lifecycle transition %q", transition)
	}
}

// GetDesiredState returns the most-recent desired-state observation for eid,
// or (nil, nil) when no desired-state record exists yet (pre-STORY-9 state).
func (p *DatabaseEntityGraphProvider) GetDesiredState(ctx context.Context, eid interfaces.EIDRef) (*types.DesiredStateView, error) {
	subject := eid.String()
	var observedAt, payloadJSON string
	err := p.db.QueryRowContext(ctx,
		`SELECT l.observed_at, p.payload_json
		 FROM eg_observation_log l
		 JOIN eg_payload_content p ON p.content_hash = l.payload_hash
		 WHERE l.subject = $1 AND l.kind = 'desired-state'
		 ORDER BY l.id DESC LIMIT 1`,
		subject,
	).Scan(&observedAt, &payloadJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: get desired state: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return nil, fmt.Errorf("entitygraph/database: decode desired state: %w", err)
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
		ConfigRevision: stringAttr(payload, "config_revision"),
		ObservedAt:     oa,
	}, nil
}

// GetDriftState returns the current drift state for eid from
// eg_drift_projection. Returns a wrapped errNotFound when no drift record
// exists for this entity.
func (p *DatabaseEntityGraphProvider) GetDriftState(ctx context.Context, eid interfaces.EIDRef) (*interfaces.DriftState, error) {
	subject := eid.String()
	var detectedAt, configRevision, lifecycleStatus, fieldsData string
	err := p.db.QueryRowContext(ctx,
		`SELECT detected_at, config_revision, lifecycle_status, fields_json
		 FROM eg_drift_projection WHERE subject = $1`,
		subject,
	).Scan(&detectedAt, &configRevision, &lifecycleStatus, &fieldsData)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("entitygraph/database: drift state for %s: %w", subject, errNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: get drift state: %w", err)
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
		LifecycleStatus: lifecycleStatus,
	}, nil
}

// ListDrifted returns all drift states from eg_drift_projection matching the
// filter. Returns a non-nil empty slice when no records match.
func (p *DatabaseEntityGraphProvider) ListDrifted(ctx context.Context, filter interfaces.DriftFilter) ([]*interfaces.DriftState, error) {
	useEntityJoin := filter.TenantFilter != "" || filter.Kind != ""

	var conds []string
	var args []interface{}
	n := 1

	if filter.LifecycleStatus != "" {
		if useEntityJoin {
			conds = append(conds, fmt.Sprintf("d.lifecycle_status = $%d", n))
		} else {
			conds = append(conds, fmt.Sprintf("lifecycle_status = $%d", n))
		}
		args = append(args, filter.LifecycleStatus)
		n++
	}

	var query string
	if useEntityJoin {
		query = `SELECT d.subject, d.detected_at, d.config_revision, d.lifecycle_status, d.fields_json
				 FROM eg_drift_projection d
				 JOIN eg_entity_index i ON i.subject = d.subject`
		if filter.TenantFilter != "" {
			conds = append(conds, fmt.Sprintf("(i.owning_tenant = $%d OR i.owning_tenant LIKE $%d)", n, n+1))
			args = append(args, filter.TenantFilter, filter.TenantFilter+"/%")
			n += 2
		}
		if filter.Kind != "" {
			conds = append(conds, fmt.Sprintf("i.entity_kind = $%d", n))
			args = append(args, filter.Kind)
		}
	} else {
		query = `SELECT subject, detected_at, config_revision, lifecycle_status, fields_json
				 FROM eg_drift_projection`
	}

	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: list drifted: %w", err)
	}
	defer func() { _ = rows.Close() }()

	states := make([]*interfaces.DriftState, 0)
	for rows.Next() {
		var subject, detectedAt, configRevision, lifecycleStatus, fieldsData string
		if err := rows.Scan(&subject, &detectedAt, &configRevision, &lifecycleStatus, &fieldsData); err != nil {
			return nil, fmt.Errorf("entitygraph/database: scan drift state: %w", err)
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
			LifecycleStatus: lifecycleStatus,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/database: iterate drift states: %w", err)
	}
	return states, nil
}

// UpdateDriftLifecycle records a workflow lifecycle transition on a drift
// record. The transition is written to eg_observation_log tagged by actor and
// the lifecycle_status in eg_drift_projection is updated atomically in the
// same transaction (ADR-022 §6).
func (p *DatabaseEntityGraphProvider) UpdateDriftLifecycle(ctx context.Context, update interfaces.DriftLifecycleUpdate) error {
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
		return fmt.Errorf("entitygraph/database: begin lifecycle tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var prevStatus string
	err = tx.QueryRowContext(ctx,
		`SELECT lifecycle_status FROM eg_drift_projection WHERE subject = $1`, subject,
	).Scan(&prevStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("entitygraph/database: no drift record for %s: %w", subject, errNotFound)
	}
	if err != nil {
		return fmt.Errorf("entitygraph/database: lookup drift record: %w", err)
	}

	lifecyclePayload := map[string]interface{}{
		"transition":  update.Transition,
		"actor":       update.Actor,
		"prev_status": prevStatus,
	}
	if update.Note != "" {
		lifecyclePayload["note"] = update.Note
	}

	payloadBytes, err := json.Marshal(lifecyclePayload)
	if err != nil {
		return fmt.Errorf("entitygraph/database: marshal lifecycle payload: %w", err)
	}
	sum := sha256.Sum256(payloadBytes)
	hash := hex.EncodeToString(sum[:])

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_payload_content(content_hash, payload_json)
		 VALUES($1, $2)
		 ON CONFLICT(content_hash) DO NOTHING`,
		hash, string(payloadBytes),
	); err != nil {
		return fmt.Errorf("entitygraph/database: store lifecycle payload: %w", err)
	}

	observedAt := at.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_observation_log
			(subject, source, source_class, observed_at, recorded_at, kind,
			 confidence, claim_scope_key, payload_hash, tenant_path)
		 VALUES($1, $2, '', $3, $3, 'lifecycle', '', '', $4, '')`,
		subject, update.Actor, observedAt, hash,
	); err != nil {
		return fmt.Errorf("entitygraph/database: append lifecycle log: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE eg_drift_projection SET lifecycle_status = $1 WHERE subject = $2`,
		newStatus, subject,
	); err != nil {
		return fmt.Errorf("entitygraph/database: update lifecycle status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entitygraph/database: commit lifecycle: %w", err)
	}
	return nil
}
