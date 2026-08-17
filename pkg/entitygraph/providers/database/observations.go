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

func init() {
	RegisterProjectionUpdater("entity", updateEntityProjection)
}

// canonicalJSON marshals a payload to a canonical JSON encoding. Go's
// encoding/json sorts map keys, so the output is stable for a given payload and
// suitable for content-addressed storage and hashing. A nil payload encodes as
// an empty object.
func canonicalJSON(payload map[string]interface{}) ([]byte, error) {
	if payload == nil {
		payload = map[string]interface{}{}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: marshal payload: %w", err)
	}
	return data, nil
}

// payloadHash returns the SHA-256 hex digest of the canonical JSON encoding of
// a payload. Identical payloads always hash to the same value.
func payloadHash(payload map[string]interface{}) (string, error) {
	data, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// subjectKind classifies an observation subject as "entity" or "edge". Entity
// subjects parse as valid EIDs; anything else (an edge identity string) is
// treated as an edge.
func subjectKind(subject string) string {
	if _, err := types.ParseEID(subject); err == nil {
		return "entity"
	}
	return "edge"
}

// subjectEntityKind derives the entity kind for an EID subject from its
// authority type. Returns "" for non-EID subjects.
func subjectEntityKind(subject string) string {
	eid, err := types.ParseEID(subject)
	if err != nil {
		return ""
	}
	return eid.AuthorityType()
}

// tenantPathOf extracts the owning tenant path from an observation payload,
// checking the conventional attribute keys. Returns "" when absent.
func tenantPathOf(obs types.Observation) string {
	if obs.Payload == nil {
		return ""
	}
	for _, k := range []string{"tenant_path", "owning_tenant"} {
		if v, ok := obs.Payload[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// ReportObservations ingests a batch of observations from one source. Each
// observation is appended to the immutable observation log, folded into the
// per-source current-state table, and dispatched to the registered projection
// updater — all inside a single transaction so partial batches never persist.
func (p *DatabaseEntityGraphProvider) ReportObservations(ctx context.Context, batch interfaces.ObservationBatch) error {
	if len(batch.Observations) == 0 && len(batch.ClaimScopes) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("entitygraph/database: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for i := range batch.Observations {
		obs := batch.Observations[i]
		if obs.Source == "" {
			obs.Source = batch.Source
		}
		if obs.Subject == "" {
			return fmt.Errorf("entitygraph/database: observation %d has empty subject", i)
		}

		sourceClass := string(resolveSourceClass(obs.Source))

		hash, err := payloadHash(obs.Payload)
		if err != nil {
			return err
		}

		// Content-hash dedup: a bit-identical re-observation from the same
		// source appends no new log row. The current-state row already carries
		// the winning hash for (subject, source).
		var existing string
		err = tx.QueryRowContext(ctx,
			`SELECT payload_hash FROM eg_entity_current WHERE subject = $1 AND source = $2`,
			obs.Subject, obs.Source).Scan(&existing)
		switch {
		case err == nil:
			if existing == hash {
				continue
			}
		case errors.Is(err, sql.ErrNoRows):
			// First observation for this (subject, source) — fall through.
		default:
			return fmt.Errorf("entitygraph/database: dedup lookup: %w", err)
		}

		payloadJSON, err := canonicalJSON(obs.Payload)
		if err != nil {
			return err
		}

		// Content-addressed payload: store once, dedup by hash.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO eg_payload_content (content_hash, payload_json)
			 VALUES ($1, $2)
			 ON CONFLICT (content_hash) DO NOTHING`,
			hash, string(payloadJSON)); err != nil {
			return fmt.Errorf("entitygraph/database: insert payload content: %w", err)
		}

		observedAt := obs.ObservedAt.UTC().Format(time.RFC3339Nano)
		recordedAt := obs.RecordedAt
		if recordedAt.IsZero() {
			recordedAt = time.Now()
		}
		recordedAtStr := recordedAt.UTC().Format(time.RFC3339Nano)
		tenantPath := tenantPathOf(obs)

		// Append to the immutable log and capture the assigned sequence id.
		var logSeq int64
		err = tx.QueryRowContext(ctx,
			`INSERT INTO eg_observation_log
				(subject, source, source_class, observed_at, recorded_at, kind, confidence, claim_scope_key, payload_hash, tenant_path)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			 RETURNING id`,
			obs.Subject, obs.Source, sourceClass, observedAt, recordedAtStr,
			string(obs.Kind), string(obs.Confidence), "", hash, tenantPath).Scan(&logSeq)
		if err != nil {
			return fmt.Errorf("entitygraph/database: append observation log: %w", err)
		}

		// Skip the entity_current upsert for observation kinds that do not state
		// the entity's current state: drift-diff and lifecycle project to
		// eg_drift_projection (ADR-022 §6), and apply-outcome projects nowhere.
		// A steward writes apply-outcome under the same (subject, source) pair as
		// its own state observations, so folding one in would overwrite that state
		// row and make rebuildEntityIndex recompute entity_kind and owning_tenant
		// from the apply payload — emptying owning_tenant, the sole access-control
		// axis. Apply-outcome is read from the observation log by GetHistory and
		// GetTimeline, which is appended above.
		if obs.Kind != types.ObservationKindDriftDiff &&
			obs.Kind != types.ObservationKindLifecycle &&
			obs.Kind != types.ObservationKindApplyOutcome {
			// Fold into per-source current state. The latest observation for the
			// same (subject, source) supersedes the prior one.
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO eg_entity_current
					(subject, source, source_class, kind, confidence, observed_at, recorded_at, payload_hash, tenant_path, log_seq)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
				 ON CONFLICT (subject, source) DO UPDATE SET
					source_class = EXCLUDED.source_class,
					kind         = EXCLUDED.kind,
					confidence   = EXCLUDED.confidence,
					observed_at  = EXCLUDED.observed_at,
					recorded_at  = EXCLUDED.recorded_at,
					payload_hash = EXCLUDED.payload_hash,
					tenant_path  = EXCLUDED.tenant_path,
					log_seq      = EXCLUDED.log_seq`,
				obs.Subject, obs.Source, sourceClass, string(obs.Kind), string(obs.Confidence),
				observedAt, recordedAtStr, hash, tenantPath, logSeq); err != nil {
				return fmt.Errorf("entitygraph/database: upsert current state: %w", err)
			}
		}

		if err := dispatchProjectionUpdate(ctx, tx, subjectKind(obs.Subject), obs, logSeq); err != nil {
			return fmt.Errorf("entitygraph/database: projection update: %w", err)
		}
	}

	if len(batch.ClaimScopes) > 0 {
		if err := processClaimScopes(ctx, tx, batch.Source, batch.ClaimScopes, batch.Observations); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entitygraph/database: commit: %w", err)
	}
	return nil
}

// updateEntityProjection rebuilds the entity index row for the observation's
// subject from the merged current state. Registered for the "entity" subject
// kind. Drift-diff and lifecycle observations route to eg_drift_projection.
// Desired-state observations project to eg_entity_current for dedup but must
// not contribute to the entity index. Apply-outcome observations enter neither
// projection — they are log-only event records.
func updateEntityProjection(ctx context.Context, tx *sql.Tx, obs types.Observation, _ int64) error {
	if obs.Kind == types.ObservationKindDriftDiff {
		return updateDriftProjectionFromObservation(ctx, tx, obs)
	}
	if obs.Kind == types.ObservationKindLifecycle {
		return applyLifecycleTransitionFromObs(ctx, tx, obs)
	}
	if obs.Kind == types.ObservationKindDesiredState || obs.Kind == types.ObservationKindApplyOutcome {
		return nil
	}
	return rebuildEntityIndex(ctx, tx, obs.Subject)
}

// rebuildEntityIndex recomputes the eg_entity_index row for subject by merging
// all per-source current-state payloads under the precedence rules and
// projecting the identity/lookup columns. When no current rows remain the index
// row is deleted.
func rebuildEntityIndex(ctx context.Context, tx *sql.Tx, subject string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT c.source, c.source_class, c.observed_at, c.payload_hash, p.payload_json
		 FROM eg_entity_current c
		 JOIN eg_payload_content p ON p.content_hash = c.payload_hash
		 WHERE c.subject = $1 AND c.kind != 'desired-state'`, subject)
	if err != nil {
		return fmt.Errorf("entitygraph/database: read current state: %w", err)
	}

	var entries []sourceEntry
	for rows.Next() {
		var src, sclass, observedAt, phash, pjson string
		if err := rows.Scan(&src, &sclass, &observedAt, &phash, &pjson); err != nil {
			_ = rows.Close()
			return fmt.Errorf("entitygraph/database: scan current state: %w", err)
		}
		var payload map[string]interface{}
		if pjson != "" {
			if err := json.Unmarshal([]byte(pjson), &payload); err != nil {
				_ = rows.Close()
				return fmt.Errorf("entitygraph/database: unmarshal payload: %w", err)
			}
		}
		t, _ := time.Parse(time.RFC3339Nano, observedAt)
		entries = append(entries, sourceEntry{
			source:      src,
			sourceClass: sclass,
			observedAt:  t,
			payloadHash: phash,
			payload:     payload,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("entitygraph/database: iterate current state: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("entitygraph/database: close current state rows: %w", err)
	}

	if len(entries) == 0 {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM eg_entity_index WHERE subject = $1`, subject); err != nil {
			return fmt.Errorf("entitygraph/database: delete stale index: %w", err)
		}
		return nil
	}

	merged := mergeAttributes(entries)

	entityKind := stringAttr(merged, "entity_kind", "kind")
	if entityKind == "" {
		entityKind = subjectEntityKind(subject)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_entity_index
			(subject, entity_kind, owning_tenant, hostname, mac_addrs, machine_sid, dir_object_guid, serial_number, cloud_object_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (subject) DO UPDATE SET
			entity_kind     = EXCLUDED.entity_kind,
			owning_tenant   = EXCLUDED.owning_tenant,
			hostname        = EXCLUDED.hostname,
			mac_addrs       = EXCLUDED.mac_addrs,
			machine_sid     = EXCLUDED.machine_sid,
			dir_object_guid = EXCLUDED.dir_object_guid,
			serial_number   = EXCLUDED.serial_number,
			cloud_object_id = EXCLUDED.cloud_object_id`,
		subject,
		entityKind,
		stringAttr(merged, "owning_tenant", "tenant_path"),
		stringAttr(merged, "hostname"),
		joinStrAttr(merged, "mac_addrs", "mac_addresses"),
		stringAttr(merged, "machine_sid"),
		stringAttr(merged, "dir_object_guid", "directory_object_guid"),
		stringAttr(merged, "serial_number"),
		stringAttr(merged, "cloud_object_id"),
	); err != nil {
		return fmt.Errorf("entitygraph/database: upsert entity index: %w", err)
	}
	return nil
}

// stringAttr returns the first non-empty string value found among the given
// attribute keys.
func stringAttr(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// joinStrAttr returns the first present attribute among keys as a comma-joined
// string, accepting a scalar string or a string/interface slice.
func joinStrAttr(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return t
			}
		case []string:
			if len(t) > 0 {
				return strings.Join(t, ",")
			}
		case []interface{}:
			parts := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok && s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, ",")
			}
		}
	}
	return ""
}
