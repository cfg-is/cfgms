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

// init wires the entity projection updater. Edge and other subject kinds are
// registered by their own stories; a missing registration is a no-op.
func init() {
	RegisterProjectionUpdater("entity", updateEntityProjection)
}

// payloadHash returns the hex-encoded SHA-256 of the canonical JSON encoding of
// payload. Go's encoding/json marshals map keys in sorted order, so the
// encoding — and therefore the hash — is deterministic for a given payload.
// This is what makes a bit-identical re-observation produce the same hash and
// thus append no new log row.
func payloadHash(payload map[string]interface{}) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("entitygraph/sqlite: hash payload: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// subjectKind classifies an observation subject: "entity" if it parses as an
// EID, otherwise "edge".
func subjectKind(subject string) string {
	if _, err := types.ParseEID(subject); err == nil {
		return "entity"
	}
	return "edge"
}

// rfc3339 formats a timestamp for storage as a sortable TEXT column value.
func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ReportObservations ingests a batch of observations from one source. Each
// observation is content-hash-deduped, appended to the observation log, and
// projected into the current-state and index tables — all within a single
// transaction so a partial batch never leaves torn projections.
//
// When ClaimScopes is non-empty the provider also diffs the current enumeration
// against the prior-assertion set and retracts missing subjects (ADR-022 §4).
func (p *SQLiteEntityGraphProvider) ReportObservations(ctx context.Context, batch interfaces.ObservationBatch) error {
	if len(batch.Observations) == 0 && len(batch.ClaimScopes) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for i := range batch.Observations {
		obs := batch.Observations[i]
		if obs.Source == "" {
			obs.Source = batch.Source
		}
		if obs.Subject == "" {
			return fmt.Errorf("entitygraph/sqlite: observation %d has empty subject", i)
		}

		hash, err := payloadHash(obs.Payload)
		if err != nil {
			return err
		}

		// Content-hash dedup: a bit-identical re-observation from the same
		// source appends no new log row. The current-state row already
		// carries the winning hash for (subject, source).
		var existing string
		err = tx.QueryRowContext(ctx,
			`SELECT payload_hash FROM eg_entity_current WHERE subject = ? AND source = ?`,
			obs.Subject, obs.Source,
		).Scan(&existing)
		switch {
		case err == nil:
			if existing == hash {
				continue
			}
		case errors.Is(err, sql.ErrNoRows):
			// first observation for this (subject, source) — fall through
		default:
			return fmt.Errorf("entitygraph/sqlite: dedup lookup: %w", err)
		}

		payloadJSON, err := json.Marshal(obs.Payload)
		if err != nil {
			return fmt.Errorf("entitygraph/sqlite: marshal payload: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO eg_payload_content(payload_hash, payload) VALUES(?, ?)`,
			hash, string(payloadJSON),
		); err != nil {
			return fmt.Errorf("entitygraph/sqlite: insert payload: %w", err)
		}

		sc := resolveSourceClass(obs.Source)
		tenantPath := extractString(obs.Payload, "tenant_path")

		res, err := tx.ExecContext(ctx,
			`INSERT INTO eg_observation_log
				(subject, source, source_class, observed_at, recorded_at, kind, confidence, claim_scope_key, payload_hash, tenant_path)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			obs.Subject, obs.Source, string(sc),
			rfc3339(obs.ObservedAt), rfc3339(obs.RecordedAt),
			string(obs.Kind), string(obs.Confidence), "", hash, tenantPath,
		)
		if err != nil {
			return fmt.Errorf("entitygraph/sqlite: append log: %w", err)
		}
		logSeq, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("entitygraph/sqlite: log seq: %w", err)
		}

		if err := dispatchProjectionUpdate(ctx, tx, subjectKind(obs.Subject), obs, logSeq); err != nil {
			return fmt.Errorf("entitygraph/sqlite: projection update: %w", err)
		}
	}

	if len(batch.ClaimScopes) > 0 {
		if err := processClaimScopes(ctx, tx, batch.Source, batch.ClaimScopes, batch.Observations); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entitygraph/sqlite: commit: %w", err)
	}
	return nil
}

// updateEntityProjection is the "entity" subject-kind projection updater. It
// upserts the current-state row for (subject, source) with the new log
// sequence and rebuilds the entity index from all current sources.
// Absence observations retract the source's assertion instead of upserting.
// Drift-diff and lifecycle observations route to eg_drift_projection instead.
func updateEntityProjection(ctx context.Context, tx *sql.Tx, obs types.Observation, logSeq int64) error {
	if obs.Kind == types.ObservationKindDriftDiff {
		return updateDriftProjectionFromObservation(ctx, tx, obs)
	}
	if obs.Kind == types.ObservationKindLifecycle {
		return applyLifecycleTransitionFromObs(ctx, tx, obs)
	}
	if obs.Kind == types.ObservationKindAbsence {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM eg_entity_current WHERE subject = ? AND source = ?`, obs.Subject, obs.Source,
		); err != nil {
			return fmt.Errorf("entitygraph/sqlite: delete entity current for absence: %w", err)
		}
		return rebuildEntityIndex(ctx, tx, obs.Subject)
	}
	hash, err := payloadHash(obs.Payload)
	if err != nil {
		return err
	}
	sc := resolveSourceClass(obs.Source)
	tenantPath := extractString(obs.Payload, "tenant_path")

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_entity_current
			(subject, source, source_class, kind, confidence, observed_at, recorded_at, payload_hash, tenant_path, log_seq)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(subject, source) DO UPDATE SET
			source_class = excluded.source_class,
			kind         = excluded.kind,
			confidence   = excluded.confidence,
			observed_at  = excluded.observed_at,
			recorded_at  = excluded.recorded_at,
			payload_hash = excluded.payload_hash,
			tenant_path  = excluded.tenant_path,
			log_seq      = excluded.log_seq`,
		obs.Subject, obs.Source, string(sc), string(obs.Kind), string(obs.Confidence),
		rfc3339(obs.ObservedAt), rfc3339(obs.RecordedAt), hash, tenantPath, logSeq,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: upsert current: %w", err)
	}

	// Desired-state observations project to eg_entity_current for content-hash
	// dedup (so re-ingesting an identical revision is a no-op) but must not
	// contribute to the entity index — GetDesiredState reads the log directly.
	if obs.Kind == types.ObservationKindDesiredState {
		return nil
	}

	return rebuildEntityIndex(ctx, tx, obs.Subject)
}

// rebuildEntityIndex recomputes the eg_entity_index row for subject from all of
// its current sources, applying source precedence. Kind and owning tenant are
// taken from the winning (highest-precedence) source; identity fields are taken
// from the precedence-merged attribute set so a lower-precedence source can
// still contribute an identity claim the winner omitted.
func rebuildEntityIndex(ctx context.Context, tx *sql.Tx, subject string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT c.source, c.source_class, c.observed_at, c.payload_hash, p.payload
		 FROM eg_entity_current c
		 JOIN eg_payload_content p ON p.payload_hash = c.payload_hash
		 WHERE c.subject = ? AND c.kind != 'desired-state'`,
		subject,
	)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: load current sources: %w", err)
	}

	var entries []sourceEntry
	for rows.Next() {
		var source, sourceClass, observedAt, hash, payloadJSON string
		if err := rows.Scan(&source, &sourceClass, &observedAt, &hash, &payloadJSON); err != nil {
			_ = rows.Close()
			return fmt.Errorf("entitygraph/sqlite: scan current source: %w", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
			_ = rows.Close()
			return fmt.Errorf("entitygraph/sqlite: decode payload: %w", err)
		}
		t, _ := time.Parse(time.RFC3339Nano, observedAt)
		entries = append(entries, sourceEntry{
			source:      source,
			sourceClass: sourceClass,
			observedAt:  t,
			payloadHash: hash,
			payload:     payload,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("entitygraph/sqlite: iterate current sources: %w", err)
	}
	_ = rows.Close()

	// No live sources (e.g. after a retraction): remove the index entry.
	if len(entries) == 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM eg_entity_index WHERE subject = ?`, subject); err != nil {
			return fmt.Errorf("entitygraph/sqlite: clear index: %w", err)
		}
		return nil
	}

	win := entries[winningSourceIdx(entries)].payload
	merged := mergeAttributes(entries)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_entity_index
			(subject, entity_kind, owning_tenant, hostname, mac_addrs, machine_sid, dir_object_guid, serial_number, cloud_object_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(subject) DO UPDATE SET
			entity_kind     = excluded.entity_kind,
			owning_tenant   = excluded.owning_tenant,
			hostname        = excluded.hostname,
			mac_addrs       = excluded.mac_addrs,
			machine_sid     = excluded.machine_sid,
			dir_object_guid = excluded.dir_object_guid,
			serial_number   = excluded.serial_number,
			cloud_object_id = excluded.cloud_object_id`,
		subject,
		extractString(win, "entity_kind"),
		extractString(win, "owning_tenant"),
		extractString(merged, "hostname"),
		extractStringList(merged, "mac_addrs"),
		extractString(merged, "machine_sid"),
		extractString(merged, "dir_object_guid"),
		extractString(merged, "serial_number"),
		extractString(merged, "cloud_object_id"),
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: upsert index: %w", err)
	}
	return nil
}

// extractString returns m[key] as a string, or "" if absent or not a string.
func extractString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// extractStringList returns m[key] as a comma-joined string, accepting a
// []string, a []interface{} of strings, or a bare string.
func extractStringList(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch vv := v.(type) {
	case []string:
		return strings.Join(vv, ",")
	case []interface{}:
		parts := make([]string, 0, len(vv))
		for _, e := range vv {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	case string:
		return vv
	default:
		return ""
	}
}
