// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// DriftFieldsJSON marshals the "fields" payload key as a JSON string. Returns
// "[]" when the key is absent or nil.
func DriftFieldsJSON(payload map[string]interface{}) (string, error) {
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

// ParseDriftFields decodes a JSON-encoded DriftField list from the storage
// column. Returns nil for empty or null values.
func ParseDriftFields(d Dialect, data string) ([]interfaces.DriftField, error) {
	if data == "" || data == "[]" || data == "null" {
		return nil, nil
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, fmt.Errorf("%s: parse drift fields: %w", d.Prefix, err)
	}
	fields := make([]interfaces.DriftField, 0, len(raw))
	for _, r := range raw {
		attribute, _ := r["attribute"].(string)
		f := interfaces.DriftField{Attribute: attribute}
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

// TransitionLifecycleStatus maps a lifecycle transition verb to the resulting
// status string. Returns an error for unrecognized transitions.
func TransitionLifecycleStatus(d Dialect, transition string) (string, error) {
	switch transition {
	case "acknowledge":
		return "acknowledged", nil
	case "resolve":
		return "resolved", nil
	case "ignore":
		return "ignored", nil
	default:
		return "", fmt.Errorf("%s: unknown lifecycle transition %q", d.Prefix, transition)
	}
}

// ScanDriftStates decodes rows of (subject, detected_at, config_revision,
// lifecycle_status, fields) into DriftStates. Rows whose subject or fields do
// not decode are skipped. normalizeStatus, when non-nil, maps the stored
// lifecycle status. It returns a non-nil empty slice when no row decodes. The
// caller closes rows.
func ScanDriftStates(rows *sql.Rows, d Dialect, normalizeStatus func(string) string) ([]*interfaces.DriftState, error) {
	states := make([]*interfaces.DriftState, 0)
	for rows.Next() {
		var subject, detectedAt, configRevision, lifecycleStatus, fieldsData string
		if err := rows.Scan(&subject, &detectedAt, &configRevision, &lifecycleStatus, &fieldsData); err != nil {
			return nil, fmt.Errorf("%s: scan drift state: %w", d.Prefix, err)
		}
		eid, err := types.ParseEID(subject)
		if err != nil {
			continue
		}
		da, _ := time.Parse(time.RFC3339Nano, detectedAt)
		fields, err := ParseDriftFields(d, fieldsData)
		if err != nil {
			continue
		}
		if normalizeStatus != nil {
			lifecycleStatus = normalizeStatus(lifecycleStatus)
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
		return nil, fmt.Errorf("%s: iterate drift states: %w", d.Prefix, err)
	}
	return states, nil
}

// LifecyclePayload builds the observation payload of a drift lifecycle
// transition and returns its JSON and content hash.
func LifecyclePayload(d Dialect, update interfaces.DriftLifecycleUpdate, prevStatus string) (payloadJSON, hash string, err error) {
	payload := map[string]interface{}{
		"transition":  update.Transition,
		"actor":       update.Actor,
		"prev_status": prevStatus,
	}
	if update.Note != "" {
		payload["note"] = update.Note
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("%s: marshal lifecycle payload: %w", d.Prefix, err)
	}
	sum := sha256.Sum256(b)
	return string(b), hex.EncodeToString(sum[:]), nil
}
