// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
)

func TestDriftFieldsJSON(t *testing.T) {
	got, err := DriftFieldsJSON(nil)
	require.NoError(t, err)
	require.Equal(t, "[]", got)

	got, err = DriftFieldsJSON(map[string]interface{}{"other": 1})
	require.NoError(t, err)
	require.Equal(t, "[]", got)

	got, err = DriftFieldsJSON(map[string]interface{}{"fields": []interface{}{map[string]interface{}{"attribute": "a"}}})
	require.NoError(t, err)
	require.JSONEq(t, `[{"attribute":"a"}]`, got)

	_, err = DriftFieldsJSON(map[string]interface{}{"fields": make(chan int)})
	require.ErrorContains(t, err, "marshal drift fields")
}

func TestParseDriftFields(t *testing.T) {
	d := Dialect{Prefix: "entitygraph/test"}
	for _, empty := range []string{"", "[]", "null"} {
		got, err := ParseDriftFields(d, empty)
		require.NoError(t, err)
		require.Nil(t, got)
	}

	got, err := ParseDriftFields(d, `[{"attribute":"mode","desired":"a","actual":"b","matching":true},{"attribute":7,"matching":"yes"}]`)
	require.NoError(t, err)
	require.Equal(t, []interfaces.DriftField{
		{Attribute: "mode", Desired: "a", Actual: "b", Matching: true},
		{},
	}, got)

	_, err = ParseDriftFields(d, `{bad`)
	require.ErrorContains(t, err, "entitygraph/test: parse drift fields")
}

func TestTransitionLifecycleStatus(t *testing.T) {
	d := Dialect{Prefix: "entitygraph/test"}
	for transition, want := range map[string]string{"acknowledge": "acknowledged", "resolve": "resolved", "ignore": "ignored"} {
		got, err := TransitionLifecycleStatus(d, transition)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	_, err := TransitionLifecycleStatus(d, "reopen")
	require.EqualError(t, err, `entitygraph/test: unknown lifecycle transition "reopen"`)
}

func TestScanDriftStates(t *testing.T) {
	db := openMemory(t)
	d := Dialect{Prefix: "entitygraph/test"}
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, `SELECT 'host:a', '2026-01-02T03:04:05Z', 'rev', '', '[{"attribute":"m","desired":1}]'
		UNION ALL SELECT 'not an eid', '', '', 'detected', '[]'
		UNION ALL SELECT 'host:b', '', '', 'detected', '{bad'
		UNION ALL SELECT 'host:c', '', '', 'resolved', 'null'`)
	require.NoError(t, err)
	got, err := ScanDriftStates(rows, d, func(s string) string {
		if s == "" {
			return "detected"
		}
		return s
	})
	_ = rows.Close()
	require.NoError(t, err)
	require.Len(t, got, 2, "rows with a bad subject or bad fields are skipped")
	require.Equal(t, "host:a", got[0].EID.String())
	require.Equal(t, "detected", got[0].LifecycleStatus)
	require.Equal(t, 2026, got[0].DetectedAt.Year())
	require.Equal(t, "rev", got[0].ConfigRevision)
	require.Len(t, got[0].Fields, 1)
	require.Equal(t, "resolved", got[1].LifecycleStatus)

	rows, err = db.QueryContext(ctx, `SELECT 'host:a', '', '', '', '[]' WHERE 0`)
	require.NoError(t, err)
	got, err = ScanDriftStates(rows, d, nil)
	_ = rows.Close()
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Empty(t, got)

	rows, err = db.QueryContext(ctx, `SELECT 'host:a'`)
	require.NoError(t, err)
	_, err = ScanDriftStates(rows, d, nil)
	_ = rows.Close()
	require.ErrorContains(t, err, "entitygraph/test: scan drift state")
}

func TestLifecyclePayload(t *testing.T) {
	d := Dialect{Prefix: "entitygraph/test"}
	update := interfaces.DriftLifecycleUpdate{Transition: "resolve", Actor: "op", At: time.Now()}

	payload, hash, err := LifecyclePayload(d, update, "detected")
	require.NoError(t, err)
	require.JSONEq(t, `{"transition":"resolve","actor":"op","prev_status":"detected"}`, payload)
	require.Len(t, hash, 64)

	update.Note = "done"
	withNote, noteHash, err := LifecyclePayload(d, update, "detected")
	require.NoError(t, err)
	require.JSONEq(t, `{"transition":"resolve","actor":"op","prev_status":"detected","note":"done"}`, withNote)
	require.NotEqual(t, hash, noteHash)

	_, again, err := LifecyclePayload(d, update, "detected")
	require.NoError(t, err)
	require.Equal(t, noteHash, again, "the hash is deterministic")
}
