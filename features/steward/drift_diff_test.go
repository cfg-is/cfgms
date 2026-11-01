// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for the standalone steward's managed-resource drift-diff accumulation
// (Issue #3373, ADR-022 §6): onManagedResourceDrift no longer only logs — it also
// produces a DriftDiffRecord.
package steward_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	steward "github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/driftdiff"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newDriftTestSteward builds a real standalone steward from a minimal cfg.
func newDriftTestSteward(t *testing.T, id string) *steward.Steward {
	t.Helper()
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, id)
	s, err := steward.NewStandalone(cfgPath, logging.NewLogger("error"))
	require.NoError(t, err)
	steward.SetDNACollector(s, nil) // this file exercises managed-resource drift only
	return s
}

// TestOnManagedResourceDrift_ProducesDriftDiffRecord asserts the AC directly: the
// handler that previously only logged now also produces a DriftDiffRecord carrying
// the full compared field set and the config revision.
func TestOnManagedResourceDrift_ProducesDriftDiffRecord(t *testing.T) {
	s := newDriftTestSteward(t, "drift-record-steward")

	diff := &stewardtesting.StateDiff{
		ResourceID: "service:sshd",
		DesiredMap: map[string]interface{}{
			"enabled": true,
			"port":    float64(22),
		},
		ChangedFields: map[string]stewardtesting.FieldDiff{
			"enabled": {Current: false, Desired: true},
		},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{"legacy": "on"},
	}

	steward.OnManagedResourceDrift(s, "sshd-service", "service", diff)

	records := steward.PendingDriftDiffs(s)
	require.Len(t, records, 1, "the drift event must produce exactly one record")

	rec := records[0]
	assert.Equal(t, "service:sshd", rec.FragmentID)
	assert.Equal(t, steward.ConfigRevision(s), rec.ConfigRevision,
		"the record must be attributable to the cfg it was measured against")
	assert.True(t, strings.HasPrefix(rec.ConfigRevision, "sha256:"),
		"standalone config revision is the cfg content hash, got %q", rec.ConfigRevision)
	assert.False(t, rec.DetectedAt.IsZero())

	byAttr := map[string]*commonpb.DriftDiffField{}
	for _, f := range rec.Fields {
		byAttr[f.Attribute] = f
	}
	require.Len(t, byAttr, 3, "changed + matching + removed fields must all be carried")
	assert.False(t, byAttr["enabled"].Matching)
	assert.True(t, byAttr["port"].Matching, "matching fields must be included, not just deltas")
	assert.Nil(t, byAttr["legacy"].Desired, "an actual-only field carries no desired value")
}

// TestOnManagedResourceDrift_SkipsUnaddressableDiff asserts a diff with no resource
// identifier produces no record: the controller resolves the subject EID from
// fragment_id, so such a record could not be addressed.
func TestOnManagedResourceDrift_SkipsUnaddressableDiff(t *testing.T) {
	s := newDriftTestSteward(t, "drift-noid-steward")

	steward.OnManagedResourceDrift(s, "anon", "file", &stewardtesting.StateDiff{
		DesiredMap:    map[string]interface{}{"a": 1},
		ChangedFields: map[string]stewardtesting.FieldDiff{},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{},
	})

	assert.Empty(t, steward.PendingDriftDiffs(s))
}

// TestDriftDiffAccumulator_BoundedOnStandaloneSteward asserts the steward's buffer is
// bounded. Standalone drains every convergence pass, but the bound must hold even if
// a single pass produces more records than the buffer can carry.
func TestDriftDiffAccumulator_BoundedOnStandaloneSteward(t *testing.T) {
	s := newDriftTestSteward(t, "drift-bounded-steward")

	for i := 0; i < driftdiff.DefaultCapacity+25; i++ {
		steward.OnManagedResourceDrift(s, "res", "file", &stewardtesting.StateDiff{
			ResourceID:    "file:/tmp/f" + string(rune('a'+i%26)),
			DesiredMap:    map[string]interface{}{"content": "x"},
			ChangedFields: map[string]stewardtesting.FieldDiff{"content": {Current: "y", Desired: "x"}},
			AddedFields:   map[string]interface{}{},
			RemovedFields: map[string]interface{}{},
		})
	}

	assert.Equal(t, driftdiff.DefaultCapacity, steward.PendingDriftDiffCount(s),
		"the accumulator must never exceed its capacity")
}

// TestRunConvergence_DrainsDriftDiffAccumulator asserts the standalone terminus: a
// convergence pass empties the buffer, so records cannot accumulate across cycles in
// a mode that has no controller to ship them to.
func TestRunConvergence_DrainsDriftDiffAccumulator(t *testing.T) {
	s := newDriftTestSteward(t, "drift-drain-steward")

	steward.AppendDriftDiff(s, &commonpb.DriftDiffRecord{FragmentID: "service:leftover"})
	require.Equal(t, 1, steward.PendingDriftDiffCount(s))

	steward.RunConvergence(s, context.Background())

	assert.Equal(t, 0, steward.PendingDriftDiffCount(s),
		"a convergence pass must drain the accumulator")
}

// TestStandaloneConvergence_RealDriftProducesRecord is the end-to-end standalone test:
// a real file resource whose on-disk content differs from its cfg drives the real
// executor, and the drift the Compare step detects reaches the accumulator as a
// record — no test double anywhere in the path.
func TestStandaloneConvergence_RealDriftProducesRecord(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "managed.txt")
	require.NoError(t, os.WriteFile(managed, []byte("actual content"), 0o644))

	cfgData := `steward:
  id: drift-e2e-steward

resources:
  - name: managed-file
    module: file
    config:
      path: ` + managed + `
      state: present
      content: "desired content"
      allowed_base_path: ` + dir + `
`
	cfgPath := filepath.Join(dir, "test.cfg")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgData), 0o644))

	s, err := steward.NewStandalone(cfgPath, logging.NewLogger("error"))
	require.NoError(t, err)
	steward.SetDNACollector(s, nil)

	report, err := s.ExecuteConfiguration(context.Background())
	require.NoError(t, err)
	require.Positive(t, report.TotalResources)

	records := steward.PendingDriftDiffs(s)
	require.Len(t, records, 1, "the drifted file must produce one drift-diff record")
	assert.Equal(t, managed, records[0].FragmentID,
		"the record must be addressed by the executor-resolved resource identifier")
	assert.Equal(t, steward.ConfigRevision(s), records[0].ConfigRevision)

	var content *commonpb.DriftDiffField
	for _, f := range records[0].Fields {
		if f.Attribute == "content" {
			content = f
		}
	}
	require.NotNil(t, content, "the drifted 'content' field must be reported")
	assert.False(t, content.Matching)
}
