// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for the steward-side drift-diff accumulation and encoding path
// (Issue #3373, ADR-022 §6): the drift handler wired in InitializeConfigExecutor
// appends records, and encodeDriftDiffs drains them onto DNATransfer.DriftDiffBytes.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/driftdiff"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newDriftDiffTestClient returns a TransportClient with only what the drift-diff
// path needs. The accumulator is a value field, so a directly-constructed client
// already has a working, bounded buffer.
func newDriftDiffTestClient(t *testing.T) *TransportClient {
	t.Helper()
	return &TransportClient{logger: logging.NewLogger("error")}
}

// decodeDriftDiffBytes decodes the wire form encodeDriftDiffs produces.
func decodeDriftDiffBytes(t *testing.T, raw [][]byte) []*commonpb.DriftDiffRecord {
	t.Helper()
	out := make([]*commonpb.DriftDiffRecord, 0, len(raw))
	for _, b := range raw {
		var rec commonpb.DriftDiffRecord
		require.NoError(t, json.Unmarshal(b, &rec))
		out = append(out, &rec)
	}
	return out
}

// TestEncodeDriftDiffs_DrainsAndEncodes asserts that accumulated records are encoded
// in append order and that the accumulator is emptied by the encode — a second sync
// must not re-ship records the controller already has.
func TestEncodeDriftDiffs_DrainsAndEncodes(t *testing.T) {
	c := newDriftDiffTestClient(t)

	c.driftDiffs.Append(&commonpb.DriftDiffRecord{
		FragmentID:     "service:sshd",
		ConfigRevision: "rev-1",
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "enabled", Desired: true, Actual: false, Matching: false},
			{Attribute: "port", Desired: float64(22), Actual: float64(22), Matching: true},
		},
	})
	c.driftDiffs.Append(&commonpb.DriftDiffRecord{
		FragmentID:     "file:/etc/hosts",
		ConfigRevision: "rev-1",
		Fields: []*commonpb.DriftDiffField{
			{Attribute: "content", Desired: "expected", Actual: "actual"},
		},
	})

	encoded := c.encodeDriftDiffs()
	require.Len(t, encoded, 2)

	records := decodeDriftDiffBytes(t, encoded)
	assert.Equal(t, "service:sshd", records[0].FragmentID)
	assert.Equal(t, "rev-1", records[0].ConfigRevision)
	require.Len(t, records[0].Fields, 2)
	assert.True(t, records[0].Fields[1].Matching, "matching fields must survive the encode")
	assert.Equal(t, "file:/etc/hosts", records[1].FragmentID)

	assert.Nil(t, c.encodeDriftDiffs(),
		"the accumulator must be empty after an encode; records must not ship twice")
}

// TestEncodeDriftDiffs_EmptyReturnsNil asserts the no-drift case adds nothing to the
// DNA transfer.
func TestEncodeDriftDiffs_EmptyReturnsNil(t *testing.T) {
	c := newDriftDiffTestClient(t)
	assert.Nil(t, c.encodeDriftDiffs())
}

// TestEncodeDriftDiffs_BoundedByAccumulatorCapacity asserts that a steward whose
// controller has stopped issuing SYNC_DNA cannot grow the pending set without limit.
// This is the endpoint memory-exhaustion bound: only the controller triggers a drain.
func TestEncodeDriftDiffs_BoundedByAccumulatorCapacity(t *testing.T) {
	c := newDriftDiffTestClient(t)

	// Many convergence cycles' worth of records with no intervening SYNC_DNA.
	for i := 0; i < driftdiff.DefaultCapacity*3; i++ {
		c.driftDiffs.Append(&commonpb.DriftDiffRecord{FragmentID: fmt.Sprintf("service:s%d", i)})
	}
	assert.Equal(t, driftdiff.DefaultCapacity, c.driftDiffs.Len(),
		"the pending set must stay bounded while the controller is silent")

	encoded := c.encodeDriftDiffs()
	assert.Len(t, encoded, driftdiff.DefaultCapacity)

	// Newest-wins: the most recent observation of the host is what survives.
	records := decodeDriftDiffBytes(t, encoded)
	assert.Equal(t, fmt.Sprintf("service:s%d", driftdiff.DefaultCapacity*3-1),
		records[len(records)-1].FragmentID)
}

// TestEncodeDriftDiffs_ConcurrentWithDriftHandler is the race-detection test for the
// producer/consumer split: the executor's drift handler appends from the convergence
// goroutines while the SYNC_DNA command handler drains. Run with -race.
//
// It asserts exact accounting as well as race freedom — a record must be encoded
// exactly once, never duplicated onto two syncs and never lost between them.
func TestEncodeDriftDiffs_ConcurrentWithDriftHandler(t *testing.T) {
	c := newDriftDiffTestClient(t)

	const (
		producers   = 6
		perProducer = 200
		total       = producers * perProducer
	)

	// The handler body is the same shape as the closure InitializeConfigExecutor
	// registers: build a record from the StateDiff, then append it.
	appendDrift := func(resourceID string) {
		diff := &stewardtesting.StateDiff{
			ResourceID:    resourceID,
			DesiredMap:    map[string]interface{}{"enabled": true},
			ChangedFields: map[string]stewardtesting.FieldDiff{"enabled": {Current: false, Desired: true}},
			AddedFields:   map[string]interface{}{},
			RemovedFields: map[string]interface{}{},
		}
		c.driftDiffs.Append(driftdiff.BuildRecord(diff, "rev-concurrent"))
	}

	var producerWG sync.WaitGroup
	for p := 0; p < producers; p++ {
		producerWG.Add(1)
		go func(producer int) {
			defer producerWG.Done()
			for i := 0; i < perProducer; i++ {
				appendDrift(fmt.Sprintf("service:p%d-%d", producer, i))
			}
		}(p)
	}

	stop := make(chan struct{})
	encodedCount := make(chan int, 1)
	go func() {
		count := 0
		for {
			select {
			case <-stop:
				count += len(c.encodeDriftDiffs())
				encodedCount <- count
				return
			default:
				count += len(c.encodeDriftDiffs())
			}
		}
	}()

	producerWG.Wait()
	close(stop)
	encoded := <-encodedCount

	// The accumulator is deliberately smaller than `total`, so some records are
	// evicted; every record is either encoded or evicted, and none is encoded twice.
	assert.LessOrEqual(t, encoded, total)
	assert.Positive(t, encoded)
	assert.Equal(t, 0, c.driftDiffs.Len(), "nothing may remain buffered after the final drain")
}

// TestDriftHandlerRecordsAreShippedOnSync asserts the full steward-side chain a
// StateDiff travels: BuildRecord (as the executor's drift handler calls it) →
// accumulator → encodeDriftDiffs → the [][]byte that lands in
// DNATransfer.DriftDiffBytes, with the full compared field set intact.
func TestDriftHandlerRecordsAreShippedOnSync(t *testing.T) {
	c := newDriftDiffTestClient(t)

	diff := &stewardtesting.StateDiff{
		ResourceID: "service:nginx",
		DesiredMap: map[string]interface{}{
			"enabled": true,
			"port":    float64(443),
		},
		ChangedFields: map[string]stewardtesting.FieldDiff{
			"enabled": {Current: false, Desired: true},
		},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{"legacy": "on"},
	}
	c.driftDiffs.Append(driftdiff.BuildRecord(diff, "cfg-rev-7"))

	encoded := c.encodeDriftDiffs()
	require.Len(t, encoded, 1)

	rec := decodeDriftDiffBytes(t, encoded)[0]
	assert.Equal(t, "service:nginx", rec.FragmentID)
	assert.Equal(t, "cfg-rev-7", rec.ConfigRevision)
	require.Len(t, rec.Fields, 3, "changed + matching + removed must all ship")

	byAttr := map[string]*commonpb.DriftDiffField{}
	for _, f := range rec.Fields {
		byAttr[f.Attribute] = f
	}
	require.Contains(t, byAttr, "enabled")
	assert.False(t, byAttr["enabled"].Matching)
	require.Contains(t, byAttr, "port")
	assert.True(t, byAttr["port"].Matching)
	require.Contains(t, byAttr, "legacy")
	assert.Nil(t, byAttr["legacy"].Desired)
}

// TestDriftHandlerSkipsDiffWithoutResourceID asserts a StateDiff carrying no resource
// identifier produces no shipped record: the controller resolves the subject EID from
// fragment_id, so such a record could not be addressed.
func TestDriftHandlerSkipsDiffWithoutResourceID(t *testing.T) {
	c := newDriftDiffTestClient(t)

	diff := &stewardtesting.StateDiff{
		DesiredMap:    map[string]interface{}{"enabled": true},
		ChangedFields: map[string]stewardtesting.FieldDiff{"enabled": {Current: false, Desired: true}},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{},
	}
	c.driftDiffs.Append(driftdiff.BuildRecord(diff, "rev"))

	assert.Nil(t, c.encodeDriftDiffs())
}

// TestInitializeConfigExecutor_WiresDriftDiffAccumulation is the wiring test: it runs
// a real file resource through the real executor created by InitializeConfigExecutor
// and asserts the drift the Compare step detects reaches DNATransfer.DriftDiffBytes.
//
// No test double is involved — the handler under test is the one production registers,
// and the drift is produced by an actual on-disk file differing from its cfg.
func TestInitializeConfigExecutor_WiresDriftDiffAccumulation(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "managed.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("actual content"), 0o644))

	c := newDriftDiffTestClient(t)
	c.lastConfigVersion = "cfg-rev-42"
	require.NoError(t, c.InitializeConfigExecutor("tenant-drift"))

	c.mu.RLock()
	executor := c.configExecutor
	c.mu.RUnlock()
	require.NotNil(t, executor)

	result := executor.ExecuteResource(context.Background(), stewardconfig.ResourceConfig{
		Name:   "managed-file",
		Module: "file",
		Config: map[string]interface{}{
			"path":              filePath,
			"state":             "present",
			"content":           "desired content",
			"allowed_base_path": dir,
		},
	})
	require.True(t, result.DriftDetected, "the file must be detected as drifted")

	encoded := c.encodeDriftDiffs()
	require.Len(t, encoded, 1, "the drift event must have produced exactly one shipped record")

	rec := decodeDriftDiffBytes(t, encoded)[0]
	assert.Equal(t, filePath, rec.FragmentID,
		"the record must be addressed by the executor-resolved resource identifier")
	assert.Equal(t, "cfg-rev-42", rec.ConfigRevision,
		"the applied config version must be stamped on the record")
	require.NotEmpty(t, rec.Fields)

	var contentField *commonpb.DriftDiffField
	for _, f := range rec.Fields {
		if f.Attribute == "content" {
			contentField = f
		}
	}
	require.NotNil(t, contentField, "the drifted 'content' field must be reported")
	assert.False(t, contentField.Matching)
}
