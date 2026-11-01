// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for the drift-diff record builder and the bounded accumulator (Issue #3373).
package driftdiff

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
)

// fieldsByAttribute indexes a record's field list for assertion.
func fieldsByAttribute(rec *commonpb.DriftDiffRecord) map[string]*commonpb.DriftDiffField {
	out := make(map[string]*commonpb.DriftDiffField, len(rec.Fields))
	for _, f := range rec.Fields {
		out[f.Attribute] = f
	}
	return out
}

// TestBuildRecord_AllFourFieldClassifications covers every branch of the field
// classification in one record: a changed field, an added field (desired only), a
// removed field (actual only), and a matching field.
//
// This is the core data transformation of the story: a misclassification here writes
// a wrong drift payload into the entity graph without any error surfacing.
func TestBuildRecord_AllFourFieldClassifications(t *testing.T) {
	diff := &stewardtesting.StateDiff{
		ResourceID: "service:sshd",
		DesiredMap: map[string]interface{}{
			"enabled": true,        // changed
			"user":    "sshd",      // added (absent from actual)
			"port":    float64(22), // matching
		},
		ChangedFields: map[string]stewardtesting.FieldDiff{
			"enabled": {Current: false, Desired: true},
		},
		AddedFields: map[string]interface{}{
			"user": "sshd",
		},
		RemovedFields: map[string]interface{}{
			"legacy_flag": "on", // present on the host, absent from the cfg
		},
	}

	rec := BuildRecord(diff, "cfg-v9")
	require.NotNil(t, rec)
	assert.Equal(t, "service:sshd", rec.FragmentID)
	assert.Equal(t, "cfg-v9", rec.ConfigRevision)
	assert.False(t, rec.DetectedAt.IsZero(), "DetectedAt must be stamped")
	require.Len(t, rec.Fields, 4, "every compared field must be present, matching included")

	byAttr := fieldsByAttribute(rec)

	changed := byAttr["enabled"]
	require.NotNil(t, changed)
	assert.Equal(t, true, changed.Desired, "changed field takes Desired from the FieldDiff")
	assert.Equal(t, false, changed.Actual, "changed field takes Actual from FieldDiff.Current")
	assert.False(t, changed.Matching)

	added := byAttr["user"]
	require.NotNil(t, added)
	assert.Equal(t, "sshd", added.Desired)
	assert.Nil(t, added.Actual, "an added field has no actual value")
	assert.False(t, added.Matching)

	removed := byAttr["legacy_flag"]
	require.NotNil(t, removed)
	assert.Nil(t, removed.Desired, "a removed field has no desired value")
	assert.Equal(t, "on", removed.Actual)
	assert.False(t, removed.Matching)

	matching := byAttr["port"]
	require.NotNil(t, matching)
	assert.Equal(t, float64(22), matching.Desired)
	assert.Equal(t, float64(22), matching.Actual)
	assert.True(t, matching.Matching, "a field in DesiredMap and in no delta map is matching")
}

// TestBuildRecord_MatchingFieldsIncluded asserts the "full compared field set"
// requirement directly: a resource where only one of three managed fields drifted
// still reports all three.
func TestBuildRecord_MatchingFieldsIncluded(t *testing.T) {
	diff := &stewardtesting.StateDiff{
		ResourceID: "file:/etc/hosts",
		DesiredMap: map[string]interface{}{
			"content": "expected",
			"mode":    "0644",
			"owner":   "root",
		},
		ChangedFields: map[string]stewardtesting.FieldDiff{
			"content": {Current: "actual", Desired: "expected"},
		},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{},
	}

	rec := BuildRecord(diff, "")
	require.NotNil(t, rec)
	require.Len(t, rec.Fields, 3)

	matching := 0
	for _, f := range rec.Fields {
		if f.Matching {
			matching++
		}
	}
	assert.Equal(t, 2, matching, "mode and owner are matching and must be reported")
}

// TestBuildRecord_NoDriftStillProducesFullFieldSet asserts a record built from a diff
// with no deltas reports every managed field as matching.
func TestBuildRecord_NoDriftStillProducesFullFieldSet(t *testing.T) {
	diff := &stewardtesting.StateDiff{
		ResourceID:    "service:cron",
		DesiredMap:    map[string]interface{}{"enabled": true, "state": "running"},
		ChangedFields: map[string]stewardtesting.FieldDiff{},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{},
	}

	rec := BuildRecord(diff, "rev-1")
	require.NotNil(t, rec)
	require.Len(t, rec.Fields, 2)
	for _, f := range rec.Fields {
		assert.True(t, f.Matching, "field %q must be matching", f.Attribute)
		assert.Equal(t, f.Desired, f.Actual)
	}
}

// TestBuildRecord_RejectsUnaddressableDiff asserts a diff that cannot be addressed to
// an entity-graph EID produces no record. The controller resolves the subject EID
// from FragmentID, so a record without one would be unroutable.
func TestBuildRecord_RejectsUnaddressableDiff(t *testing.T) {
	assert.Nil(t, BuildRecord(nil, "rev"), "a nil diff produces no record")

	noID := &stewardtesting.StateDiff{
		DesiredMap:    map[string]interface{}{"a": 1},
		ChangedFields: map[string]stewardtesting.FieldDiff{},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{},
	}
	assert.Nil(t, BuildRecord(noID, "rev"), "a diff with no ResourceID produces no record")
}

// TestBuildRecord_EmptyDesiredMapKeepsRemovedFields asserts that a resource whose
// managed fields are all actual-only still produces the removed entries, so an
// unpopulated DesiredMap cannot blank a record that has real content.
func TestBuildRecord_EmptyDesiredMapKeepsRemovedFields(t *testing.T) {
	diff := &stewardtesting.StateDiff{
		ResourceID:    "vm:orphan",
		DesiredMap:    nil,
		ChangedFields: map[string]stewardtesting.FieldDiff{},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{"stale": "value"},
	}

	rec := BuildRecord(diff, "rev-2")
	require.NotNil(t, rec)
	require.Len(t, rec.Fields, 1)
	assert.Equal(t, "stale", rec.Fields[0].Attribute)
	assert.Equal(t, "value", rec.Fields[0].Actual)
	assert.Nil(t, rec.Fields[0].Desired)
}

// ─── Accumulator ─────────────────────────────────────────────────────────────

func newRecord(id string) *commonpb.DriftDiffRecord {
	return &commonpb.DriftDiffRecord{FragmentID: id, DetectedAt: time.Now().UTC()}
}

// TestAccumulator_AppendDrainRoundTrip asserts records come back in append order and
// that a drain empties the buffer.
func TestAccumulator_AppendDrainRoundTrip(t *testing.T) {
	acc := NewAccumulator(8)
	acc.Append(newRecord("a"))
	acc.Append(newRecord("b"))
	assert.Equal(t, 2, acc.Len())

	records, dropped := acc.Drain()
	require.Len(t, records, 2)
	assert.Equal(t, "a", records[0].FragmentID)
	assert.Equal(t, "b", records[1].FragmentID)
	assert.Zero(t, dropped)
	assert.Equal(t, 0, acc.Len(), "a drain must empty the buffer")

	records, dropped = acc.Drain()
	assert.Empty(t, records, "a second drain returns nothing")
	assert.Zero(t, dropped)
}

// TestAccumulator_NilRecordIgnored asserts nil records never enter the buffer, so a
// drainer cannot be handed a nil element.
func TestAccumulator_NilRecordIgnored(t *testing.T) {
	acc := NewAccumulator(4)
	acc.Append(nil)
	assert.Equal(t, 0, acc.Len())
}

// TestAccumulator_BoundedDropOldest asserts the buffer never exceeds its capacity and
// that overflow discards the OLDEST records while counting every discard.
//
// This is the memory-exhaustion bound: the accumulator is drained only when the
// controller asks for a DNA sync, so a partitioned steward appends indefinitely.
func TestAccumulator_BoundedDropOldest(t *testing.T) {
	const capacity = 4
	acc := NewAccumulator(capacity)

	for i := 0; i < 10; i++ {
		acc.Append(newRecord(fmt.Sprintf("rec-%d", i)))
		require.LessOrEqual(t, acc.Len(), capacity, "the buffer must never exceed its capacity")
	}

	records, dropped := acc.Drain()
	require.Len(t, records, capacity)
	assert.Equal(t, uint64(6), dropped, "every discarded record must be counted")

	// Newest-wins: the retained window is the last `capacity` records.
	assert.Equal(t, "rec-6", records[0].FragmentID)
	assert.Equal(t, "rec-9", records[capacity-1].FragmentID)

	// The dropped counter resets with the drain, so the next report is per-cycle.
	acc.Append(newRecord("after"))
	records, dropped = acc.Drain()
	require.Len(t, records, 1)
	assert.Zero(t, dropped)
}

// TestAccumulator_ZeroValueIsBounded asserts the zero value is usable and bounded by
// DefaultCapacity, so a struct embedding an Accumulator by value cannot end up with an
// unbounded or silently-discarding buffer.
func TestAccumulator_ZeroValueIsBounded(t *testing.T) {
	var acc Accumulator
	assert.Equal(t, DefaultCapacity, acc.Capacity())

	for i := 0; i < DefaultCapacity+10; i++ {
		acc.Append(newRecord(fmt.Sprintf("rec-%d", i)))
	}
	assert.Equal(t, DefaultCapacity, acc.Len())

	records, dropped := acc.Drain()
	assert.Len(t, records, DefaultCapacity)
	assert.Equal(t, uint64(10), dropped)
}

// TestAccumulator_NegativeCapacityFallsBackToDefault asserts a caller cannot request
// an unbounded (or zero-length) accumulator.
func TestAccumulator_NegativeCapacityFallsBackToDefault(t *testing.T) {
	assert.Equal(t, DefaultCapacity, NewAccumulator(-1).Capacity())
	assert.Equal(t, DefaultCapacity, NewAccumulator(0).Capacity())
}

// TestAccumulator_ConcurrentAppendAndDrain is the race-detection test for the
// producer/consumer protocol: the convergence loop appends from module goroutines
// while the DNA send path drains. Run with -race.
//
// It asserts more than absence of a race: every record appended is accounted for
// exactly once, either drained or counted as dropped. A lost or duplicated record
// under concurrency would corrupt the controller's drift projection silently.
func TestAccumulator_ConcurrentAppendAndDrain(t *testing.T) {
	const (
		producers        = 8
		perProducer      = 250
		totalAppended    = producers * perProducer
		accumulatorLimit = 32 // small on purpose: forces overflow while draining
	)

	acc := NewAccumulator(accumulatorLimit)

	var producerWG sync.WaitGroup
	for p := 0; p < producers; p++ {
		producerWG.Add(1)
		go func(producer int) {
			defer producerWG.Done()
			for i := 0; i < perProducer; i++ {
				acc.Append(newRecord(fmt.Sprintf("p%d-r%d", producer, i)))
			}
		}(p)
	}

	// Consumer: drains in a loop, mirroring the SYNC_DNA send path, and performs one
	// final drain after the producers are done so nothing is left buffered.
	stop := make(chan struct{})
	type tally struct {
		drained int
		dropped uint64
	}
	result := make(chan tally, 1)
	go func() {
		var t tally
		for {
			select {
			case <-stop:
				recs, d := acc.Drain()
				t.drained += len(recs)
				t.dropped += d
				result <- t
				return
			default:
				recs, d := acc.Drain()
				t.drained += len(recs)
				t.dropped += d
			}
		}
	}()

	producerWG.Wait()
	close(stop)
	got := <-result

	// Exact accounting: every appended record is either handed to the consumer or
	// counted as an eviction — never lost silently, never counted twice.
	assert.Equal(t, totalAppended, got.drained+int(got.dropped),
		"every appended record must be either drained or counted as dropped")
	assert.Positive(t, got.drained, "the consumer must observe records")
	assert.Equal(t, 0, acc.Len(), "the buffer must be empty after the final drain")
}

// TestAccumulator_ConcurrentBuildAndAppend runs BuildRecord and Append together from
// several goroutines, which is the shape the executor produces: the drift handler is
// invoked from whichever goroutine is converging a resource. Run with -race.
func TestAccumulator_ConcurrentBuildAndAppend(t *testing.T) {
	acc := NewAccumulator(DefaultCapacity)

	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				diff := &stewardtesting.StateDiff{
					ResourceID: fmt.Sprintf("service:w%d-%d", worker, i),
					DesiredMap: map[string]interface{}{"enabled": true},
					ChangedFields: map[string]stewardtesting.FieldDiff{
						"enabled": {Current: false, Desired: true},
					},
					AddedFields:   map[string]interface{}{},
					RemovedFields: map[string]interface{}{},
				}
				acc.Append(BuildRecord(diff, "rev"))
			}
		}(g)
	}
	wg.Wait()

	records, dropped := acc.Drain()
	assert.Equal(t, 600, len(records)+int(dropped))
	for _, rec := range records {
		require.Len(t, rec.Fields, 1)
		assert.False(t, rec.Fields[0].Matching)
	}
}
