// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package driftdiff builds and accumulates the managed-resource drift-diff records
// the steward ships to the controller on its next DNA sync (ADR-022 §6, Issue #3373).
//
// The package exists because the steward has two convergence engines that both
// observe managed-resource drift through the same execution.DriftEventHandler
// contract, and both must produce the identical record shape:
//
//   - features/steward.Steward — the standalone (cfg-file driven) engine. Its
//     onManagedResourceDrift handler records here; the accumulator is drained at the
//     end of every convergence pass, since standalone mode has no controller to sync to.
//   - features/steward/client.TransportClient — the controller-connected engine. Its
//     handler (registered in InitializeConfigExecutor) records here; the accumulator is
//     drained onto DNATransfer.DriftDiffBytes on each SYNC_DNA cycle.
//
// Keeping BuildRecord and Accumulator in one package is what stops those two paths
// from diverging into two record formats for the same event.
package driftdiff

import (
	"sync"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
)

// DefaultCapacity bounds how many drift-diff records one accumulator holds between
// drains.
//
// The bound is mandatory, not defensive tuning: records are produced by the local
// convergence loop (one per drifting resource per cycle) but drained only when the
// controller issues SYNC_DNA. A partitioned steward, or one whose controller has
// gone quiet, would otherwise grow this slice without limit for as long as the
// silence lasts — controller silence must never become endpoint memory exhaustion,
// least of all across a 50k-steward fleet.
//
// 1024 is above any realistic per-cycle drifting-resource count (a cfg with more
// managed resources than that is already past the steward's fragment budget, see
// execution/monitor.go maxModuleFragments), so a healthy steward never reaches it.
const DefaultCapacity = 1024

// Accumulator is a bounded, drop-oldest buffer of drift-diff records that is safe
// for concurrent use: the convergence loop appends while the DNA sync path drains.
//
// When the buffer is full, the OLDEST record is discarded to make room. Newest-wins
// is the right eviction policy here because a drift-diff record is a point-in-time
// observation of a resource's current state — the newest record for a resource
// supersedes any older one, so under pressure the retained window is the most
// current view of the host. Every discard increments a counter the drainer reports,
// so loss is always visible in the log rather than silent.
//
// The zero value is a ready-to-use accumulator bounded by DefaultCapacity, so a
// struct that embeds one by value cannot accidentally end up with an unbounded — or
// silently discarding — buffer. Do not copy an Accumulator after first use.
type Accumulator struct {
	mu sync.Mutex
	// capacity is the buffer bound; 0 means DefaultCapacity, which is what makes the
	// zero value safe.
	capacity int
	records  []*commonpb.DriftDiffRecord
	dropped  uint64
}

// NewAccumulator returns an accumulator holding at most capacity records.
// A capacity <= 0 selects DefaultCapacity — an unbounded accumulator is not
// constructible by design.
func NewAccumulator(capacity int) *Accumulator {
	if capacity < 0 {
		capacity = 0
	}
	return &Accumulator{capacity: capacity}
}

// Append adds a record to the buffer, evicting the oldest record and incrementing
// the dropped counter when the buffer is already at capacity. Nil records are
// ignored.
func (a *Accumulator) Append(rec *commonpb.DriftDiffRecord) {
	if a == nil || rec == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.records) >= a.effectiveCapacity() {
		// Drop-oldest: shift left in place so the backing array is reused rather
		// than reallocated on every append once the buffer is saturated.
		copy(a.records, a.records[1:])
		a.records[len(a.records)-1] = rec
		a.dropped++
		return
	}
	a.records = append(a.records, rec)
}

// Drain atomically removes and returns every buffered record, together with the
// number of records dropped since the previous drain. The caller owns the returned
// slice.
func (a *Accumulator) Drain() ([]*commonpb.DriftDiffRecord, uint64) {
	if a == nil {
		return nil, 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	records := a.records
	dropped := a.dropped
	a.records = nil
	a.dropped = 0
	return records, dropped
}

// Len reports how many records are currently buffered.
func (a *Accumulator) Len() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.records)
}

// Capacity reports the effective buffer bound.
func (a *Accumulator) Capacity() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.effectiveCapacity()
}

// effectiveCapacity resolves the zero value to DefaultCapacity. Callers hold a.mu.
func (a *Accumulator) effectiveCapacity() int {
	if a.capacity <= 0 {
		return DefaultCapacity
	}
	return a.capacity
}

// BuildRecord converts a convergence-loop StateDiff into the DriftDiffRecord shipped
// on the next DNA sync (ADR-022 §6, Issue #3373). It returns nil when the diff is nil
// or carries no resource identifier, since a record with no fragment_id cannot be
// resolved to an entity-graph EID on the controller side.
//
// The record carries the FULL compared field set — matching fields included, not just
// deltas — which is what lets the controller render "3 of 7 fields drifted" instead of
// only the drifted three. The set is reconstructed from StateDiff as follows:
//
//   - Changed: the attribute is in ChangedFields; desired/actual come from FieldDiff.
//   - Added (present in desired, absent from actual): the attribute is in AddedFields;
//     actual is nil.
//   - Removed (present in actual, absent from desired): the attribute is in
//     RemovedFields; desired is nil.
//   - Matching: the attribute is in DesiredMap and in none of the three maps above.
//
// DesiredMap is the managed desired-field map CompareStates populates; without it the
// matching fields cannot be recovered from StateDiff alone, because CompareStates only
// records the fields that differ.
func BuildRecord(diff *stewardtesting.StateDiff, configRevision string) *commonpb.DriftDiffRecord {
	if diff == nil || diff.ResourceID == "" {
		return nil
	}

	fields := make([]*commonpb.DriftDiffField, 0, len(diff.DesiredMap)+len(diff.RemovedFields))

	// Managed desired fields: changed, added, or matching.
	for attr, desiredVal := range diff.DesiredMap {
		switch {
		case hasChanged(diff, attr):
			fd := diff.ChangedFields[attr]
			fields = append(fields, &commonpb.DriftDiffField{
				Attribute: attr,
				Desired:   fd.Desired,
				Actual:    fd.Current,
				Matching:  false,
			})
		case hasAdded(diff, attr):
			fields = append(fields, &commonpb.DriftDiffField{
				Attribute: attr,
				Desired:   desiredVal,
				Actual:    nil,
				Matching:  false,
			})
		default:
			fields = append(fields, &commonpb.DriftDiffField{
				Attribute: attr,
				Desired:   desiredVal,
				Actual:    desiredVal,
				Matching:  true,
			})
		}
	}

	// Actual-only fields: present on the host, absent from the desired config.
	for attr, actualVal := range diff.RemovedFields {
		fields = append(fields, &commonpb.DriftDiffField{
			Attribute: attr,
			Desired:   nil,
			Actual:    actualVal,
			Matching:  false,
		})
	}

	return &commonpb.DriftDiffRecord{
		FragmentID:     diff.ResourceID,
		Fields:         fields,
		ConfigRevision: configRevision,
		DetectedAt:     time.Now().UTC(),
	}
}

func hasChanged(diff *stewardtesting.StateDiff, attr string) bool {
	_, ok := diff.ChangedFields[attr]
	return ok
}

func hasAdded(diff *stewardtesting.StateDiff, attr string) bool {
	_, ok := diff.AddedFields[attr]
	return ok
}
