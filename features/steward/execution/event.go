// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package execution

import (
	"fmt"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EventEmitter is implemented by components that receive convergence observation
// events from the Executor. Enqueue must never block the convergence goroutine —
// implementations drop when full and increment a counter (ADR-012 §2).
type EventEmitter interface {
	Enqueue(entry *transportpb.LogEntry)
}

// enqueueDetection emits a detection event before module.Get. The event is owned
// by the steward (not the module) and is enqueued on the out-of-band channel so
// a module hang still leaves the detection observable (ADR-012 §2 crash-isolation).
// A nil emitter is a no-op.
func (e *Executor) enqueueDetection(correlationID, resourceID, driftModeStr string) {
	if e.eventEmitter == nil {
		return
	}
	e.eventEmitter.Enqueue(&transportpb.LogEntry{
		StewardId:     e.stewardID,
		Level:         transportpb.Severity_SEVERITY_INFO,
		Message:       "convergence detection",
		Timestamp:     timestamppb.Now(),
		CorrelationId: correlationID,
		Fields: map[string]string{
			"event_kind":  "detection",
			"resource_id": resourceID,
			"drift_mode":  driftModeStr,
		},
	})
}

// enqueueTimeoutOutcome emits an outcome event when a per-resource module call
// (Get, Set, or verifyChanges) exceeds the configured deadline (ADR-012 §7).
// The event carries both the configured ceiling (timeout_ms) and the actual
// elapsed time (duration_ms) so the controller can distinguish timeout outcomes
// from other outcome types and observe proximity to the limit.
func (e *Executor) enqueueTimeoutOutcome(correlationID string, timeout, elapsed time.Duration) {
	if e.eventEmitter == nil {
		return
	}
	e.eventEmitter.Enqueue(&transportpb.LogEntry{
		StewardId:     e.stewardID,
		Level:         transportpb.Severity_SEVERITY_WARNING,
		Message:       "convergence outcome",
		Timestamp:     timestamppb.Now(),
		CorrelationId: correlationID,
		Fields: map[string]string{
			"event_kind":  "outcome",
			"action":      "did-not-finish(timeout)",
			"timeout_ms":  fmt.Sprintf("%d", timeout.Milliseconds()),
			"duration_ms": fmt.Sprintf("%d", elapsed.Milliseconds()),
		},
	})
}

// enqueueOutcome emits an outcome event when convergence completes, errors, or
// drift is reported without correction (monitor mode). A nil emitter is a no-op.
func (e *Executor) enqueueOutcome(correlationID, action string, duration time.Duration) {
	if e.eventEmitter == nil {
		return
	}
	e.eventEmitter.Enqueue(&transportpb.LogEntry{
		StewardId:     e.stewardID,
		Level:         transportpb.Severity_SEVERITY_INFO,
		Message:       "convergence outcome",
		Timestamp:     timestamppb.Now(),
		CorrelationId: correlationID,
		Fields: map[string]string{
			"event_kind":  "outcome",
			"action":      action,
			"duration_ms": fmt.Sprintf("%d", duration.Milliseconds()),
		},
	})
}
