// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/controller/health"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	convergenceSecondsMetric = "cfgms_config_convergence_seconds"
	applyFailedMetric        = "cfgms_config_apply_failed_total"

	// convergenceFailedMessage is the error text stored on a delivery row whose
	// apply failed. The steward-supplied failure text is deliberately not copied:
	// the command record is readable through the API.
	convergenceFailedMessage = "steward reported configuration apply failure"
)

// convergenceBuckets are the upper bounds, in seconds, of the convergence
// histogram: from a connected steward applying at once up to an hour for one
// that was offline and drained its queued delivery on reconnect.
var convergenceBuckets = []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600}

func init() { registerSignalSource(registerConvergenceSignals) }

// convergenceObservers holds the observer a signal source created for a Server.
// The Server struct carries no field for it: the observer is created by the
// source when the health collector's signals are registered and found again by
// handleEventFromProvider through observeConvergence.
var convergenceObservers sync.Map // *Server -> *convergenceObserver

// convergenceObserver measures how long a config push delivery takes from the
// controller issuing its delivery row to the steward reporting that command
// completed, and counts applies the steward reported as failed.
//
// The pushed version string does not round-trip to the steward (the steward
// reports its own config service version), but the command id does: a push
// delivery row is a sync_config command record with id <pushID>-<stewardID>, and
// the steward's completion event carries that id.
type convergenceObserver struct {
	logger logging.Logger
	// store resolves the command store at observe time; it returns nil when the
	// deployment has none.
	store func() business.CommandStore
	// now supplies the controller receipt time.
	now func() time.Time

	seconds *health.Histogram
	failed  *health.Counter

	// mu serializes the read-check-update of a delivery row, so two events for
	// the same command on this node record once. Across restarts and redeliveries
	// the durable terminal status on the row is the dedupe.
	mu sync.Mutex
}

// registerConvergenceSignals is the signal source for the convergence signals.
func registerConvergenceSignals(s *Server) error {
	reg := s.healthCollector.Signals()
	seconds, err := reg.RegisterHistogram(convergenceSecondsMetric,
		"Seconds from a config push delivery row being issued to the steward reporting its command completed.",
		convergenceBuckets, nil)
	if err != nil {
		return err
	}
	failed, err := reg.RegisterCounter(applyFailedMetric,
		"Config push deliveries the steward reported as failed to apply.", nil)
	if err != nil {
		return err
	}
	convergenceObservers.Store(s, &convergenceObserver{
		logger: s.logger,
		store: func() business.CommandStore {
			if s.storageManager == nil {
				return nil
			}
			return s.storageManager.GetCommandStore()
		},
		now:     time.Now,
		seconds: seconds,
		failed:  failed,
	})
	return nil
}

// observeConvergence hands a command completion or failure event to the
// Server's convergence observer. It does nothing when no observer was
// registered (no health collector) and never reports a failure to the caller.
func (s *Server) observeConvergence(ctx context.Context, event *controlplaneTypes.Event) {
	if o, ok := convergenceObservers.Load(s); ok {
		o.(*convergenceObserver).observe(ctx, event)
	}
}

// observe records one command completion or failure event. Only sync_config
// records carrying a push_id (push delivery rows) are measured; any other or
// unknown command id is ignored. The row is marked terminal first and recorded
// only if that is the transition out of a non-terminal status, so a duplicate
// event or an outbox redelivery, including after a restart, records nothing.
// The steward-supplied event timestamp is not used.
func (o *convergenceObserver) observe(ctx context.Context, event *controlplaneTypes.Event) {
	if event == nil || event.CommandID == "" {
		return
	}
	terminal, ok := terminalStatusForEvent(event.Type)
	if !ok {
		return
	}
	received := o.now()
	store := o.store()
	if store == nil {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	rec := o.openPushDelivery(ctx, store, event.CommandID)
	if rec == nil || !o.markTerminal(ctx, store, rec.ID, terminal) {
		return
	}
	o.record(rec, terminal, received)
}

// terminalStatusForEvent maps a command completion or failure event type to the
// terminal command status it sets.
func terminalStatusForEvent(t controlplaneTypes.EventType) (business.CommandStatus, bool) {
	switch t {
	case controlplaneTypes.EventCommandCompleted:
		return business.CommandStatusCompleted, true
	case controlplaneTypes.EventCommandFailed:
		return business.CommandStatusFailed, true
	}
	return "", false
}

// openPushDelivery returns the record for commandID when it is a push delivery
// row still in a non-terminal status, and nil for anything else (an unknown
// command, another command type, a row already terminal, a store error).
func (o *convergenceObserver) openPushDelivery(ctx context.Context, store business.CommandStore, commandID string) *business.CommandRecord {
	rec, err := store.GetCommandRecord(ctx, commandID)
	if err != nil {
		if !errors.Is(err, business.ErrCommandNotFound) {
			o.logger.Warn("Convergence observer could not read command record",
				"command_id", logging.SanitizeLogValue(commandID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return nil
	}
	if rec == nil || !isPushDelivery(rec) || isTerminalCommandStatus(rec.Status) {
		return nil
	}
	return rec
}

// markTerminal writes the terminal status and reports whether it was written.
// On failure nothing is recorded: the row is still non-terminal, so a
// redelivery retries.
func (o *convergenceObserver) markTerminal(ctx context.Context, store business.CommandStore, id string, terminal business.CommandStatus) bool {
	errMsg := ""
	if terminal == business.CommandStatusFailed {
		errMsg = convergenceFailedMessage
	}
	if err := store.UpdateCommandStatus(ctx, id, terminal, nil, errMsg); err != nil {
		o.logger.Warn("Convergence observer could not mark command terminal",
			"command_id", logging.SanitizeLogValue(id),
			"error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	return true
}

// record writes the signal for a delivery row that just became terminal.
func (o *convergenceObserver) record(rec *business.CommandRecord, terminal business.CommandStatus, received time.Time) {
	var err error
	if terminal == business.CommandStatusFailed {
		err = o.failed.Inc(nil)
	} else {
		// Issued time and receipt time can come from different nodes' clocks.
		err = o.seconds.Observe(max(received.Sub(rec.IssuedAt).Seconds(), 0), nil)
	}
	if err != nil {
		o.logger.Warn("Convergence observer could not record signal",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// isPushDelivery reports whether rec is a config push delivery row: a
// sync_config command whose payload names the push it belongs to.
func isPushDelivery(rec *business.CommandRecord) bool {
	if rec.Type != string(controlplaneTypes.CommandSyncConfig) {
		return false
	}
	pushID, _ := rec.Payload["push_id"].(string)
	return pushID != ""
}

func isTerminalCommandStatus(status business.CommandStatus) bool {
	switch status {
	case business.CommandStatusCompleted, business.CommandStatusFailed, business.CommandStatusCancelled:
		return true
	}
	return false
}
