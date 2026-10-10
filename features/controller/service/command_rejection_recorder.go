// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// fenceRetryWriteTimeout bounds the store write after a fence retry send.
const fenceRetryWriteTimeout = 10 * time.Second

// Rejection reason codes a steward may report (Issue #4569). The set is closed:
// the reason arrives from a possibly compromised steward, so anything outside it
// is ignored, and DeliveryDetail is always written from these constants rather
// than from the wire string.
const (
	RejectionTermFenced      = "term_fenced"
	RejectionUnauthenticated = "unauthenticated"
	RejectionWrongSteward    = "wrong_steward"
	RejectionStaleTimestamp  = "stale_timestamp"
	RejectionDuplicateID     = "duplicate_id"
	RejectionParamsTooLarge  = "params_too_large"
	RejectionInvalidCommand  = "invalid_command"
)

// knownRejectionReasons maps each accepted wire reason to the controller's own
// constant for it.
var knownRejectionReasons = map[string]string{
	RejectionTermFenced:      RejectionTermFenced,
	RejectionUnauthenticated: RejectionUnauthenticated,
	RejectionWrongSteward:    RejectionWrongSteward,
	RejectionStaleTimestamp:  RejectionStaleTimestamp,
	RejectionDuplicateID:     RejectionDuplicateID,
	RejectionParamsTooLarge:  RejectionParamsTooLarge,
	RejectionInvalidCommand:  RejectionInvalidCommand,
}

// FenceRetrier re-sends a command a steward rejected on its term fence
// (Issue #4866). *commands.Publisher satisfies it. RetryFenced only schedules
// the re-send and returns false once the command's retry budget is spent.
type FenceRetrier interface {
	RetryFenced(commandID, stewardID string, cmdType controlplaneTypes.CommandType, params map[string]interface{}, onSent func(attempt int, err error)) bool
}

// CommandRejectionRecorder records a steward's receive-path rejection of a
// command on the command's delivery record (Issue #4569): DeliveryStatus
// rejected and DeliveryDetail set to the reason code, except that a
// duplicate_id report means the steward already holds the command, so the
// record moves to delivered instead.
//
// Responses reach only the controller node holding the steward's stream; the
// command store is shared, so that node can update the record directly.
type CommandRejectionRecorder struct {
	store  business.CommandStore
	logger logging.Logger

	mu      sync.Mutex
	counts  map[string]int64
	retrier FenceRetrier
}

// SetRetrier enables bounded retry of retryable term_fenced rejections. It is
// set after construction because the publisher is built after the recorder.
func (r *CommandRejectionRecorder) SetRetrier(retrier FenceRetrier) {
	r.mu.Lock()
	r.retrier = retrier
	r.mu.Unlock()
}

func (r *CommandRejectionRecorder) getRetrier() FenceRetrier {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.retrier
}

// NewCommandRejectionRecorder constructs the recorder over a command store.
func NewCommandRejectionRecorder(store business.CommandStore, logger logging.Logger) *CommandRejectionRecorder {
	return &CommandRejectionRecorder{
		store:  store,
		logger: logger,
		counts: make(map[string]int64),
	}
}

// Subscribe registers the recorder on a server-mode control plane provider.
func (r *CommandRejectionRecorder) Subscribe(ctx context.Context, sub controlplaneInterfaces.ResponseSubscriber) error {
	if err := sub.SubscribeResponses(ctx, r.HandleResponse); err != nil {
		return fmt.Errorf("subscribe to steward responses: %w", err)
	}
	return nil
}

// RejectionCounts returns a snapshot of the per-reason counter. Unknown reasons
// and responses dropped by the ownership check are never counted.
func (r *CommandRejectionRecorder) RejectionCounts() map[string]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int64, len(r.counts))
	for k, v := range r.counts {
		out[k] = v
	}
	return out
}

// HandleResponse is the controlplane ResponseHandler. It never returns an error
// for a response it declines to act on.
func (r *CommandRejectionRecorder) HandleResponse(ctx context.Context, resp *controlplaneTypes.Response) error {
	if resp == nil || resp.Success || resp.CommandID == "" {
		return nil
	}

	wireReason := rejectionReasonOf(resp)
	reason, ok := knownRejectionReasons[wireReason]
	if !ok {
		r.logger.Warn("Ignoring command rejection with unknown reason",
			"command_id", logging.SanitizeLogValue(resp.CommandID),
			"steward_id", logging.SanitizeLogValue(resp.StewardID),
			"reason", logging.SanitizeLogValue(wireReason))
		return nil
	}

	rec, err := r.store.GetCommandRecord(ctx, resp.CommandID)
	if err != nil {
		if errors.Is(err, business.ErrCommandNotFound) {
			r.count(reason)
			r.logger.Debug("Command rejection for a command with no delivery record",
				"command_id", logging.SanitizeLogValue(resp.CommandID),
				"steward_id", logging.SanitizeLogValue(resp.StewardID),
				"reason", reason)
			return nil
		}
		return fmt.Errorf("load command record: %w", err)
	}

	// A steward may only mark its own records.
	if rec.StewardID != resp.StewardID {
		r.logger.Warn("Dropping command rejection from a steward that does not own the record",
			"command_id", logging.SanitizeLogValue(resp.CommandID),
			"response_steward_id", logging.SanitizeLogValue(resp.StewardID),
			"record_steward_id", logging.SanitizeLogValue(rec.StewardID))
		return nil
	}

	r.count(reason)

	if rec.DeliveryStatus != business.DeliveryStatusPending && rec.DeliveryStatus != business.DeliveryStatusDelivered {
		r.logger.Debug("Command rejection left record unchanged",
			"command_id", logging.SanitizeLogValue(resp.CommandID),
			"delivery_status", string(rec.DeliveryStatus),
			"reason", reason)
		return nil
	}

	// A term_fenced rejection the steward marked retryable is re-sent with a
	// freshly read term. Both the reason and the flag are required: the flag
	// comes from a steward that may be compromised.
	if retrier := r.getRetrier(); retrier != nil && reason == RejectionTermFenced && retryableOf(resp) {
		if retrier.RetryFenced(rec.ID, rec.StewardID, controlplaneTypes.CommandType(rec.Type), rec.Payload, r.fenceRetrySent(rec.ID)) {
			r.logger.Info("Retrying fence-rejected command with a fresh term",
				"command_id", logging.SanitizeLogValue(resp.CommandID),
				"steward_id", logging.SanitizeLogValue(resp.StewardID))
			return nil
		}
		r.logger.Warn("Fence retries exhausted; recording command as rejected",
			"command_id", logging.SanitizeLogValue(resp.CommandID),
			"steward_id", logging.SanitizeLogValue(resp.StewardID))
	}

	status := business.DeliveryStatusRejected
	if reason == RejectionDuplicateID {
		// The steward already holds this ID, so the command was delivered.
		status = business.DeliveryStatusDelivered
	}
	if err := r.store.UpdateDeliveryStatus(ctx, rec.ID, status, reason); err != nil {
		if errors.Is(err, business.ErrDeliveryStatusTerminal) || errors.Is(err, business.ErrCommandNotFound) {
			r.logger.Debug("Command rejection not recorded",
				"command_id", logging.SanitizeLogValue(resp.CommandID),
				"error", logging.SanitizeLogValue(err.Error()))
			return nil
		}
		return fmt.Errorf("record command rejection: %w", err)
	}

	r.logger.Warn("Steward rejected command",
		"command_id", logging.SanitizeLogValue(resp.CommandID),
		"steward_id", logging.SanitizeLogValue(resp.StewardID),
		"reason", reason,
		"delivery_status", string(status))
	return nil
}

// fenceRetrySent returns the onSent callback for one record's fence retries. It
// runs on the publisher's timer goroutine, so it uses its own context.
func (r *CommandRejectionRecorder) fenceRetrySent(recordID string) func(attempt int, err error) {
	return func(attempt int, sendErr error) {
		ctx, cancel := context.WithTimeout(context.Background(), fenceRetryWriteTimeout)
		defer cancel()

		status := business.DeliveryStatusDelivered
		detail := fmt.Sprintf("%s: delivered on retry %d", RejectionTermFenced, attempt)
		if sendErr != nil {
			// Back to pending so the on-connect drain picks it up.
			status = business.DeliveryStatusPending
			detail = logging.SanitizeLogValue(sendErr.Error())
		}
		if err := r.store.UpdateDeliveryStatus(ctx, recordID, status, detail); err != nil {
			if errors.Is(err, business.ErrDeliveryStatusTerminal) {
				r.logger.Debug("Fence retry outcome not recorded",
					"command_id", logging.SanitizeLogValue(recordID),
					"error", logging.SanitizeLogValue(err.Error()))
				return
			}
			r.logger.Warn("Failed to record fence retry outcome",
				"command_id", logging.SanitizeLogValue(recordID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}
}

func (r *CommandRejectionRecorder) count(reason string) {
	r.mu.Lock()
	r.counts[reason]++
	r.mu.Unlock()
}

// retryableOf reports whether the steward marked the rejection retryable.
func retryableOf(resp *controlplaneTypes.Response) bool {
	b, ok := resp.Details["retryable"].(bool)
	return ok && b
}

// rejectionReasonOf reads the reason code from Details["reason"], falling back
// to Message, which carries the same code by contract.
func rejectionReasonOf(resp *controlplaneTypes.Response) string {
	if s, ok := resp.Details["reason"].(string); ok && s != "" {
		return s
	}
	return resp.Message
}
