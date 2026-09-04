// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"sync"

	"github.com/cfgis/cfgms/features/controller/commands"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// PendingDeliveryDrainHook drains a reconnecting steward's durable outbox
// backlog (Issue #3757) immediately on connect, rather than waiting for some
// unrelated future dispatch to notice the pending row.
//
// Identity scoping (ADR-031 Decision 3, Issue #3764, Security review round 2):
// OnConnect's stewardID argument is the mTLS-authenticated CN of the
// connecting steward, supplied by the transport layer on every successful
// ControlChannel registration — never a value a client can otherwise choose.
// This hook resolves that steward's CURRENT tenant from stewardStore itself
// and passes both to CommandStore.ListPendingDeliveries, which further scopes
// by the steward's tenant chain. A steward reconnecting can therefore never
// trigger delivery of, or receive, another steward's pending rows: the ID it
// is scoped by is the one the mTLS handshake proved it is, not one it
// supplies in a request.
type PendingDeliveryDrainHook struct {
	commandStore business.CommandStore
	stewardStore business.StewardStore
	logger       logging.Logger

	mu        sync.RWMutex
	publisher *commands.Publisher
}

// NewPendingDeliveryDrainHook constructs the hook. publisher may be nil at
// construction time — commands.Publisher is constructed later in the same
// init-cycle break service.NewSigningRotationService's SetPublisher
// documents — and must be supplied via SetPublisher before this hook does
// anything; until then OnConnect is a no-op.
func NewPendingDeliveryDrainHook(commandStore business.CommandStore, stewardStore business.StewardStore, publisher *commands.Publisher, logger logging.Logger) *PendingDeliveryDrainHook {
	return &PendingDeliveryDrainHook{
		commandStore: commandStore,
		stewardStore: stewardStore,
		publisher:    publisher,
		logger:       logger,
	}
}

// SetPublisher injects the command publisher once it has been constructed.
func (h *PendingDeliveryDrainHook) SetPublisher(p *commands.Publisher) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publisher = p
}

func (h *PendingDeliveryDrainHook) currentPublisher() *commands.Publisher {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.publisher
}

// OnConnect implements the StewardOnConnectHook contract
// (OnConnect(ctx, stewardID) error).
func (h *PendingDeliveryDrainHook) OnConnect(ctx context.Context, stewardID string) error {
	if h == nil || h.commandStore == nil || h.stewardStore == nil {
		return nil
	}
	publisher := h.currentPublisher()
	if publisher == nil {
		return nil
	}

	record, err := h.stewardStore.GetSteward(ctx, stewardID)
	if err != nil || record == nil || record.TenantID == "" {
		// No resolvable tenant for this steward: ListPendingDeliveries requires
		// one and fails closed without it (business.ErrCommandTenantIDRequired).
		// Nothing can be drained safely, so this is not treated as an error.
		return nil
	}

	pending, err := h.commandStore.ListPendingDeliveries(ctx, stewardID, record.TenantID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("pending-delivery drain: failed to list pending deliveries",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return err
	}

	for _, rec := range pending {
		if rec == nil {
			continue
		}
		if _, pubErr := publisher.PublishCommand(ctx, stewardID, controlplaneTypes.CommandType(rec.Type), rec.Payload); pubErr != nil {
			if h.logger != nil {
				h.logger.Warn("pending-delivery drain: redelivery attempt failed, leaving pending",
					"steward_id", logging.SanitizeLogValue(stewardID),
					"command_id", logging.SanitizeLogValue(rec.ID),
					"error", logging.SanitizeLogValue(pubErr.Error()))
			}
			continue
		}
		if updErr := h.commandStore.UpdateDeliveryStatus(ctx, rec.ID, business.DeliveryStatusDelivered, ""); updErr != nil && h.logger != nil {
			h.logger.Warn("pending-delivery drain: failed to record delivered status",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"command_id", logging.SanitizeLogValue(rec.ID),
				"error", logging.SanitizeLogValue(updErr.Error()))
		}
	}
	return nil
}
