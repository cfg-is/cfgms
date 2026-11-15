// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"errors"
	"sync"

	"github.com/cfgis/cfgms/features/controller/commands"
	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TransportAddressHook advertises the controller's configured transport address
// to a steward on every authenticated connect (Issue #6254), so a steward that
// registered earlier learns the cluster's current transport.external_address.
//
// The address comes from TransportConfig.ResolveAdvertisedAddress, the same
// helper registration and re-admission use, so both always return one value.
// The command is controller-originated and LockdownDenied: a locked-down
// steward refuses it, which this hook treats as expected, not as a failure.
type TransportAddressHook struct {
	transport *controllerconfig.TransportConfig
	logger    logging.Logger

	mu        sync.RWMutex
	publisher *commands.Publisher
}

// NewTransportAddressHook constructs the hook. publisher may be nil at
// construction time (commands.Publisher does not exist yet when the connect
// hooks are built, the same init-cycle break PendingDeliveryDrainHook
// documents) and must be supplied via SetPublisher; until then OnConnect is a
// no-op.
func NewTransportAddressHook(transport *controllerconfig.TransportConfig, publisher *commands.Publisher, logger logging.Logger) *TransportAddressHook {
	return &TransportAddressHook{transport: transport, publisher: publisher, logger: logger}
}

// SetPublisher injects the command publisher once it has been constructed. A
// nil receiver is a no-op: the hook is built only when a signer can exist, so
// the caller wires the publisher without a branch of its own.
func (h *TransportAddressHook) SetPublisher(p *commands.Publisher) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publisher = p
}

func (h *TransportAddressHook) currentPublisher() *commands.Publisher {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.publisher
}

// OnConnect implements the onConnectHook contract. stewardID is the
// mTLS-authenticated CN of the connecting steward. With no publisher or no
// transport config it does nothing. When the address cannot be resolved (a
// wildcard bind with no external address) it logs a warning and sends nothing.
// A locked-down steward's refusal is not an error; any other publish error is
// returned for the composite to log.
func (h *TransportAddressHook) OnConnect(ctx context.Context, stewardID string) error {
	if h == nil || h.transport == nil {
		return nil
	}
	publisher := h.currentPublisher()
	if publisher == nil {
		return nil
	}

	addr, err := h.transport.ResolveAdvertisedAddress()
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("transport address advertisement skipped: address not resolvable",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return nil
	}

	params := map[string]interface{}{controlplaneTypes.ParamTransportAddress: addr}
	if _, err := publisher.PublishCommand(ctx, stewardID, controlplaneTypes.CommandAdvertiseTransportAddress, params); err != nil {
		if errors.Is(err, controlplaneInterfaces.ErrStewardLockedDown) {
			return nil
		}
		return err
	}
	return nil
}
