// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/features/steward/commands"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// NewReceivePathClient builds a TransportClient that runs only the command
// receive path (Raft-term fence, authenticated dispatch and rejection reporting)
// on an already-started client-mode control plane provider, and subscribes that
// path to cp. It performs no registration, data plane, heartbeat or config sync,
// so a controller-side test can exercise the real steward receive path against
// the in-process control plane provider without a network (Issue #4569).
func NewReceivePathClient(
	ctx context.Context,
	stewardID string,
	cp controlplaneInterfaces.ControlPlaneProvider,
	dispatch *commands.Handler,
	logger logging.Logger,
) (*TransportClient, error) {
	if stewardID == "" || cp == nil || dispatch == nil || logger == nil {
		return nil, fmt.Errorf("steward ID, control plane, command handler and logger are required")
	}
	c := &TransportClient{
		logger:       logger,
		stewardID:    stewardID,
		controlPlane: cp,
	}
	if err := cp.SubscribeCommands(ctx, stewardID, func(ctx context.Context, sc *cpTypes.SignedCommand) error {
		return c.receiveCommand(ctx, sc, dispatch.HandleCommand)
	}); err != nil {
		return nil, fmt.Errorf("subscribe to commands: %w", err)
	}
	return c, nil
}
