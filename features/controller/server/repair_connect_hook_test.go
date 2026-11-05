// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestRepairConnectHook_UnboundDoesNothing(t *testing.T) {
	h := &repairConnectHook{logger: logging.NewNoopLogger()}
	assert.NoError(t, h.OnConnect(context.Background(), "steward-1"), "no API server is bound yet")
}

func TestBindRepairDelivery_NoTransportBindsNothing(t *testing.T) {
	h := &repairConnectHook{logger: logging.NewNoopLogger()}
	// Without a control plane and lockdown predicate there is nothing to deliver
	// over: the hook stays unbound and connects are not affected.
	bindRepairDelivery(nil, h, nil, nil, nil, (*commands.SignerChainBuilder)(nil))
	require.Nil(t, h.target.Load())
	assert.NoError(t, h.OnConnect(context.Background(), "steward-1"))
}
