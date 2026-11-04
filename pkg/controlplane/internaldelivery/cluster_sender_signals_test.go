// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package internaldelivery

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// The cluster sender delegates the tamper-state and repair signals to the local
// provider unchanged.
func TestClusterAwareSender_DelegatesTamperStateAndRepair(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() { _ = server.Stop(ctx) })
	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": "steward-cluster"}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() { _ = client.Stop(ctx) })

	var tamper []bool
	var repairs []controlplaneTypes.RepairRequest
	client.SetInboundHooks(controlplaneInterfaces.InboundHooks{
		OnTamperState: func(locked bool) { tamper = append(tamper, locked) },
		OnRepair:      func(r controlplaneTypes.RepairRequest) { repairs = append(repairs, r) },
	})

	sender := NewClusterAwareSender(server, "node-a", nil, nil, nil, logging.NewNoopLogger())
	require.NoError(t, sender.SendTamperState(ctx, "steward-cluster", true))
	req := controlplaneTypes.RepairRequest{RepairID: "r1", ApprovedLossCodes: []string{"x"}, Signature: []byte("s")}
	require.NoError(t, sender.SendRepair(ctx, "steward-cluster", req))

	assert.Equal(t, []bool{true}, tamper)
	require.Len(t, repairs, 1)
	assert.Equal(t, req, repairs[0])

	require.ErrorIs(t, sender.SendTamperState(ctx, "ghost", true), controlplaneInterfaces.ErrStewardNotConnected)
}
