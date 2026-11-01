// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

func TestHealthReasons_SetClearSorted(t *testing.T) {
	c := newMinimalClient(t)
	assert.Empty(t, c.HealthReasons())

	c.SetHealthReason("dna", "subsystem.pending", "m")
	c.SetHealthReason("controller", "subsystem.pending", "m")
	c.SetHealthReason("dna", "other", "replaced")

	got := c.HealthReasons()
	require.Len(t, got, 2)
	assert.Equal(t, "controller", got[0].Component)
	assert.Equal(t, cpTypes.HealthReason{Component: "dna", Code: "other", Message: "replaced"}, got[1])

	c.ClearHealthReason("controller")
	c.ClearHealthReason("absent")
	require.Len(t, c.HealthReasons(), 1)
}

func TestHeartbeatStatus_ReasonsForceDegraded(t *testing.T) {
	c := newMinimalClient(t)
	c.SetStatusFunc(func() string { return string(cpTypes.StatusHealthy) })
	assert.Equal(t, "healthy", c.heartbeatStatus())

	c.SetHealthReason("tls", "x.y", "m")
	assert.Equal(t, "degraded", c.heartbeatStatus())

	c.ClearHealthReason("tls")
	assert.Equal(t, "healthy", c.heartbeatStatus())
}

func TestHeartbeatStatus_ReasonsWithoutStatusFunc(t *testing.T) {
	c := newMinimalClient(t)
	c.SetHealthReason("tls", "x.y", "m")
	assert.Equal(t, "degraded", c.heartbeatStatus())
}

func TestHeartbeatStatus_ErrorKeptWithReasons(t *testing.T) {
	c := newMinimalClient(t)
	c.SetStatusFunc(func() string { return string(cpTypes.StatusError) })
	c.SetHealthReason("tls", "x.y", "m")
	assert.Equal(t, "error", c.heartbeatStatus())
}

func TestUseHealthReasons_SharesAndCarriesOver(t *testing.T) {
	c := newMinimalClient(t)
	c.SetHealthReason("early", "a", "m")

	shared := NewHealthReasonRegistry()
	shared.Set("controller", "subsystem.pending", "m")
	shared.Set("early", "b", "shared wins")
	c.UseHealthReasons(shared)
	c.UseHealthReasons(nil)

	got := c.HealthReasons()
	require.Len(t, got, 2)
	assert.Equal(t, "b", got[1].Code)

	shared.Clear("controller")
	assert.Len(t, c.HealthReasons(), 1, "client reads the shared registry")
}

func TestSendHeartbeat_CarriesReasons(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()

	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() { _ = server.Stop(context.Background()) })

	got := make(chan *cpTypes.Heartbeat, 1)
	require.NoError(t, server.SubscribeHeartbeats(ctx, func(_ context.Context, hb *cpTypes.Heartbeat) error {
		got <- hb
		return nil
	}))

	cp := memory.New(memory.ModeClient)
	require.NoError(t, cp.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": "steward-r"}))
	require.NoError(t, cp.Start(ctx))
	t.Cleanup(func() { _ = cp.Stop(context.Background()) })

	c := newMinimalClientWithCP(t, nil, nil, cp, "steward-r", "tenant-1")
	c.SetHealthReason("controller", "subsystem.pending", "subsystem not ready")

	require.NoError(t, c.SendHeartbeat(ctx, c.heartbeatStatus(), nil))

	select {
	case hb := <-got:
		assert.Equal(t, cpTypes.StatusDegraded, hb.Status)
		assert.Equal(t, []cpTypes.HealthReason{
			{Component: "controller", Code: "subsystem.pending", Message: "subsystem not ready"},
		}, hb.Reasons)
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat not received")
	}
}
