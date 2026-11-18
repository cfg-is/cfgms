// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// waitDeclared returns the controller-side connection once it has settled and
// requires it to have settled on a declaration, not on the floor.
func waitDeclared(t *testing.T, ctl *reportOnlyController, notConnectionID string) *registry.StewardConnection {
	t.Helper()
	var conn *registry.StewardConnection
	require.Eventually(t, func() bool {
		c, ok := ctl.reg.Get(reportOnlyStewardID)
		if ok && c.ConnectionID != notConnectionID {
			conn = c
			return true
		}
		return false
	}, 10*time.Second, 20*time.Millisecond, "steward should be connected")
	select {
	case <-conn.CapabilitiesSettled():
	case <-time.After(10 * time.Second):
		t.Fatal("the connection never settled")
	}
	return conn
}

func TestTransportClientDeclaresBuildCapabilitiesOnConnect(t *testing.T) {
	ctl := newReportOnlyController(t)
	start := time.Now()
	newReportOnlyClient(t, ctl, nil)

	conn := waitDeclared(t, ctl, "")
	// The controller's default grace is far longer than this: settling this
	// quickly means the declaration was the stream's first message, not a timeout.
	assert.Less(t, time.Since(start), grpcCP.DefaultCapabilityGrace, "declared before the grace could end")

	snap := conn.CapabilitySnapshot()
	assert.Equal(t, registry.CapabilityDeclared, snap.State)

	want := grpcCP.LocalCapabilities(reportOnlyStewardID)
	assert.Equal(t, want.CommandTypes, snap.CommandTypes)
	assert.Equal(t, cpTypes.SupportedSigningPayloadVersions(), snap.SigningPayloadVersions)
	assert.Contains(t, snap.SigningPayloadVersions, cpTypes.SigningPayloadV2, "this build verifies v2")
	assert.Contains(t, snap.CommandTypes, int32(15), "the build's newest command type is declared")
}

func TestTransportClientRedeclaresOnEveryReconnect(t *testing.T) {
	ctl := newReportOnlyController(t)
	newReportOnlyClient(t, ctl, nil)
	first := waitDeclared(t, ctl, "")

	// The controller ends the stream; the provider reconnects on its own and the
	// new stream starts with a declaration again.
	first.Evict(errors.New("test: controller ends the stream"))
	second := waitDeclared(t, ctl, first.ConnectionID)

	assert.NotEqual(t, first.ConnectionID, second.ConnectionID)
	assert.Equal(t, registry.CapabilityDeclared, second.CapabilitySnapshot().State)
	assert.Equal(t, first.CapabilitySnapshot().CommandTypes, second.CapabilitySnapshot().CommandTypes)
}

// declareCapture is a real in-memory control plane provider that records what a
// steward declares through it.
type declareCapture struct {
	*memory.Provider
	mu   sync.Mutex
	sent []*cpTypes.StewardCapabilities
	err  error
}

func (d *declareCapture) SendCapabilities(ctx context.Context, caps *cpTypes.StewardCapabilities) error {
	d.mu.Lock()
	d.sent = append(d.sent, caps)
	err := d.err
	d.mu.Unlock()
	if err != nil {
		return err
	}
	return d.Provider.SendCapabilities(ctx, caps)
}

func TestDeclareCapabilitiesOnInjectedProvider(t *testing.T) {
	c := newMinimalClient(t)

	bus := memory.NewBus()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(func() { _ = server.Stop(context.Background()) })
	clientCP := memory.New(memory.ModeClient)
	require.NoError(t, clientCP.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "steward_id": "steward-injected", "bus": bus,
	}))
	require.NoError(t, clientCP.Start(context.Background()))
	t.Cleanup(func() { _ = clientCP.Stop(context.Background()) })

	t.Run("a provider that can declare receives the build's capabilities", func(t *testing.T) {
		cp := &declareCapture{Provider: clientCP}
		c.declareCapabilities(context.Background(), cp, "steward-injected")

		cp.mu.Lock()
		defer cp.mu.Unlock()
		require.Len(t, cp.sent, 1)
		assert.Equal(t, grpcCP.LocalCapabilities("steward-injected"), *cp.sent[0])
	})

	t.Run("a failed declaration is tolerated", func(t *testing.T) {
		cp := &declareCapture{Provider: clientCP, err: errors.New("not connected")}
		c.declareCapabilities(context.Background(), cp, "steward-injected")
		cp.mu.Lock()
		defer cp.mu.Unlock()
		assert.Len(t, cp.sent, 1, "the send was attempted once and its failure did not propagate")
	})
}
