// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	teststorage "github.com/cfgis/cfgms/pkg/testing/storage"
)

func newTestHAManager(t *testing.T, nodeID, externalAddr string) *ha.Manager {
	t.Helper()
	storageManager, err := teststorage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := ha.DefaultConfig()
	cfg.Mode = ha.SingleServerMode
	cfg.Node.ID = nodeID
	cfg.Node.ExternalAddress = externalAddr

	manager, err := ha.NewManager(cfg, logging.NewNoopLogger(), storageManager, nil, "")
	require.NoError(t, err)
	return manager
}

func TestHAClusterNodeResolver_ResolvesKnownNodeUsingLocalPort(t *testing.T) {
	manager := newTestHAManager(t, "node-a-0001", "10.0.0.5:7000")

	resolver, err := newHAClusterNodeResolver(manager, "0.0.0.0:9443", logging.NewNoopLogger())
	require.NoError(t, err)

	addr, ok := resolver.ResolveDeliveryAddr("node-a-0001")
	require.True(t, ok)
	// Host comes from the node's advertised HA address; port comes from this
	// node's own configured internal delivery listen address.
	assert.Equal(t, "10.0.0.5:9443", addr)
}

func TestHAClusterNodeResolver_UnknownNodeNotFound(t *testing.T) {
	manager := newTestHAManager(t, "node-a-0001", "10.0.0.5:7000")

	resolver, err := newHAClusterNodeResolver(manager, "0.0.0.0:9443", logging.NewNoopLogger())
	require.NoError(t, err)

	_, ok := resolver.ResolveDeliveryAddr("node-nonexistent-0002")
	assert.False(t, ok)
}

func TestNewHAClusterNodeResolver_RejectsListenAddrWithoutPort(t *testing.T) {
	manager := newTestHAManager(t, "node-a-0001", "10.0.0.5:7000")

	_, err := newHAClusterNodeResolver(manager, "not-a-host-port", logging.NewNoopLogger())
	require.Error(t, err)
}

func TestRoutingTableConnectHook_NilStoreIsNoop(t *testing.T) {
	hook := &routingTableConnectHook{routingStore: nil, logger: logging.NewNoopLogger(), localNodeID: "node-a-0001"}
	require.NoError(t, hook.OnConnect(context.Background(), "steward-1"))
}

func TestRoutingTableConnectHook_RecordsConnectionOnConnect(t *testing.T) {
	routingStore, err := flatfile.NewFlatFileRoutingStore(t.TempDir())
	require.NoError(t, err)

	hook := &routingTableConnectHook{routingStore: routingStore, logger: logging.NewNoopLogger(), localNodeID: "node-a-0001"}
	require.NoError(t, hook.OnConnect(context.Background(), "steward-1"))

	nodeID, ok, err := routingStore.LookupNode(context.Background(), "steward-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "node-a-0001", nodeID)
}
