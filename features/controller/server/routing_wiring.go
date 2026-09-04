// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"fmt"
	"net"

	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// routingTableConnectHook records a steward's connection ownership in the
// shared steward-routing table on every connect (ADR-031 Decision 3, Issue
// #3764). It implements the same OnConnect(ctx, stewardID) error contract as
// every other StewardOnConnectHook in the composite chain.
//
// A nil routingStore (no provider support, or a non-cluster deployment) makes
// OnConnect a no-op, so composing this hook unconditionally never changes
// connect behavior outside cluster mode.
type routingTableConnectHook struct {
	routingStore business.RoutingStore
	logger       logging.Logger
	localNodeID  string
}

// OnConnect implements the StewardOnConnectHook contract.
func (h *routingTableConnectHook) OnConnect(ctx context.Context, stewardID string) error {
	if h == nil || h.routingStore == nil {
		return nil
	}
	if err := h.routingStore.RecordConnection(ctx, stewardID, h.localNodeID); err != nil {
		if h.logger != nil {
			h.logger.Warn("internaldelivery: failed to record routing connection on connect",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return err
	}
	return nil
}

// haClusterNodeResolver implements internaldelivery.NodeResolver by combining
// pkg/ha's cluster membership (which knows every peer node's advertised host)
// with this node's own configured internal-delivery port.
//
// Simplifying assumption: every node in a deployment binds the internal
// delivery service on the SAME port (InternalDeliveryListenAddr's port),
// varying only by host — the same assumption pkg/ha itself makes for its own
// transport port. A deployment that needs per-node ports is out of scope for
// this story.
type haClusterNodeResolver struct {
	haManager *ha.Manager
	port      string
	logger    logging.Logger
}

// newHAClusterNodeResolver constructs a haClusterNodeResolver. localDeliveryListenAddr
// is THIS node's own configured internal delivery listen address
// (cfg.InternalDeliveryListenAddr); only its port is used, since a peer's
// advertised host comes from pkg/ha's cluster membership instead.
func newHAClusterNodeResolver(haManager *ha.Manager, localDeliveryListenAddr string, logger logging.Logger) (*haClusterNodeResolver, error) {
	_, port, err := net.SplitHostPort(localDeliveryListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid internal delivery listen address %q: %w", localDeliveryListenAddr, err)
	}
	return &haClusterNodeResolver{haManager: haManager, port: port, logger: logger}, nil
}

// ResolveDeliveryAddr implements internaldelivery.NodeResolver.
func (r *haClusterNodeResolver) ResolveDeliveryAddr(nodeID string) (string, bool) {
	if r.haManager == nil {
		return "", false
	}
	nodes, err := r.haManager.GetClusterNodes()
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("internaldelivery: failed to list cluster nodes for routing resolution",
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return "", false
	}
	for _, n := range nodes {
		if n == nil || n.ID != nodeID {
			continue
		}
		host := n.Address
		if h, _, splitErr := net.SplitHostPort(n.Address); splitErr == nil {
			host = h
		}
		if host == "" {
			return "", false
		}
		return net.JoinHostPort(host, r.port), true
	}
	return "", false
}
