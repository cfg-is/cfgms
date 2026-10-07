// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package internaldelivery

// NodeResolver resolves a controller node ID (as recorded by
// business.RoutingStore and reported by pkg/ha) to the address of that node's
// internal delivery gRPC listener. ClusterAwareSender uses this to dial the
// peer identified by a routing-table lookup.
//
// Implementations live outside this package (features/controller/server)
// because resolving a node ID to an address requires HA cluster membership
// knowledge this package does not have and must not depend on.
type NodeResolver interface {
	// ResolveDeliveryAddr returns the dial address (host:port) of nodeID's
	// internal delivery listener. ok is false when nodeID is not a known
	// cluster member, or its delivery address cannot be determined.
	ResolveDeliveryAddr(nodeID string) (addr string, ok bool)
}
