// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package internaldelivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	deliverypb "github.com/cfgis/cfgms/api/proto/clusterdelivery"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcconvert "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ClusterAwareSender wraps a node-local controlplaneInterfaces.ControlPlaneProvider
// and adds a cluster dispatch fallback (ADR-031 Decision 3, Issue #3764): when
// a SendCommand/FanOutCommand call fails because the target steward is not
// connected to this node, it consults the shared steward-routing table for a
// peer node holding the connection and forwards the command to that peer's
// internal delivery RPC.
//
// Every other method delegates unchanged to the wrapped local provider —
// ClusterAwareSender only ever changes command delivery, never event
// subscription, heartbeats, or lifecycle.
//
// Forwarding is a best-effort fast path, never a hard requirement: any
// failure to resolve or reach a peer returns the ORIGINAL local
// "not connected" error, so the caller (commands.Publisher /
// dispatcher.Dispatcher) falls back to its normal durable-outbox retry path
// (Issue #3757) exactly as it would without cluster mode. A forwarding
// failure is therefore never surfaced as a harder error than the local
// failure it is trying to route around.
type ClusterAwareSender struct {
	local        controlplaneInterfaces.ControlPlaneProvider
	localNodeID  string
	routingStore business.RoutingStore
	resolver     NodeResolver
	tlsConfig    *tls.Config
	logger       logging.Logger

	mu    sync.Mutex
	conns map[string]*grpc.ClientConn // keyed by dial address
}

// Compile-time assertion.
var _ controlplaneInterfaces.ControlPlaneProvider = (*ClusterAwareSender)(nil)

// NewClusterAwareSender constructs a ClusterAwareSender. local is the
// node-local control-plane provider that already handles direct steward
// connections; localNodeID identifies this node so a routing-table lookup
// that resolves to ourselves is never forwarded back to ourselves.
func NewClusterAwareSender(
	local controlplaneInterfaces.ControlPlaneProvider,
	localNodeID string,
	routingStore business.RoutingStore,
	resolver NodeResolver,
	tlsConfig *tls.Config,
	logger logging.Logger,
) *ClusterAwareSender {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &ClusterAwareSender{
		local:        local,
		localNodeID:  localNodeID,
		routingStore: routingStore,
		resolver:     resolver,
		tlsConfig:    tlsConfig,
		logger:       logger,
		conns:        make(map[string]*grpc.ClientConn),
	}
}

// SendCommand implements controlplaneInterfaces.ControlPlaneProvider.SendCommand.
func (c *ClusterAwareSender) SendCommand(ctx context.Context, cmd *types.SignedCommand) error {
	err := c.local.SendCommand(ctx, cmd)
	if err == nil {
		return nil
	}
	if !errors.Is(err, controlplaneInterfaces.ErrStewardNotConnected) {
		return err
	}
	if fwdErr := c.forwardToPeer(ctx, cmd); fwdErr == nil {
		return nil
	}
	// Forwarding did not succeed (no routing entry, peer unreachable, peer
	// also doesn't have the steward, etc.) — return the ORIGINAL local error
	// so the caller's existing outbox fallback behavior is unchanged.
	return err
}

// FanOutCommand implements controlplaneInterfaces.ControlPlaneProvider.FanOutCommand.
// Every steward the local provider could not reach is retried individually
// through the cluster-aware SendCommand path (fleet-wide fan-out composes
// both primitives, per ADR-031 Decision 3).
func (c *ClusterAwareSender) FanOutCommand(ctx context.Context, cmd *types.SignedCommand, stewardIDs []string) (*types.FanOutResult, error) {
	result, err := c.local.FanOutCommand(ctx, cmd, stewardIDs)
	if err != nil || result == nil {
		return result, err
	}

	for stewardID, ferr := range result.Failed {
		if !errors.Is(ferr, controlplaneInterfaces.ErrStewardNotConnected) {
			continue
		}
		perSteward := *cmd
		perSteward.Command.StewardID = stewardID
		if fwdErr := c.forwardToPeer(ctx, &perSteward); fwdErr == nil {
			delete(result.Failed, stewardID)
			result.Succeeded = append(result.Succeeded, stewardID)
		}
	}
	return result, nil
}

// forwardToPeer consults the shared routing table for cmd's target steward
// and, if a peer node holds the connection, forwards the command to that
// peer's internal delivery RPC. Returns a non-nil error for every case the
// caller should fall back to the outbox on: no routing store configured, no
// record, a stale/self record, an unresolvable peer address, or an RPC/local
// delivery failure at the peer.
func (c *ClusterAwareSender) forwardToPeer(ctx context.Context, cmd *types.SignedCommand) error {
	if c.routingStore == nil || c.resolver == nil {
		return fmt.Errorf("internaldelivery: no cluster routing configured")
	}
	stewardID := cmd.Command.StewardID
	if stewardID == "" {
		return fmt.Errorf("internaldelivery: command has no steward_id to route")
	}

	nodeID, ok, err := c.routingStore.LookupNode(ctx, stewardID)
	if err != nil {
		return fmt.Errorf("internaldelivery: routing lookup failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("internaldelivery: no routing entry for steward %s", stewardID)
	}
	if nodeID == c.localNodeID {
		// The routing table says we hold this steward, but the local provider
		// just told us otherwise (disconnect race). Forwarding to ourselves
		// would recurse into the same failure.
		return fmt.Errorf("internaldelivery: routing table points back to local node")
	}

	addr, ok := c.resolver.ResolveDeliveryAddr(nodeID)
	if !ok {
		return fmt.Errorf("internaldelivery: no delivery address for node %s", nodeID)
	}

	conn, err := c.dial(addr)
	if err != nil {
		return fmt.Errorf("internaldelivery: failed to dial node %s: %w", nodeID, err)
	}

	client := deliverypb.NewDeliveryServiceClient(conn)
	resp, err := client.DeliverCommand(ctx, &deliverypb.DeliverCommandRequest{
		StewardId: stewardID,
		Command:   grpcconvert.SignedCommandToProto(cmd),
	})
	if err != nil {
		return fmt.Errorf("internaldelivery: delivery RPC to node %s failed: %w", nodeID, err)
	}
	if !resp.GetDelivered() {
		return fmt.Errorf("internaldelivery: node %s could not deliver to steward %s: %s", nodeID, stewardID, resp.GetMessage())
	}

	c.logger.Info("internaldelivery: forwarded command to peer node",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"peer_node_id", logging.SanitizeLogValue(nodeID))
	return nil
}

// dial returns a cached gRPC client connection for addr, creating one if
// necessary. Connections are reused across calls rather than dialed per
// delivery attempt.
func (c *ClusterAwareSender) dial(addr string) (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if conn, ok := c.conns[addr]; ok {
		return conn, nil
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(c.tlsConfig)))
	if err != nil {
		return nil, err
	}
	c.conns[addr] = conn
	return conn, nil
}

// Close tears down every cached outbound peer connection. Independent of the
// wrapped local provider's own lifecycle — callers close that separately.
func (c *ClusterAwareSender) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	for addr, conn := range c.conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(c.conns, addr)
	}
	return firstErr
}

// The remaining methods delegate unchanged to the wrapped local provider.

func (c *ClusterAwareSender) Name() string { return c.local.Name() }

func (c *ClusterAwareSender) Initialize(ctx context.Context, config map[string]interface{}) error {
	return c.local.Initialize(ctx, config)
}

func (c *ClusterAwareSender) Start(ctx context.Context) error { return c.local.Start(ctx) }

func (c *ClusterAwareSender) Stop(ctx context.Context) error { return c.local.Stop(ctx) }

func (c *ClusterAwareSender) Reconnect(ctx context.Context) error { return c.local.Reconnect(ctx) }

func (c *ClusterAwareSender) SubscribeCommands(ctx context.Context, stewardID string, handler controlplaneInterfaces.CommandHandler) error {
	return c.local.SubscribeCommands(ctx, stewardID, handler)
}

func (c *ClusterAwareSender) PublishEvent(ctx context.Context, event *types.Event) error {
	return c.local.PublishEvent(ctx, event)
}

func (c *ClusterAwareSender) SubscribeEvents(ctx context.Context, filter *types.EventFilter, handler controlplaneInterfaces.EventHandler) error {
	return c.local.SubscribeEvents(ctx, filter, handler)
}

func (c *ClusterAwareSender) SendHeartbeat(ctx context.Context, heartbeat *types.Heartbeat) error {
	return c.local.SendHeartbeat(ctx, heartbeat)
}

func (c *ClusterAwareSender) SubscribeHeartbeats(ctx context.Context, handler controlplaneInterfaces.HeartbeatHandler) error {
	return c.local.SubscribeHeartbeats(ctx, handler)
}

func (c *ClusterAwareSender) GetStats(ctx context.Context) (*types.ControlPlaneStats, error) {
	return c.local.GetStats(ctx)
}

func (c *ClusterAwareSender) IsConnected() bool { return c.local.IsConnected() }
