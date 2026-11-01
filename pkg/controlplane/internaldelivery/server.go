// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package internaldelivery implements the internal controller-to-controller
// delivery RPC (ADR-031 Decision 3, Issue #3764): the first inter-node gRPC
// service other than Raft's own transport. It lets node A ask node B to
// deliver a command to a steward B currently holds a control-plane
// connection for, using the shared steward-routing table
// (pkg/storage/interfaces/business.RoutingStore) to resolve which node to
// ask. The durable outbox (Issue #3757) remains the guarantee underneath
// this fast path: a forwarding failure here is never treated as a hard
// delivery failure, only as "use the outbox instead".
package internaldelivery

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	deliverypb "github.com/cfgis/cfgms/api/proto/clusterdelivery"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcconvert "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// Server implements deliverypb.DeliveryServiceServer. It is the receiving
// side of a peer's forwarded delivery request: it looks the target steward up
// in ITS OWN local registry and, if found, delivers via ITS OWN local
// control-plane provider — never via a cluster-aware wrapper, which would let
// a request for a steward this node does not have recurse into forwarding it
// right back out.
type Server struct {
	deliverypb.UnimplementedDeliveryServiceServer

	registry     registry.Registry
	controlPlane controlplaneInterfaces.ControlPlaneProvider
	logger       logging.Logger
}

// NewServer constructs the internal delivery gRPC service handler. reg and
// controlPlane must be the node-local registry and control-plane provider —
// the same pair the API server wires for direct steward delivery — not a
// ClusterAwareSender.
func NewServer(reg registry.Registry, controlPlane controlplaneInterfaces.ControlPlaneProvider, logger logging.Logger) *Server {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &Server{registry: reg, controlPlane: controlPlane, logger: logger}
}

// DeliverCommand implements deliverypb.DeliveryServiceServer.DeliverCommand.
func (s *Server) DeliverCommand(ctx context.Context, req *deliverypb.DeliverCommandRequest) (*deliverypb.DeliverCommandResponse, error) {
	stewardID := req.GetStewardId()
	if stewardID == "" {
		return nil, status.Error(codes.InvalidArgument, "steward_id is required")
	}
	if req.GetCommand() == nil {
		return nil, status.Error(codes.InvalidArgument, "command is required")
	}

	if s.registry == nil {
		return &deliverypb.DeliverCommandResponse{NotConnected: true, Message: "no local registry configured"}, nil
	}
	if _, ok := s.registry.Get(stewardID); !ok {
		return &deliverypb.DeliverCommandResponse{NotConnected: true, Message: "steward not connected to this node"}, nil
	}

	cmd := grpcconvert.SignedCommandFromProto(req.GetCommand())
	if cmd == nil {
		return nil, status.Error(codes.InvalidArgument, "command could not be decoded")
	}
	// The command's own steward_id must match the requested target: a peer
	// forwarding a command addressed to one steward must never be able to
	// cause delivery to a different steward connected to this node by
	// mismatching the two fields.
	if cmd.Command.StewardID != stewardID {
		return nil, status.Error(codes.InvalidArgument, "command steward_id does not match request steward_id")
	}

	if err := s.controlPlane.SendCommand(ctx, cmd); err != nil {
		if errors.Is(err, controlplaneInterfaces.ErrStewardNotConnected) {
			// The steward disconnected between our registry check above and the
			// send itself (race with a concurrent disconnect) — report exactly
			// as "not connected", not as a delivery error.
			return &deliverypb.DeliverCommandResponse{NotConnected: true, Message: "steward disconnected before delivery"}, nil
		}
		// The concrete failure is logged, never returned: the error text comes
		// from the local control-plane provider and can carry internal detail
		// back to the caller.
		s.logger.Warn("internaldelivery: local delivery failed",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		return nil, status.Error(codes.Internal, "local delivery failed")
	}

	return &deliverypb.DeliverCommandResponse{Delivered: true}, nil
}
