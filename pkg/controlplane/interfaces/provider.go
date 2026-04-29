// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the pluggable control plane abstraction for CFGMS.
//
// The control plane handles commands, events, and heartbeats between controller
// and stewards, abstracting away transport-specific details (gRPC, WebSocket, etc.).
package interfaces

import (
	"context"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// ControlPlaneProvider defines the interface for control plane implementations.
//
// The control plane is responsible for command/event/heartbeat communication
// between controllers and stewards. It provides semantic methods that hide
// transport-specific details like topics, QoS levels, and subscriptions.
// SendResponse is not part of this interface — it lives on the concrete
// *grpc.Provider to prevent cross-steward response injection (epic #747).
//
// Implementations must be thread-safe and support concurrent operations.
type ControlPlaneProvider interface {
	// Name returns the provider name (e.g., "grpc", "websocket")
	Name() string

	// Initialize configures the provider with implementation-specific settings
	//
	// The config map contains provider-specific configuration. Common keys:
	//   - "broker_addr": string - Broker/server address
	//   - "client_id": string - Client identifier
	//   - "tls_config": *tls.Config - TLS configuration
	//   - "steward_id": string - Steward ID (for client mode)
	Initialize(ctx context.Context, config map[string]interface{}) error

	// Start begins control plane operation
	//
	// For server-side (controller): Starts listening for connections
	// For client-side (steward): Connects to the controller
	Start(ctx context.Context) error

	// Stop gracefully shuts down the control plane
	//
	// Disconnects all connections and stops accepting new ones.
	// The context can be used to force shutdown if graceful shutdown times out.
	Stop(ctx context.Context) error

	// =================================================================
	// Commands (Controller → Steward)
	// =================================================================

	// SendCommand sends a signed command to a specific steward.
	//
	// The cmd envelope must already be signed by the controller before calling
	// this method. The transport layer carries the signature intact; verification
	// is performed by the steward handler on receipt.
	//
	// Returns an error if the command cannot be delivered. Does not wait
	// for command execution — use SubscribeEvents to receive completion events.
	SendCommand(ctx context.Context, cmd *types.SignedCommand) error

	// FanOutCommand sends a signed command to a specific list of stewards.
	//
	// The caller is responsible for resolving target steward IDs (by tenant,
	// search results, online status, etc.). The transport layer delivers to
	// each steward without knowledge of organizational hierarchy.
	//
	// Returns FanOutResult with per-steward delivery status. The error return
	// is for systemic failures (provider not started, etc.), not per-steward
	// delivery failures which are reported in FanOutResult.Failed.
	FanOutCommand(ctx context.Context, cmd *types.SignedCommand, stewardIDs []string) (*types.FanOutResult, error)

	// SubscribeCommands subscribes to commands (steward-side)
	//
	// The handler is called for each command received by this steward.
	// Returns an error if subscription fails.
	SubscribeCommands(ctx context.Context, stewardID string, handler CommandHandler) error

	// =================================================================
	// Events (Steward → Controller)
	// =================================================================

	// PublishEvent publishes an event from steward to controller
	//
	// Events notify the controller of significant occurrences (command
	// completion, errors, state changes, etc.).
	PublishEvent(ctx context.Context, event *types.Event) error

	// SubscribeEvents subscribes to events matching a filter (controller-side)
	//
	// The handler is called for each matching event. Use EventFilter to
	// subscribe to specific stewards, tenants, or event types.
	SubscribeEvents(ctx context.Context, filter *types.EventFilter, handler EventHandler) error

	// =================================================================
	// Heartbeats (Bidirectional)
	// =================================================================

	// SendHeartbeat sends a heartbeat from steward to controller
	//
	// Heartbeats allow the controller to monitor steward connectivity
	// and health. Typically sent on a periodic interval (e.g., every 30s).
	SendHeartbeat(ctx context.Context, heartbeat *types.Heartbeat) error

	// SubscribeHeartbeats subscribes to heartbeats (controller-side)
	//
	// The handler is called for each heartbeat received. Use this to
	// detect steward connectivity and health status changes.
	SubscribeHeartbeats(ctx context.Context, handler HeartbeatHandler) error

	// =================================================================
	// Status & Monitoring
	// =================================================================

	// GetStats returns provider operational statistics
	GetStats(ctx context.Context) (*types.ControlPlaneStats, error)

	// IsConnected reports connection status
	//
	// For server-side: true if accepting connections
	// For client-side: true if connected to server
	IsConnected() bool
}

// CommandHandler is called when a signed command is received (steward-side).
//
// The handler receives the full SignedCommand envelope so that it can verify
// the signature and metadata (StewardID, replay window) before dispatching.
// The handler should publish events/responses to notify the controller of
// progress and completion.
type CommandHandler func(ctx context.Context, cmd *types.SignedCommand) error

// EventHandler is called when an event is received (controller-side).
//
// Events provide asynchronous notifications from stewards about state
// changes, command progress, and significant occurrences.
type EventHandler func(ctx context.Context, event *types.Event) error

// HeartbeatHandler is called when a heartbeat is received (controller-side).
//
// Heartbeats allow monitoring of steward connectivity and health status.
type HeartbeatHandler func(ctx context.Context, heartbeat *types.Heartbeat) error
