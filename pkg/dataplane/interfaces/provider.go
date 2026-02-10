// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the pluggable data plane abstraction for CFGMS.
//
// The data plane handles high-throughput data transfers (configuration, DNA,
// bulk data) between controller and stewards, abstracting away transport-specific
// details (QUIC, gRPC streams, WebSockets, etc.).
package interfaces

import (
	"context"

	"github.com/cfgis/cfgms/pkg/dataplane/types"
)

// DataPlaneProvider defines the interface for data plane implementations.
//
// The data plane is responsible for high-throughput, reliable data transfers
// between controllers and stewards. It provides semantic methods that hide
// transport-specific details like stream management, flow control, and compression.
//
// Implementations must be thread-safe and support concurrent operations.
type DataPlaneProvider interface {
	// Name returns the provider name (e.g., "quic", "grpc", "websocket")
	Name() string

	// Description returns a human-readable description
	Description() string

	// Initialize configures the provider with implementation-specific settings
	//
	// The config map contains provider-specific configuration. Common keys:
	//   - "listen_addr": string - Server listen address (server-side)
	//   - "server_addr": string - Server address to connect to (client-side)
	//   - "tls_config": *tls.Config - TLS configuration (required for security)
	//   - "steward_id": string - Steward ID (for client mode)
	//   - "max_streams": int - Maximum concurrent streams per connection
	//   - "buffer_size": int - Transfer buffer size in bytes
	Initialize(ctx context.Context, config map[string]interface{}) error

	// Start begins data plane operation
	//
	// For server-side (controller): Starts listening for connections
	// For client-side (steward): Establishes connection to the controller
	Start(ctx context.Context) error

	// Stop gracefully shuts down the data plane
	//
	// Closes all active sessions and stops accepting new connections.
	// The context can be used to force shutdown if graceful shutdown times out.
	Stop(ctx context.Context) error

	// =================================================================
	// Server-Side (Controller)
	// =================================================================

	// AcceptConnection accepts an incoming data plane connection (controller-side)
	//
	// Blocks until a steward connects or the context is canceled.
	// Returns a DataPlaneSession for the established connection.
	AcceptConnection(ctx context.Context) (DataPlaneSession, error)

	// =================================================================
	// Client-Side (Steward)
	// =================================================================

	// Connect establishes a connection to the controller (steward-side)
	//
	// The serverAddr parameter allows connecting to a specific controller
	// (overrides config if provided). Returns a DataPlaneSession for the
	// established connection.
	Connect(ctx context.Context, serverAddr string) (DataPlaneSession, error)

	// =================================================================
	// Status & Monitoring
	// =================================================================

	// GetStats returns provider operational statistics
	GetStats(ctx context.Context) (*types.DataPlaneStats, error)

	// Available checks if the provider can be started
	//
	// Returns false and an error if prerequisites are missing (e.g.,
	// certificates, network connectivity, configuration).
	Available() (bool, error)

	// IsListening reports server listening status (controller-side)
	//
	// Returns true if the provider is accepting incoming connections.
	IsListening() bool

	// IsConnected reports connection status (steward-side)
	//
	// Returns true if connected to the controller.
	IsConnected() bool
}

// ProviderRegistry manages data plane provider registration and discovery.
var providerRegistry = make(map[string]DataPlaneProvider)

// RegisterProvider registers a data plane provider implementation.
//
// This should be called from init() functions in provider packages.
// Panics if a provider with the same name is already registered.
func RegisterProvider(provider DataPlaneProvider) {
	name := provider.Name()
	if _, exists := providerRegistry[name]; exists {
		panic("data plane provider already registered: " + name)
	}
	providerRegistry[name] = provider
}

// GetProvider retrieves a registered provider by name.
//
// Returns nil if no provider with that name exists.
func GetProvider(name string) DataPlaneProvider {
	return providerRegistry[name]
}

// GetAvailableProviders returns all registered provider names.
func GetAvailableProviders() []string {
	names := make([]string, 0, len(providerRegistry))
	for name := range providerRegistry {
		names = append(names, name)
	}
	return names
}
