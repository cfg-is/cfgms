// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the data plane session abstraction for CFGMS.
package interfaces

import (
	"context"

	"github.com/cfgis/cfgms/pkg/dataplane/types"
)

// DataPlaneSession represents an established data plane connection.
//
// Sessions provide high-level transfer operations (config, DNA, bulk data).
// All methods are thread-safe and can be called concurrently.
type DataPlaneSession interface {
	// =================================================================
	// Identification
	// =================================================================

	// ID returns a unique identifier for this session
	ID() string

	// PeerID returns the peer's identifier
	//
	// For controller-side: Returns the steward ID
	// For steward-side: Returns the controller ID
	PeerID() string

	// =================================================================
	// Configuration Transfers
	// =================================================================

	// SendConfig sends configuration data to the peer
	//
	// Handles serialization, compression, and reliable delivery.
	// Returns when the transfer completes or an error occurs.
	SendConfig(ctx context.Context, config *types.ConfigTransfer) error

	// ReceiveConfig receives configuration data from the peer
	//
	// Blocks until configuration is received or context is canceled.
	// Handles decompression and deserialization automatically.
	ReceiveConfig(ctx context.Context) (*types.ConfigTransfer, error)

	// =================================================================
	// DNA Transfers
	// =================================================================

	// SendDNA sends DNA data to the peer
	//
	// DNA transfers include system state, attributes, and metadata.
	// Handles serialization, compression, and reliable delivery.
	SendDNA(ctx context.Context, dna *types.DNATransfer) error

	// ReceiveDNA receives DNA data from the peer
	//
	// Blocks until DNA is received or context is canceled.
	// Handles decompression and deserialization automatically.
	ReceiveDNA(ctx context.Context) (*types.DNATransfer, error)

	// =================================================================
	// Bulk Transfers
	// =================================================================

	// SendBulk sends bulk data to the peer
	//
	// Used for large file transfers, package deployments, or other
	// bulk operations. Handles chunking, flow control, and progress tracking.
	SendBulk(ctx context.Context, bulk *types.BulkTransfer) error

	// ReceiveBulk receives bulk data from the peer
	//
	// Blocks until bulk transfer completes or context is canceled.
	// Handles reassembly and integrity verification.
	ReceiveBulk(ctx context.Context) (*types.BulkTransfer, error)

	// =================================================================
	// Session Management
	// =================================================================

	// Close gracefully closes the session
	//
	// Waits for in-progress transfers to complete (up to context deadline),
	// then closes all streams and the underlying connection.
	Close(ctx context.Context) error

	// IsClosed reports whether the session has been closed
	IsClosed() bool

	// LocalAddr returns the local network address
	LocalAddr() string

	// RemoteAddr returns the peer's network address
	RemoteAddr() string
}
