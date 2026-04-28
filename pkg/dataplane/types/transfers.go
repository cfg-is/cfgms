// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package types provides data transfer types for the data plane communication layer.
//
// This package defines semantic transfer types for controller-steward communication,
// abstracting away transport-specific details (QUIC streams, gRPC, etc.).
package types

import (
	"time"
)

// StreamType identifies the purpose of a raw stream.
type StreamType string

// DefaultChunkSize is the maximum bytes per gRPC data-plane chunk (64 KB).
// Both stream.go and config_handler.go import this constant from the types
// package so the concrete grpc provider is never imported by feature code.
const DefaultChunkSize = 64 * 1024

const (
	// StreamConfig indicates a configuration transfer stream
	StreamConfig StreamType = "config"

	// StreamDNA indicates a DNA transfer stream
	StreamDNA StreamType = "dna"

	// StreamBulk indicates a bulk data transfer stream
	StreamBulk StreamType = "bulk"

	// StreamCustom indicates a custom application-specific stream
	StreamCustom StreamType = "custom"
)

// ConfigTransfer represents a configuration data transfer.
//
// Configuration transfers include tenant-specific configuration data,
// policies, and settings that need to be synchronized to stewards.
type ConfigTransfer struct {
	// ID is a unique identifier for this transfer
	ID string `json:"id"`

	// StewardID identifies the target steward
	StewardID string `json:"steward_id"`

	// TenantID identifies the tenant
	TenantID string `json:"tenant_id"`

	// Version is the configuration version
	Version string `json:"version"`

	// Timestamp when the transfer was initiated
	Timestamp time.Time `json:"timestamp"`

	// Data contains the serialized configuration payload
	//
	// Typically JSON or protobuf, compressed with gzip or zstd.
	// The provider handles compression/decompression automatically.
	Data []byte `json:"data"`

	// Signature is the cryptographic signature of the data
	//
	// Used to verify data integrity and authenticity. Format depends
	// on the signing algorithm configured in the controller.
	Signature []byte `json:"signature,omitempty"`

	// Metadata contains transfer-specific metadata
	//
	// Examples: compression algorithm, encoding format, priority
	Metadata map[string]string `json:"metadata,omitempty"`
}

// DNATransfer represents a DNA (system state) data transfer.
//
// DNA transfers include system attributes, hardware/software inventory,
// and current state information from stewards to the controller.
type DNATransfer struct {
	// ID is a unique identifier for this transfer
	ID string `json:"id"`

	// StewardID identifies the source steward
	StewardID string `json:"steward_id"`

	// TenantID identifies the tenant
	TenantID string `json:"tenant_id"`

	// Timestamp when the DNA was collected
	Timestamp time.Time `json:"timestamp"`

	// Attributes contains the DNA attributes
	//
	// Typically a map of attribute names to values, serialized as JSON
	// or protobuf. The provider handles compression automatically.
	Attributes []byte `json:"attributes"`

	// Delta indicates if this is a delta update
	//
	// If true, Attributes contains only changed attributes since the
	// last transfer. If false, contains complete DNA snapshot.
	Delta bool `json:"delta"`

	// BaseVersion is the DNA version this delta is based on (if Delta=true)
	BaseVersion string `json:"base_version,omitempty"`

	// Metadata contains transfer-specific metadata
	//
	// Examples: compression algorithm, attribute count, collection duration
	Metadata map[string]string `json:"metadata,omitempty"`
}

// BulkTransfer represents a large data transfer.
//
// Bulk transfers are used for file deployments, package installations,
// log collection, or other large data movements. They support chunking,
// resumption, and progress tracking.
type BulkTransfer struct {
	// ID is a unique identifier for this transfer
	ID string `json:"id"`

	// StewardID identifies the steward involved in the transfer
	StewardID string `json:"steward_id"`

	// TenantID identifies the tenant
	TenantID string `json:"tenant_id"`

	// Direction indicates transfer direction
	//
	// "to_steward": Controller → Steward (deployment)
	// "to_controller": Steward → Controller (collection)
	Direction string `json:"direction"`

	// Type indicates the bulk transfer type
	//
	// Examples: "file", "package", "logs", "backup"
	Type string `json:"type"`

	// TotalSize is the total transfer size in bytes
	TotalSize int64 `json:"total_size"`

	// ChunkSize is the size of each chunk in bytes
	ChunkSize int `json:"chunk_size"`

	// Timestamp when the transfer was initiated
	Timestamp time.Time `json:"timestamp"`

	// Data contains the bulk data payload
	//
	// For chunked transfers, this contains the current chunk.
	// The provider handles chunking and reassembly automatically.
	Data []byte `json:"data"`

	// Checksum is the integrity checksum for the data
	//
	// Used to verify data wasn't corrupted during transfer.
	// Format: "algorithm:hash" (e.g., "sha256:abc123...")
	Checksum string `json:"checksum"`

	// Progress tracking (optional, for resumable transfers)
	Progress *TransferProgress `json:"progress,omitempty"`

	// Metadata contains transfer-specific metadata
	//
	// Examples: filename, compression, encryption, priority
	Metadata map[string]string `json:"metadata,omitempty"`
}

// TransferProgress tracks the progress of a bulk transfer.
//
// Used for resumable transfers and progress reporting.
type TransferProgress struct {
	// BytesTransferred is the number of bytes successfully transferred
	BytesTransferred int64 `json:"bytes_transferred"`

	// ChunksCompleted is the number of chunks successfully transferred
	ChunksCompleted int `json:"chunks_completed"`

	// StartTime when the transfer began
	StartTime time.Time `json:"start_time"`

	// LastUpdate when progress was last updated
	LastUpdate time.Time `json:"last_update"`

	// EstimatedCompletion is the estimated completion time
	EstimatedCompletion time.Time `json:"estimated_completion,omitempty"`
}
