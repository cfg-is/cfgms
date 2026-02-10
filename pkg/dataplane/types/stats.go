// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package types provides statistics types for data plane monitoring.
package types

import (
	"time"
)

// DataPlaneStats contains operational statistics for a data plane provider.
//
// These statistics are used for monitoring, debugging, and capacity planning.
type DataPlaneStats struct {
	// ProviderName is the name of the data plane provider
	ProviderName string `json:"provider_name"`

	// Uptime is how long the provider has been running
	Uptime time.Duration `json:"uptime"`

	// =================================================================
	// Connection Statistics
	// =================================================================

	// ActiveSessions is the current number of active sessions
	ActiveSessions int `json:"active_sessions"`

	// TotalSessionsAccepted is the total sessions accepted (server-side)
	TotalSessionsAccepted int64 `json:"total_sessions_accepted"`

	// TotalConnectionAttempts is the total connection attempts (client-side)
	TotalConnectionAttempts int64 `json:"total_connection_attempts"`

	// FailedConnections is the number of failed connection attempts
	FailedConnections int64 `json:"failed_connections"`

	// =================================================================
	// Transfer Statistics
	// =================================================================

	// ConfigTransfers tracks configuration transfer statistics
	ConfigTransfers TransferStats `json:"config_transfers"`

	// DNATransfers tracks DNA transfer statistics
	DNATransfers TransferStats `json:"dna_transfers"`

	// BulkTransfers tracks bulk transfer statistics
	BulkTransfers TransferStats `json:"bulk_transfers"`

	// =================================================================
	// Performance Metrics
	// =================================================================

	// BytesSent is the total bytes sent across all sessions
	BytesSent int64 `json:"bytes_sent"`

	// BytesReceived is the total bytes received across all sessions
	BytesReceived int64 `json:"bytes_received"`

	// AverageLatency is the average transfer latency
	AverageLatency time.Duration `json:"average_latency"`

	// AverageThroughput is the average throughput in bytes/second
	AverageThroughput int64 `json:"average_throughput"`

	// =================================================================
	// Error Statistics
	// =================================================================

	// TransferErrors is the number of transfer errors encountered
	TransferErrors int64 `json:"transfer_errors"`

	// TimeoutErrors is the number of timeout errors
	TimeoutErrors int64 `json:"timeout_errors"`

	// ProtocolErrors is the number of protocol-level errors
	ProtocolErrors int64 `json:"protocol_errors"`

	// =================================================================
	// Resource Usage
	// =================================================================

	// ActiveStreams is the current number of active streams across all sessions
	ActiveStreams int `json:"active_streams"`

	// MemoryUsageBytes is the approximate memory usage in bytes
	MemoryUsageBytes int64 `json:"memory_usage_bytes"`
}

// TransferStats contains statistics for a specific transfer type.
type TransferStats struct {
	// Sent is the number of transfers sent
	Sent int64 `json:"sent"`

	// Received is the number of transfers received
	Received int64 `json:"received"`

	// Failed is the number of failed transfers
	Failed int64 `json:"failed"`

	// TotalBytes is the total bytes transferred
	TotalBytes int64 `json:"total_bytes"`

	// AverageSize is the average transfer size in bytes
	AverageSize int64 `json:"average_size"`

	// AverageDuration is the average transfer duration
	AverageDuration time.Duration `json:"average_duration"`
}
