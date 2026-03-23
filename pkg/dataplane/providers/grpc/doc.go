// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package grpc implements the gRPC data plane provider for CFGMS.
//
// This provider implements the DataPlaneProvider interface using gRPC streaming
// RPCs (SyncConfig, SyncDNA, BulkTransfer) defined in the StewardTransport
// service. In the unified gRPC-over-QUIC model, data transfers share the same
// connection as the control plane — there is no separate "connect QUIC now"
// dance.
//
// # Connection Sharing
//
// In client mode, the provider accepts an existing *grpc.ClientConn from the
// control plane (via the "grpc_conn" config key). This is the intended
// production usage: one QUIC connection carries both ControlChannel RPCs and
// data transfer RPCs.
//
// In server mode, the provider either accepts an existing *grpc.Server (via
// the "grpc_server" config key) or starts its own gRPC-over-QUIC server.
//
// # Transfer Methods
//
// The provider maps DataPlaneSession methods to gRPC RPCs:
//
//   - SendConfig / ReceiveConfig → SyncConfig (server-streaming)
//   - SendDNA / ReceiveDNA       → SyncDNA    (client-streaming)
//   - SendBulk / ReceiveBulk     → BulkTransfer (bidirectional streaming)
//
// Data is chunked at 64 KB boundaries for streaming. Transfer structs are
// JSON-serialised before chunking so all metadata fields are preserved.
//
// # Raw Streams
//
// OpenStream and AcceptStream are not supported by this provider. Use the
// typed transfer methods (SendConfig, SendDNA, SendBulk) instead.
package grpc
