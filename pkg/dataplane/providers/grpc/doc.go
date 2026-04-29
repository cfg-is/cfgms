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
// # DoS Limits
//
// Every gRPC server created by this package enforces the following limits to
// prevent a malicious steward from OOM-ing the controller:
//
//   - MaxRecvMsgSize: 8 MB — a single inbound gRPC message larger than this
//     is rejected with codes.ResourceExhausted. The 64 KB chunk size used by
//     the transfer helpers keeps normal traffic well within the limit.
//   - MaxSendMsgSize: 8 MB — symmetric cap on outbound messages.
//   - MaxConcurrentStreams: 100 — limits active gRPC streams per connection,
//     preventing stream-flood attacks from overwhelming the server.
//   - KeepaliveParams: ping every 30 s, close if no ACK within 60 s.
//   - KeepaliveEnforcementPolicy: clients must wait at least 10 s between pings.
//
// Constants are defined in limits.go. Both call sites (provider.go startServer
// and features/controller/server/server.go Start) use the shared ServerOptions()
// helper so the limits stay in sync.
package grpc
