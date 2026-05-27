// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package grpc

// Integration tests that relied on the channel-based dataPlaneHandler
// (serverSess.ReceiveDNA, serverSess.SendConfig, etc.) were removed in
// Issue #898. The equivalent round-trip coverage is now in
// features/controller/transport/dna_handler_test.go and
// features/controller/transport/bulk_handler_test.go.
