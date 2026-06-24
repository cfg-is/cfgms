// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain installs a package-wide goroutine-leak guard. Any test that starts
// a server or client without a matching teardown will be caught here.
//
// goleak retries for up to 100 iterations (≈10 s) before declaring a leak, so
// quic-go's internal send-queue goroutines (which exit asynchronously after
// Transport.Close returns) are given time to drain before a false positive is
// reported.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
