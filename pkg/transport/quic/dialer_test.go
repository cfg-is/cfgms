// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDialer_ReturnsNetConn verifies that Dial returns a valid net.Conn.
// Skipped in short mode — QUIC dial requires UDP buffer allocation that can
// fail on CI runners with restricted socket buffer limits (macOS GitHub Actions).
func TestDialer_ReturnsNetConn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping QUIC dial test in short mode — requires UDP buffer allocation")
	}
	tlsPair := newTestTLSPair(t)

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	// Accept in the background. Server goroutine will return once it
	// receives the sync byte written below.
	go func() {
		conn, aerr := lis.Accept()
		if aerr == nil {
			_ = conn.Close()
		}
	}()

	conn, err := Dial(t.Context(), lis.Addr().String(), tlsPair.client, nil)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Write a byte to trigger stream notification so the server goroutine
	// doesn't leak waiting in AcceptStream.
	_, _ = conn.Write([]byte{0x00})

	assert.NotNil(t, conn.LocalAddr())
	assert.NotNil(t, conn.RemoteAddr())

	require.NoError(t, conn.Close())
}

// TestDialer_NewDialer_ContextDialer verifies that NewDialer returns a function
// with the correct signature for grpc.WithContextDialer.
// Skipped in short mode — same UDP buffer requirement as TestDialer_ReturnsNetConn.
func TestDialer_NewDialer_ContextDialer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping QUIC dial test in short mode — requires UDP buffer allocation")
	}
	tlsPair := newTestTLSPair(t)

	dialFn := NewDialer(tlsPair.client, nil)

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	go func() {
		conn, aerr := lis.Accept()
		if aerr == nil {
			_ = conn.Close()
		}
	}()

	conn, err := dialFn(t.Context(), lis.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, conn)

	_, _ = conn.Write([]byte{0x00})
	require.NoError(t, conn.Close())
}

// TestDialer_InvalidAddr verifies that Dial returns an error when it cannot
// reach the target address within the given context deadline.
func TestDialer_InvalidAddr(t *testing.T) {
	tlsPair := newTestTLSPair(t)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	// Port 1 is privileged and almost certainly not listening.
	// QUIC/UDP will eventually give up or get ICMP unreachable.
	_, err := Dial(ctx, "127.0.0.1:1", tlsPair.client, nil)
	assert.Error(t, err, "Dial to unreachable address should fail")
}
