// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDialer_ReturnsNetConn verifies that Dial returns a valid net.Conn.
func TestDialer_ReturnsNetConn(t *testing.T) {
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

	var _ net.Conn = conn
	assert.NotNil(t, conn.LocalAddr())
	assert.NotNil(t, conn.RemoteAddr())

	require.NoError(t, conn.Close())
}

// TestDialer_NewDialer_ContextDialer verifies that NewDialer returns a function
// with the correct signature for grpc.WithContextDialer.
func TestDialer_NewDialer_ContextDialer(t *testing.T) {
	tlsPair := newTestTLSPair(t)

	dialFn := NewDialer(tlsPair.client, nil)

	// Verify the function signature matches grpc.WithContextDialer expectation.
	var _ func(ctx context.Context, addr string) (net.Conn, error) = dialFn

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
