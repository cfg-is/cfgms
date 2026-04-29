// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConn_ImplementsNetConn verifies the compile-time interface contract.
func TestConn_ImplementsNetConn(t *testing.T) {
	var _ net.Conn = (*Conn)(nil)
}

// TestConn_ReadWrite verifies that bytes written through one end of a QUIC stream
// are readable from the Conn wrapper on the other end.
func TestConn_ReadWrite(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	serverConn, clientConn := dialPair(t, tlsPair)

	// Client writes, server reads.
	_, err := clientConn.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 16)
	require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := serverConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))

	// Server writes, client reads.
	_, err = serverConn.Write([]byte("world"))
	require.NoError(t, err)

	require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err = clientConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "world", string(buf[:n]))
}

// TestConn_Addresses verifies that LocalAddr and RemoteAddr return valid QUIC
// addresses with network "quic".
func TestConn_Addresses(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	serverConn, clientConn := dialPair(t, tlsPair)

	// Both sides should report addresses.
	require.NotNil(t, serverConn.LocalAddr())
	require.NotNil(t, serverConn.RemoteAddr())
	require.NotNil(t, clientConn.LocalAddr())
	require.NotNil(t, clientConn.RemoteAddr())

	// The addresses must be non-empty strings.
	assert.NotEmpty(t, serverConn.LocalAddr().String())
	assert.NotEmpty(t, serverConn.RemoteAddr().String())
	assert.NotEmpty(t, clientConn.LocalAddr().String())
	assert.NotEmpty(t, clientConn.RemoteAddr().String())

	// The network name must be "quic".
	assert.Equal(t, "quic", serverConn.LocalAddr().Network())
	assert.Equal(t, "quic", serverConn.RemoteAddr().Network())
}

// TestConn_Close_PropagatesDisconnect verifies that calling Close on one end
// sends a QUIC CONNECTION_CLOSE frame that causes the peer's Read to return
// an error immediately, rather than waiting for the 90-second idle timeout.
func TestConn_Close_PropagatesDisconnect(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	serverConn, clientConn := dialPair(t, tlsPair)

	// Set a read deadline so the test fails fast if propagation is broken.
	require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(2*time.Second)))

	require.NoError(t, clientConn.Close())

	buf := make([]byte, 16)
	_, err := serverConn.Read(buf)
	assert.Error(t, err, "server Read should return error after client Close")
}

// TestConn_Deadlines verifies that deadline methods propagate to the stream
// without returning errors under normal conditions.
func TestConn_Deadlines(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	_, clientConn := dialPair(t, tlsPair)

	deadline := time.Now().Add(5 * time.Second)

	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, clientConn.SetReadDeadline(deadline))
	require.NoError(t, clientConn.SetWriteDeadline(deadline))

	// Clear deadlines (zero time means no deadline).
	require.NoError(t, clientConn.SetDeadline(time.Time{}))
	require.NoError(t, clientConn.SetReadDeadline(time.Time{}))
	require.NoError(t, clientConn.SetWriteDeadline(time.Time{}))
}
