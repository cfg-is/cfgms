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

// TestListener_ImplementsNetListener verifies the compile-time interface contract.
func TestListener_ImplementsNetListener(t *testing.T) {
	var _ net.Listener = (*Listener)(nil)
}

// TestListener_AcceptAndClose verifies that Accept returns a valid net.Conn
// with correct address fields.
func TestListener_AcceptAndClose(t *testing.T) {
	tlsPair := newTestTLSPair(t)

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)

	// Addr should be a valid non-empty address.
	require.NotNil(t, lis.Addr())
	assert.NotEmpty(t, lis.Addr().String())

	// Accept in a goroutine.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, aerr := lis.Accept()
		acceptCh <- acceptResult{conn: conn, err: aerr}
	}()

	// Dial and write a byte to trigger stream notification on the server side.
	clientConn, err := Dial(t.Context(), lis.Addr().String(), tlsPair.client, nil)
	require.NoError(t, err)
	defer func() { _ = clientConn.Close() }()

	_, err = clientConn.Write([]byte{0x00})
	require.NoError(t, err)

	// Wait for Accept with a bounded timeout.
	select {
	case result := <-acceptCh:
		require.NoError(t, result.err)
		require.NotNil(t, result.conn)
		assert.NotNil(t, result.conn.LocalAddr())
		assert.NotNil(t, result.conn.RemoteAddr())
		_ = result.conn.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Accept")
	}

	require.NoError(t, lis.Close())
}

// TestListener_CloseUnblocksAccept verifies that Close causes a blocked Accept
// to return with an error rather than hanging indefinitely.
func TestListener_CloseUnblocksAccept(t *testing.T) {
	tlsPair := newTestTLSPair(t)

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		_, aerr := lis.Accept()
		errCh <- aerr
	}()

	// Close the listener, which should unblock Accept.
	require.NoError(t, lis.Close())

	select {
	case err := <-errCh:
		assert.Error(t, err, "Accept should return an error after Close")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Accept to unblock after Close")
	}
}
