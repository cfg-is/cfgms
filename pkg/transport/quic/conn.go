// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"crypto/tls"
	"net"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// Conn wraps a QUIC stream to implement net.Conn.
//
// Read, Write, Close, and deadline operations delegate to the underlying
// QUIC stream. Address methods return the addresses from the parent QUIC
// connection. The parent connection reference is kept so that TLS state
// from the QUIC handshake can be exposed via TLSConnectionState.
type Conn struct {
	quicConn   *quicgo.Conn
	stream     *quicgo.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

// Compile-time check that Conn implements net.Conn.
var _ net.Conn = (*Conn)(nil)

// newConn creates a Conn from a QUIC connection, one of its streams, and the
// pre-computed addresses. The quicConn reference is required so that
// TLSConnectionState can expose the peer certificate after the handshake.
func newConn(quicConn *quicgo.Conn, stream *quicgo.Stream, localAddr, remoteAddr net.Addr) *Conn {
	return &Conn{
		quicConn:   quicConn,
		stream:     stream,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// Read reads data from the QUIC stream.
func (c *Conn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

// Write writes data to the QUIC stream.
func (c *Conn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

// Close closes the QUIC connection.
//
// Both the stream write half (STREAM_FIN) and the underlying QUIC connection
// (CONNECTION_CLOSE) are closed. Closing at the connection level ensures the
// peer receives an immediate signal even when the shared UDP receive loop has
// already stopped (e.g. after the QUIC listener is closed). Without this,
// gRPC's transport only closes the stream write half, and the peer must wait
// for the QUIC idle timeout (~90 s) to detect the disconnect.
func (c *Conn) Close() error {
	_ = c.stream.Close()
	return c.quicConn.CloseWithError(0, "")
}

// LocalAddr returns the local QUIC connection address.
func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote QUIC connection address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets the read and write deadline on the QUIC stream.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the QUIC stream.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the QUIC stream.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// TLSConnectionState returns the TLS connection state from the underlying QUIC
// connection. The state includes the negotiated cipher suite, the peer's
// certificate chain, and the ALPN protocol, all of which are established
// during the QUIC handshake.
//
// Returns nil if the parent connection reference is not available.
func (c *Conn) TLSConnectionState() *tls.ConnectionState {
	if c.quicConn == nil {
		return nil
	}
	state := c.quicConn.ConnectionState().TLS
	return &state
}
