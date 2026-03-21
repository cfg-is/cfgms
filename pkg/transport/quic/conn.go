// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"net"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// Conn wraps a QUIC stream to implement net.Conn.
//
// Read, Write, Close, and deadline operations delegate to the underlying
// QUIC stream. Address methods return the addresses from the parent QUIC
// connection.
type Conn struct {
	stream     *quicgo.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

// Compile-time check that Conn implements net.Conn.
var _ net.Conn = (*Conn)(nil)

// newConn creates a Conn from a QUIC stream and connection addresses.
func newConn(stream *quicgo.Stream, localAddr, remoteAddr net.Addr) *Conn {
	return &Conn{
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

// Close closes the QUIC stream.
func (c *Conn) Close() error {
	return c.stream.Close()
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
