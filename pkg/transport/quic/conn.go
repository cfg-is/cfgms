// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package quic

import (
	"crypto/tls"
	"net"
	"sync"
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
	closeOnce  sync.Once
	closeErr   error
	onClose    func()
	// grace, when set, defers the connection-level close after Close so data
	// already written can be delivered. Nil closes the connection immediately.
	grace *graceTracker
}

// graceTracker tracks connections whose CONNECTION_CLOSE is deferred so the
// owning listener can close them all when it shuts down.
type graceTracker struct {
	mu      sync.Mutex
	closing bool
	pending map[*quicgo.Conn]struct{}
}

func newGraceTracker() *graceTracker {
	return &graceTracker{pending: make(map[*quicgo.Conn]struct{})}
}

// add registers qc for a deferred close; false means the tracker is already
// shut down and the caller must close immediately.
func (g *graceTracker) add(qc *quicgo.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return false
	}
	g.pending[qc] = struct{}{}
	return true
}

func (g *graceTracker) remove(qc *quicgo.Conn) {
	g.mu.Lock()
	delete(g.pending, qc)
	g.mu.Unlock()
}

// closeAll closes every pending connection and refuses further deferrals.
func (g *graceTracker) closeAll() {
	g.mu.Lock()
	g.closing = true
	pending := g.pending
	g.pending = make(map[*quicgo.Conn]struct{})
	g.mu.Unlock()
	for qc := range pending {
		_ = qc.CloseWithError(0, "")
	}
}

// Compile-time check that Conn implements net.Conn.
var _ net.Conn = (*Conn)(nil)

// newConn creates a Conn from a QUIC connection, one of its streams, and the
// pre-computed addresses. The quicConn reference is required so that
// TLSConnectionState can expose the peer certificate after the handshake.
func newConn(quicConn *quicgo.Conn, stream *quicgo.Stream, localAddr, remoteAddr net.Addr) *Conn {
	return newConnWithCloseHook(quicConn, stream, localAddr, remoteAddr, nil)
}

func newConnWithCloseHook(quicConn *quicgo.Conn, stream *quicgo.Stream, localAddr, remoteAddr net.Addr, onClose func()) *Conn {
	return &Conn{
		quicConn:   quicConn,
		stream:     stream,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		onClose:    onClose,
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

// closeGrace bounds how long a listener-side Close waits for the peer to take delivery of the
// data written before Close before it tears the QUIC connection down.
const closeGrace = time.Second

// Close closes the QUIC stream and then the underlying QUIC connection.
//
// The stream write half is closed first (STREAM_FIN after every byte already
// written). The QUIC connection (CONNECTION_CLOSE with application error code
// 0) is closed only once the peer has closed the connection itself or
// closeGrace elapses. CONNECTION_CLOSE discards stream data the peer has not
// yet received, so closing it immediately lost gRPC's final status trailers
// and a refused client saw a transport error instead of the status. Closing at
// the connection level still gives the peer a prompt signal after the QUIC
// listener is closed, which a stream-only close does not (the peer would wait
// for the ~90s idle timeout).
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.stream.Close()
		if c.grace != nil && c.grace.add(c.quicConn) {
			go func() {
				t := time.NewTimer(closeGrace)
				defer t.Stop()
				select {
				case <-c.quicConn.Context().Done():
				case <-t.C:
				}
				c.grace.remove(c.quicConn)
				_ = c.quicConn.CloseWithError(0, "")
			}()
		} else {
			_ = c.quicConn.CloseWithError(0, "")
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
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
