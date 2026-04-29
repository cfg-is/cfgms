// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// defaultQuicConfig returns the default QUIC configuration for the transport adapter.
//
// Keepalive tuning rationale (Story #504):
//
//   - KeepAlivePeriod 25s: Under the 30s worst-case NAT/firewall UDP pinhole timeout.
//     At 50k stewards this produces ~2,000 PING frames/sec (vs 5,000 at 10s).
//     Application heartbeats (default 30s) provide additional traffic that keeps
//     connections alive, so QUIC keepalives are a safety net, not the primary signal.
//
//   - MaxIdleTimeout 90s: 3.6× the keepalive period. A connection is torn down only
//     after ~3 missed keepalives AND no application traffic. This is generous enough
//     to survive transient network blips while still detecting genuinely dead connections
//     well before the controller's heartbeat timeout (default 15s detection + this).
//
//   - HandshakeIdleTimeout 30s: quic-go defaults to 5s, which is too aggressive for
//     macOS CI environments under load (many rapid UDP socket open/close cycles exhaust
//     the kernel socket buffer, causing handshakes to stall). 30s matches the typical
//     TLS handshake timeout used by HTTP/2 clients and is still well within acceptable
//     connection-establishment latency for a management plane.
//
// All values can be overridden by passing a custom *quic.Config to Listen/Dial.
func defaultQuicConfig() *quicgo.Config {
	return &quicgo.Config{
		MaxIdleTimeout:       90 * time.Second,
		KeepAlivePeriod:      25 * time.Second,
		HandshakeIdleTimeout: 30 * time.Second,
	}
}

// mergeQuicConfig returns cfg if non-nil, otherwise returns the default config.
func mergeQuicConfig(cfg *quicgo.Config) *quicgo.Config {
	if cfg != nil {
		return cfg
	}
	return defaultQuicConfig()
}

// Listener wraps a QUIC listener to implement net.Listener.
//
// Each accepted QUIC connection opens its first bidirectional stream, which is
// wrapped as a net.Conn for gRPC to use. gRPC handles its own HTTP/2
// multiplexing within that stream.
type Listener struct {
	ql     *quicgo.Listener
	ctx    context.Context
	cancel context.CancelFunc
}

// Compile-time check that Listener implements net.Listener.
var _ net.Listener = (*Listener)(nil)

// Listen creates a new QUIC listener on the given address.
//
// tlsConfig must have NextProtos set to a value agreed with the client.
// If quicConfig is nil, sensible defaults (MaxIdleTimeout: 90s,
// KeepAlivePeriod: 25s, HandshakeIdleTimeout: 30s) are used. See defaultQuicConfig for rationale.
func Listen(addr string, tlsConfig *tls.Config, quicConfig *quicgo.Config) (*Listener, error) {
	ql, err := quicgo.ListenAddr(addr, tlsConfig, mergeQuicConfig(quicConfig))
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Listener{
		ql:     ql,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Accept waits for and returns the next connection.
//
// It accepts the next QUIC connection, waits for the first bidirectional
// stream to be opened, and returns that stream as a net.Conn.
func (l *Listener) Accept() (net.Conn, error) {
	quicConn, err := l.ql.Accept(l.ctx)
	if err != nil {
		return nil, err
	}

	stream, err := quicConn.AcceptStream(l.ctx)
	if err != nil {
		_ = quicConn.CloseWithError(1, "stream accept failed")
		return nil, err
	}

	localAddr := newAddr(quicConn.LocalAddr().String())
	remoteAddr := newAddr(quicConn.RemoteAddr().String())
	return newConn(quicConn, stream, localAddr, remoteAddr), nil
}

// Close stops the listener. Any blocked Accept call will return with an error.
func (l *Listener) Close() error {
	l.cancel()
	return l.ql.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.ql.Addr()
}
