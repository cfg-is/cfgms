// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"context"
	"crypto/tls"
	"errors"
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
// DoS resilience fields (Issue #931):
//
//   - MaxIncomingStreams 1: one bidirectional stream per QUIC connection is the design
//     contract (see doc.go). Restricting to 1 prevents stream-flood attacks.
//
//   - MaxIncomingUniStreams -1: disable unidirectional streams entirely. gRPC uses only
//     bidirectional streams, so any unidirectional stream is unexpected traffic.
//
//   - InitialStreamReceiveWindow 512 KB: quic-go default; set explicitly so the choice
//     is documented and testable.
//
//   - InitialConnectionReceiveWindow 1 MB: with MaxIncomingStreams=1, this is effectively
//     the same as the stream window in practice.
//
//   - Allow0RTT false: 0-RTT allows replay of early data, which is insecure for mTLS
//     connections. Always disabled.
//
//   - DisablePathMTUDiscovery false: MTU discovery is safe and useful; set explicitly
//     to document intent and prevent accidental regression.
//
// All values can be overridden by passing a custom *quic.Config to Listen/Dial.
func defaultQuicConfig() *quicgo.Config {
	return &quicgo.Config{
		MaxIdleTimeout:                 90 * time.Second,
		KeepAlivePeriod:                25 * time.Second,
		HandshakeIdleTimeout:           30 * time.Second,
		MaxIncomingStreams:             1,
		MaxIncomingUniStreams:          -1,
		InitialStreamReceiveWindow:     512 * 1024,
		InitialConnectionReceiveWindow: 1 * 1024 * 1024,
		Allow0RTT:                      false,
		DisablePathMTUDiscovery:        false,
	}
}

// requireAddressValidation is a GetConfigForClient callback that rejects any
// connection whose source address has not been verified via QUIC's Retry mechanism.
// It is defense-in-depth: Listen() also sets Transport.VerifySourceAddress so that
// the Retry round-trip always completes before this callback is invoked, ensuring
// that AddrVerified is true for every legitimate connection that reaches this gate.
func requireAddressValidation(info *quicgo.ClientInfo) (*quicgo.Config, error) {
	if !info.AddrVerified {
		return nil, errors.New("quic: address validation required")
	}
	return nil, nil
}

// Listener wraps a QUIC listener to implement net.Listener.
//
// Each accepted QUIC connection opens its first bidirectional stream, which is
// wrapped as a net.Conn for gRPC to use. gRPC handles its own HTTP/2
// multiplexing within that stream.
type Listener struct {
	ql     *quicgo.Listener
	tr     *quicgo.Transport // non-nil: Listen() owns this transport's UDP socket
	cfg    *quicgo.Config    // effective config after Listen() injection
	ctx    context.Context
	cancel context.CancelFunc
}

// Compile-time check that Listener implements net.Listener.
var _ net.Listener = (*Listener)(nil)

// Listen creates a new QUIC listener on the given address.
//
// tlsConfig must have NextProtos set to a value agreed with the client.
// If quicConfig is nil, sensible defaults (MaxIdleTimeout: 90s,
// KeepAlivePeriod: 25s, HandshakeIdleTimeout: 30s, MaxIncomingStreams: 1,
// and other DoS-resilience fields) are used. See defaultQuicConfig for rationale.
//
// Listen enforces QUIC address validation (Retry) on every inbound connection
// as an anti-amplification measure. The Transport's VerifySourceAddress triggers a
// Retry round-trip for every first-attempt connection; GetConfigForClient =
// requireAddressValidation then gates the now-verified connection. Caller-provided
// GetConfigForClient callbacks are preserved unchanged.
func Listen(addr string, tlsConfig *tls.Config, quicConfig *quicgo.Config) (*Listener, error) {
	if quicConfig == nil {
		quicConfig = defaultQuicConfig()
	}
	// Shallow copy to avoid mutating the caller's config pointer in-place.
	cfgCopy := *quicConfig
	quicConfig = &cfgCopy
	if quicConfig.GetConfigForClient == nil {
		quicConfig.GetConfigForClient = requireAddressValidation
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	// VerifySourceAddress triggers a QUIC Retry for every first-attempt
	// connection. Honest clients respond to the Retry token automatically
	// via quic-go's built-in handling. IP-spoofed senders cannot complete
	// the round-trip, so they are silently dropped after the Retry.
	tr := &quicgo.Transport{
		Conn:                udpConn,
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	ql, err := tr.Listen(tlsConfig, quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Listener{
		ql:     ql,
		tr:     tr,
		cfg:    quicConfig,
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
	err := l.ql.Close()
	if l.tr != nil {
		_ = l.tr.Close()
		// Transport.Close with createdConn=false does not close the underlying UDP
		// socket; close it explicitly to release the file descriptor.
		if cerr := l.tr.Conn.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.ql.Addr()
}
