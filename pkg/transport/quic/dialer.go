// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package quic

import (
	"context"
	"crypto/tls"
	"net"
	"strings"

	quicgo "github.com/quic-go/quic-go"
)

// Dial establishes a QUIC connection to addr and opens the first bidirectional
// stream, returning it as a net.Conn.
//
// tlsConfig must have NextProtos set to a value matching the server's config.
// If quicConfig is nil, sensible defaults are used.
//
// The returned net.Conn is suitable for use as a gRPC transport connection when
// paired with grpc.WithTransportCredentials(insecure.NewCredentials()), since
// TLS is handled at the QUIC layer.
func Dial(ctx context.Context, addr string, tlsConfig *tls.Config, quicConfig *quicgo.Config) (net.Conn, error) {
	if quicConfig == nil {
		quicConfig = defaultQuicConfig()
	}
	quicConn, err := quicgo.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(1, "stream open failed")
		return nil, err
	}

	localAddr := newAddr(quicConn.LocalAddr().String())
	remoteAddr := newAddr(quicConn.RemoteAddr().String())
	return newConn(quicConn, stream, localAddr, remoteAddr), nil
}

// NewDialer returns a function compatible with grpc.WithContextDialer.
//
// Example:
//
//	conn, err := grpc.NewClient(addr,
//	    grpc.WithContextDialer(quic.NewDialer(tlsConfig, nil)),
//	    grpc.WithTransportCredentials(insecure.NewCredentials()),
//	)
func NewDialer(tlsConfig *tls.Config, quicConfig *quicgo.Config) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return Dial(ctx, addr, tlsConfig, quicConfig)
	}
}

// DialTarget wraps a host:port address with gRPC's passthrough resolver scheme.
//
// grpc.NewClient defaults to the dns resolver, which resolves the host to an IP
// address before invoking a custom contextDialer. quic-go's DialAddr then
// verifies the server certificate against that IP literal rather than the
// original hostname, so mTLS fails whenever the certificate carries DNS SANs
// (the normal case for a controller addressed by hostname). Routing through the
// passthrough resolver hands the address to the dialer verbatim, preserving the
// hostname for QUIC's TLS verification.
//
// An address that already carries a resolver scheme (contains "://") is
// returned unchanged.
func DialTarget(addr string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	return "passthrough:///" + addr
}
