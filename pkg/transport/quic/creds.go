// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package quic

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc/credentials"
)

// TransportCredentials returns a gRPC TransportCredentials that reads TLS state
// from the underlying QUIC connection instead of performing its own TLS handshake.
//
// When gRPC runs over QUIC, TLS happens at the QUIC layer during connection
// establishment. gRPC does not need to (and must not) do TLS again. However,
// gRPC's peer context and AuthInfo need access to the TLS state (specifically
// peer certificates) for authorization decisions.
//
// This credentials implementation bridges the gap: its ServerHandshake reads
// the TLS state from the net.Conn (which must be a *quic.Conn) and wraps it
// as credentials.TLSInfo so that gRPC handlers can access peer certificates
// through the standard peer.FromContext() mechanism.
func TransportCredentials() credentials.TransportCredentials {
	return &quicCreds{}
}

type quicCreds struct{}

func (c *quicCreds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	info, err := authInfoFromConn(rawConn)
	if err != nil {
		return nil, nil, err
	}
	return rawConn, info, nil
}

func (c *quicCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	info, err := authInfoFromConn(rawConn)
	if err != nil {
		return nil, nil, err
	}
	return rawConn, info, nil
}

func (c *quicCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "quic-tls",
		SecurityVersion:  "1.3",
	}
}

func (c *quicCreds) Clone() credentials.TransportCredentials {
	return &quicCreds{}
}

func (c *quicCreds) OverrideServerName(_ string) error {
	return nil
}

// authInfoFromConn extracts TLS state from a *quic.Conn and wraps it as
// credentials.TLSInfo. Returns an error if the conn is not a *Conn or has
// no TLS state (which should never happen with a properly configured QUIC listener).
func authInfoFromConn(rawConn net.Conn) (credentials.AuthInfo, error) {
	qc, ok := rawConn.(*Conn)
	if !ok {
		return nil, fmt.Errorf("expected *quic.Conn, got %T", rawConn)
	}
	state := qc.TLSConnectionState()
	if state == nil {
		return nil, fmt.Errorf("QUIC connection has no TLS state")
	}
	return credentials.TLSInfo{State: *state}, nil
}
