// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// alpnProtocol is the ALPN protocol identifier for gRPC-over-QUIC in CFGMS.
// Both sides must agree on this value for the TLS handshake to succeed.
const alpnProtocol = "cfgms-grpc"

// ServerTLSConfig returns a *tls.Config suitable for the QUIC listener (controller side).
//
// The config enforces:
//   - TLS 1.3 minimum (required by QUIC)
//   - mTLS: RequireAndVerifyClientCert so every steward must present a valid cert
//   - ALPN "cfgms-grpc" to distinguish this protocol on the same port
//
// The caller provides the server certificate and the CA pool used to verify
// incoming client certificates. Both arguments are required.
func ServerTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) (*tls.Config, error) {
	if clientCAs == nil {
		return nil, fmt.Errorf("clientCAs must not be nil: mTLS requires a CA pool to verify client certificates")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpnProtocol},
	}, nil
}

// ClientTLSConfig returns a *tls.Config suitable for the QUIC dialer (steward side).
//
// The config enforces:
//   - TLS 1.3 minimum
//   - Client certificate for mTLS so the controller can verify steward identity
//   - ALPN "cfgms-grpc" (must match the server config)
//
// The caller provides the client certificate and the root CA pool used to
// verify the server certificate. Both arguments are required.
func ClientTLSConfig(clientCert tls.Certificate, rootCAs *x509.CertPool) (*tls.Config, error) {
	if rootCAs == nil {
		return nil, fmt.Errorf("rootCAs must not be nil: client must verify the server certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpnProtocol},
	}, nil
}

// PeerStewardID extracts the steward ID from a TLS connection's peer certificate.
//
// The steward ID is the Common Name (CN) of the first peer certificate presented
// during the mTLS handshake. The controller uses this to identify which steward
// opened a ControlChannel, providing cryptographic identity verification.
//
// Returns an error if no peer certificates are present or if the CN is empty.
func PeerStewardID(state tls.ConnectionState) (string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificates present: mTLS client certificate required")
	}

	cn := state.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return "", fmt.Errorf("peer certificate has empty Common Name: steward ID cannot be determined")
	}

	return cn, nil
}
