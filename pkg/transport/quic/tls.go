// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"crypto/tls"
	"fmt"
)

// ALPNProtocol is the ALPN protocol identifier for gRPC-over-QUIC in CFGMS.
// Both sides must agree on this value for the TLS handshake to succeed.
// Build *tls.Config using pkg/cert.CreateServerTLSConfig / CreateClientTLSConfig,
// then set NextProtos = []string{ALPNProtocol} on the result.
const ALPNProtocol = "cfgms-grpc"

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
