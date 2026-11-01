// SPDX-License-Identifier: AGPL-3.0-only
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

// validateServerTLSConfig rejects QUIC listener configurations that would
// weaken the transport's mTLS identity contract. QUIC always uses TLS 1.3, but
// requiring it explicitly prevents a caller from believing a permissive or
// incomplete tls.Config is acceptable.
func validateServerTLSConfig(cfg *tls.Config) error {
	if cfg == nil {
		return fmt.Errorf("quic: server TLS config is required")
	}
	if cfg.MinVersion < tls.VersionTLS13 {
		return fmt.Errorf("quic: server TLS minimum version must be TLS 1.3")
	}
	if len(cfg.NextProtos) == 0 {
		return fmt.Errorf("quic: server TLS config must declare an ALPN protocol")
	}
	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil && cfg.GetConfigForClient == nil {
		return fmt.Errorf("quic: server TLS certificate is required")
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		return fmt.Errorf("quic: server TLS config must require and verify client certificates")
	}
	if cfg.ClientCAs == nil && cfg.VerifyConnection == nil {
		return fmt.Errorf("quic: server TLS config requires client CA roots or a verification callback")
	}
	return nil
}

func validateClientTLSConfig(cfg *tls.Config) error {
	if cfg == nil {
		return fmt.Errorf("quic: client TLS config is required")
	}
	if cfg.MinVersion < tls.VersionTLS13 {
		return fmt.Errorf("quic: client TLS minimum version must be TLS 1.3")
	}
	if cfg.InsecureSkipVerify {
		return fmt.Errorf("quic: client TLS certificate verification cannot be disabled")
	}
	if len(cfg.NextProtos) == 0 {
		return fmt.Errorf("quic: client TLS config must declare an ALPN protocol")
	}
	if len(cfg.Certificates) == 0 && cfg.GetClientCertificate == nil {
		return fmt.Errorf("quic: client certificate is required")
	}
	return nil
}

// PeerStewardID extracts the steward ID from a TLS connection's peer certificate.
//
// The steward ID is the Common Name (CN) of the first peer certificate presented
// during the mTLS handshake. The controller uses this to identify which steward
// opened a ControlChannel, providing cryptographic identity verification.
//
// Returns an error if no peer certificates are present or if the CN is empty.
func PeerStewardID(state tls.ConnectionState) (string, error) {
	if !state.HandshakeComplete {
		return "", fmt.Errorf("TLS handshake is not complete")
	}
	if len(state.VerifiedChains) == 0 {
		return "", fmt.Errorf("peer certificate chain was not verified")
	}
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificates present: mTLS client certificate required")
	}

	cn := state.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return "", fmt.Errorf("peer certificate has empty Common Name: steward ID cannot be determined")
	}

	return cn, nil
}
