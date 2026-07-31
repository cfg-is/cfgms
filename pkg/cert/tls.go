// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// LoadTLSCertificate loads a TLS certificate from PEM-encoded certificate and key
func LoadTLSCertificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load X509 key pair: %w", err)
	}
	return cert, nil
}

// CertPoolFromPEM builds an x509 verification pool from one or more PEM-encoded
// CA certificates. It is the central-provider entry point for callers that need a
// verification pool on its own rather than as part of a tls.Config — for example
// verifying that an operator signing certificate chains to the controller CA.
// Callers outside pkg/cert must use this instead of constructing pools directly
// (enforced by make check-architecture).
//
// Returns an error when caCertPEM is empty or contains no parseable certificate,
// so callers can distinguish "no roots configured" from "roots were misconfigured".
func CertPoolFromPEM(caCertPEM []byte) (*x509.CertPool, error) {
	if len(caCertPEM) == 0 {
		return nil, fmt.Errorf("no CA certificate PEM provided")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate PEM")
	}

	return pool, nil
}

// ValidateServerCertificate rejects certificates that cannot currently be used
// for TLS server authentication. tls.X509KeyPair only proves that the PEM and
// private key are syntactically valid and match; it does not reject certificates
// that are expired, not yet valid, or scoped only for a different EKU.
func ValidateServerCertificate(cert tls.Certificate, now time.Time) (*x509.Certificate, error) {
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("server certificate chain is empty")
	}

	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse server certificate: %w", err)
		}
	}

	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("server certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("server certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	if len(leaf.ExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
				break
			}
		}
		if !serverAuth {
			return nil, fmt.Errorf("server certificate does not permit TLS server authentication")
		}
	}

	return leaf, nil
}

// CreateServerTLSConfig creates a TLS config for a server with mTLS support
// Parameters:
// - serverCertPEM: Server certificate in PEM format
// - serverKeyPEM: Server private key in PEM format
// - caCertPEM: CA certificate for client verification (optional, nil to disable client auth)
// - minVersion: Minimum TLS version (e.g., tls.VersionTLS12, tls.VersionTLS13)
func CreateServerTLSConfig(serverCertPEM, serverKeyPEM, caCertPEM []byte, minVersion uint16) (*tls.Config, error) {
	// Enforce minimum TLS 1.2 for security
	if minVersion < tls.VersionTLS12 {
		return nil, fmt.Errorf("minimum TLS version must be 1.2 or higher, got 0x%04x", minVersion)
	}

	// Load server certificate
	cert, err := LoadTLSCertificate(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}
	if _, err := ValidateServerCertificate(cert, time.Now()); err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion, // #nosec G402 -- TLS 1.2+ enforced by validation above (line 26-28)
	}

	// Configure client authentication if CA cert is provided
	if caCertPEM != nil {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caCertPool
	} else {
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	return tlsConfig, nil
}

// CreateClientTLSConfig creates a TLS config for a client with mTLS support
// Parameters:
// - clientCertPEM: Client certificate in PEM format (optional, nil for server auth only)
// - clientKeyPEM: Client private key in PEM format (optional, nil for server auth only)
// - caCertPEM: CA certificate for server verification
// - serverName: Server name for SNI and certificate verification
// - minVersion: Minimum TLS version (e.g., tls.VersionTLS12, tls.VersionTLS13)
func CreateClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM []byte, serverName string, minVersion uint16) (*tls.Config, error) {
	// Enforce minimum TLS 1.2 for security
	if minVersion < tls.VersionTLS12 {
		return nil, fmt.Errorf("minimum TLS version must be 1.2 or higher, got 0x%04x", minVersion)
	}

	tlsConfig := &tls.Config{
		MinVersion: minVersion, // #nosec G402 -- TLS 1.2+ enforced by validation above (line 66-68)
		ServerName: serverName,
	}

	// Load client certificate if provided (for mTLS)
	if clientCertPEM != nil && clientKeyPEM != nil {
		cert, err := LoadTLSCertificate(clientCertPEM, clientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate for server verification
	if caCertPEM != nil {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// CreateBasicTLSConfig creates a basic TLS config with custom settings
// This is useful when you need more control over the TLS configuration
func CreateBasicTLSConfig(certPEM, keyPEM []byte, minVersion uint16) (*tls.Config, error) {
	// Enforce minimum TLS 1.2 for security
	if minVersion < tls.VersionTLS12 {
		return nil, fmt.Errorf("minimum TLS version must be 1.2 or higher, got 0x%04x", minVersion)
	}

	if certPEM != nil && keyPEM != nil {
		cert, err := LoadTLSCertificate(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
		if _, err := ValidateServerCertificate(cert, time.Now()); err != nil {
			return nil, err
		}

		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   minVersion, // #nosec G402 -- TLS 1.2+ enforced by validation above (line 100-102)
		}, nil
	}

	return &tls.Config{
		MinVersion: minVersion, // #nosec G402 -- TLS 1.2+ enforced by validation above (line 100-102)
	}, nil
}

// CreateProbeClientTLSConfig creates a minimal TLS config for unauthenticated
// liveness probing. insecureSkipVerify must be true only when the probe target
// uses a self-signed cert and server identity is not required (e.g. cutover
// smoketests that confirm the API process is alive, not that it is authentic).
// MinVersion is always TLS 1.2.
func CreateProbeClientTLSConfig(insecureSkipVerify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: insecureSkipVerify, // #nosec G402 -- intentional for unauthenticated liveness probing
		MinVersion:         tls.VersionTLS12,   // #nosec G402 -- TLS 1.2 minimum enforced
	}
}

// CreateOnDemandClientTLSConfig creates a client TLS config that fetches the client
// certificate on every TLS handshake via the Manager, enabling transparent rotation.
// When caCertPEM is non-empty it is used for server verification; otherwise system roots apply.
func (m *Manager) CreateOnDemandClientTLSConfig(caCertPEM []byte, minVersion uint16) (*tls.Config, error) {
	if minVersion < tls.VersionTLS12 {
		return nil, fmt.Errorf("minimum TLS version must be 1.2 or higher, got 0x%04x", minVersion)
	}
	tlsConfig := &tls.Config{
		MinVersion: minVersion, // #nosec G402 -- TLS 1.2+ enforced by validation above
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return m.GetClientCertificate(context.Background())
		},
	}
	if len(caCertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertPEM) {
			return nil, fmt.Errorf("failed to append CA certificate to pool")
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}
