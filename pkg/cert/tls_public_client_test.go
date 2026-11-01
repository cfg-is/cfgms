// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePublicClientTLSConfig_NoExtraRootsUsesSystemTrust(t *testing.T) {
	cfg, err := CreatePublicClientTLSConfig("mail.example.com", nil, tls.VersionTLS12)
	require.NoError(t, err)
	assert.Equal(t, "mail.example.com", cfg.ServerName)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.Nil(t, cfg.RootCAs, "nil RootCAs means the system trust store is used")
}

func TestCreatePublicClientTLSConfig_ExtraRootsVerifyIssuedCert(t *testing.T) {
	manager := setupTestManager(t)
	caCertPEM, err := manager.GetCACertificate()
	require.NoError(t, err)

	cfg, err := CreatePublicClientTLSConfig("relay.cfgms.local", caCertPEM, tls.VersionTLS13)
	require.NoError(t, err)
	require.NotNil(t, cfg.RootCAs)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)

	serverCert, err := manager.GenerateServerCertificate(&ServerCertConfig{
		CommonName: "relay.cfgms.local",
		DNSNames:   []string{"relay.cfgms.local"},
	})
	require.NoError(t, err)
	leaf, err := ParseCertificateFromPEM(serverCert.CertificatePEM)
	require.NoError(t, err)

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     cfg.RootCAs,
		DNSName:   "relay.cfgms.local",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "certificate issued by the extra root must verify")
}

func TestCreatePublicClientTLSConfig_Rejects(t *testing.T) {
	_, err := CreatePublicClientTLSConfig("", nil, tls.VersionTLS12)
	require.Error(t, err)

	_, err = CreatePublicClientTLSConfig("mail.example.com", nil, tls.VersionTLS11)
	require.Error(t, err)

	_, err = CreatePublicClientTLSConfig("mail.example.com", []byte("not a certificate"), tls.VersionTLS12)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate PEM")
}

func TestIsVerificationError(t *testing.T) {
	manager := setupTestManager(t)
	serverCert, err := manager.GenerateServerCertificate(&ServerCertConfig{
		CommonName: "relay.cfgms.local",
		DNSNames:   []string{"relay.cfgms.local"},
	})
	require.NoError(t, err)
	leaf, err := ParseCertificateFromPEM(serverCert.CertificatePEM)
	require.NoError(t, err)

	// Unknown authority: verify against an empty pool.
	_, uaErr := leaf.Verify(x509.VerifyOptions{Roots: x509.NewCertPool()})
	require.Error(t, uaErr)
	assert.True(t, IsVerificationError(uaErr))
	assert.True(t, IsVerificationError(fmt.Errorf("wrapped: %w", uaErr)))

	// Hostname mismatch.
	hnErr := leaf.VerifyHostname("other.example.com")
	require.Error(t, hnErr)
	assert.True(t, IsVerificationError(hnErr))

	assert.False(t, IsVerificationError(nil))
	assert.False(t, IsVerificationError(errors.New("connection reset")))
}
