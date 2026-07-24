// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"testing"
)

// newFuzzCA creates a fresh, initialized CA for fuzz seed generation.
func newFuzzCA(f *testing.F) *CA {
	f.Helper()
	ca, err := NewCA(&CAConfig{
		Organization: "CFGMS Fuzz Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	if err != nil {
		f.Fatalf("NewCA: %v", err)
	}
	if err := ca.Initialize(nil); err != nil {
		f.Fatalf("CA.Initialize: %v", err)
	}
	return ca
}

// FuzzParseCertificateFromPEM fuzzes ParseCertificateFromPEM (utils.go:15),
// which decodes a single PEM block and passes its DER bytes to x509.ParseCertificate.
func FuzzParseCertificateFromPEM(f *testing.F) {
	ca := newFuzzCA(f)

	// Seed: real CA certificate PEM.
	caPEM, err := ca.GetCACertificate()
	if err != nil {
		f.Fatalf("GetCACertificate: %v", err)
	}
	f.Add(caPEM)

	// Seed: real client certificate PEM.
	clientCert, err := ca.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "fuzz-client",
		ValidityDays: 1,
		KeySize:      2048,
	})
	if err != nil {
		f.Fatalf("GenerateClientCertificate: %v", err)
	}
	f.Add(clientCert.CertificatePEM)

	// Seed: real server certificate PEM.
	serverCert, err := ca.GenerateServerCertificate(&ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	if err != nil {
		f.Fatalf("GenerateServerCertificate: %v", err)
	}
	f.Add(serverCert.CertificatePEM)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Errors are expected for malformed input; panics are bugs.
		_, _ = ParseCertificateFromPEM(data)
	})
}

// FuzzParseCertificateChainFromPEM fuzzes ParseCertificateChainFromPEM (utils.go:34),
// which loops pem.Decode to parse multi-block PEM data — a good multi-block
// malformed-input target.
func FuzzParseCertificateChainFromPEM(f *testing.F) {
	ca := newFuzzCA(f)

	// Seed: single-cert chain (CA cert).
	caPEM, err := ca.GetCACertificate()
	if err != nil {
		f.Fatalf("GetCACertificate: %v", err)
	}
	f.Add(caPEM)

	// Seed: multi-cert chain (client cert + CA cert concatenated).
	clientCert, err := ca.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "fuzz-client",
		ValidityDays: 1,
		KeySize:      2048,
	})
	if err != nil {
		f.Fatalf("GenerateClientCertificate: %v", err)
	}
	chain := append(clientCert.CertificatePEM, caPEM...)
	f.Add(chain)

	// Seed: server cert + CA cert chain.
	serverCert, err := ca.GenerateServerCertificate(&ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	if err != nil {
		f.Fatalf("GenerateServerCertificate: %v", err)
	}
	serverChain := append(serverCert.CertificatePEM, caPEM...)
	f.Add(serverChain)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCertificateChainFromPEM(data)
	})
}

// FuzzParsePrivateKeyFromPEM fuzzes ParsePrivateKeyFromPEM (utils.go:66),
// which dispatches on PEM block type to x509.ParsePKCS1PrivateKey /
// ParsePKCS8PrivateKey / ParseECPrivateKey.
func FuzzParsePrivateKeyFromPEM(f *testing.F) {
	ca := newFuzzCA(f)

	// Seed: RSA private key (PKCS#1 — GenerateClientCertificate produces RSA).
	clientCert, err := ca.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "fuzz-key-client",
		ValidityDays: 1,
		KeySize:      2048,
	})
	if err != nil {
		f.Fatalf("GenerateClientCertificate: %v", err)
	}
	f.Add(clientCert.PrivateKeyPEM)

	// Seed: server private key.
	serverCert, err := ca.GenerateServerCertificate(&ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	if err != nil {
		f.Fatalf("GenerateServerCertificate: %v", err)
	}
	f.Add(serverCert.PrivateKeyPEM)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePrivateKeyFromPEM(data)
	})
}
