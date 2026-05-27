// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/controller/config"
)

// TestGRPCControlPlaneServerSANs_Defaults verifies the transport defaults are
// always present even when no certificate config is supplied.
func TestGRPCControlPlaneServerSANs_Defaults(t *testing.T) {
	dnsNames, ipAddresses := grpcControlPlaneServerSANs(nil)

	assert.Subset(t, dnsNames, []string{"localhost", "cfgms-grpc-server", "controller-standalone"})
	assert.Subset(t, ipAddresses, []string{"127.0.0.1", "0.0.0.0"})
}

// TestGRPCControlPlaneServerSANs_MergesConfiguredServerSANs verifies that
// operator-configured server SANs are merged into the generated certificate.
func TestGRPCControlPlaneServerSANs_MergesConfiguredServerSANs(t *testing.T) {
	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			Server: &config.ServerCertificateConfig{
				DNSNames:    []string{"fleet-controller", "controller.example.com"},
				IPAddresses: []string{"10.0.0.5"},
			},
		},
	}

	dnsNames, ipAddresses := grpcControlPlaneServerSANs(cfg)

	assert.Contains(t, dnsNames, "fleet-controller")
	assert.Contains(t, dnsNames, "controller.example.com")
	assert.Contains(t, dnsNames, "localhost", "transport defaults must be preserved")
	assert.Contains(t, ipAddresses, "10.0.0.5")
	assert.Contains(t, ipAddresses, "127.0.0.1", "transport defaults must be preserved")
}

// TestGRPCControlPlaneServerSANs_EmptyServerConfig verifies that a non-nil
// certificate.server section with empty SAN slices leaves the transport
// defaults intact and adds nothing.
func TestGRPCControlPlaneServerSANs_EmptyServerConfig(t *testing.T) {
	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			Server: &config.ServerCertificateConfig{
				DNSNames:    []string{},
				IPAddresses: []string{},
			},
		},
	}

	dnsNames, ipAddresses := grpcControlPlaneServerSANs(cfg)

	assert.Equal(t, []string{"localhost", "cfgms-grpc-server", "controller-standalone"}, dnsNames)
	assert.Equal(t, []string{"127.0.0.1", "0.0.0.0"}, ipAddresses)
}

// TestGRPCControlPlaneServerSANs_ExternalHostname verifies that
// CFGMS_EXTERNAL_HOSTNAME is added as a DNS SAN when it is a hostname.
func TestGRPCControlPlaneServerSANs_ExternalHostname(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "fleet-controller")

	dnsNames, _ := grpcControlPlaneServerSANs(nil)

	assert.Contains(t, dnsNames, "fleet-controller")
}

// TestGRPCControlPlaneServerSANs_ExternalHostnameIP verifies that an IP literal
// in CFGMS_EXTERNAL_HOSTNAME is classified as an IP SAN, not a DNS SAN.
func TestGRPCControlPlaneServerSANs_ExternalHostnameIP(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "192.0.2.10")

	dnsNames, ipAddresses := grpcControlPlaneServerSANs(nil)

	assert.Contains(t, ipAddresses, "192.0.2.10")
	assert.NotContains(t, dnsNames, "192.0.2.10")
}

// TestGRPCControlPlaneServerSANs_Deduplicates verifies that a SAN appearing in
// both the defaults and the operator config is emitted only once.
func TestGRPCControlPlaneServerSANs_Deduplicates(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "localhost")

	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			Server: &config.ServerCertificateConfig{
				DNSNames: []string{"localhost", "fleet-controller"},
			},
		},
	}

	dnsNames, _ := grpcControlPlaneServerSANs(cfg)

	count := 0
	for _, n := range dnsNames {
		if n == "localhost" {
			count++
		}
	}
	assert.Equal(t, 1, count, "localhost must not be duplicated across defaults, config, and env")
}

// TestDedupeSANs verifies empty values are dropped and order is preserved.
func TestDedupeSANs(t *testing.T) {
	got := dedupeSANs([]string{"a", "", "b", "a", " ", "c", "b"})
	assert.Equal(t, []string{"a", "b", "c"}, got)
}
