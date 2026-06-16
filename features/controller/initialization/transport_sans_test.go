// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package initialization

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/controller/config"
)

// TestTransportCertSANs_FleetControllerHostnameIncluded asserts that the
// fleet-e2e controller hostname propagates into the cert SAN list. This is the
// regression that broke fleet-e2e in PR #1820: --init minted the internal cert
// before CFGMS_EXTERNAL_HOSTNAME or cfg.Certificate.Server.DNSNames were merged
// in, leaving the cert with default SANs only and stewards failing TLS
// verification when dialing the controller by "fleet-controller".
func TestTransportCertSANs_FleetControllerHostnameIncluded(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "fleet-controller")

	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			Server: &config.ServerCertificateConfig{
				CommonName:  "fleet-controller",
				DNSNames:    []string{"fleet-controller", "localhost"},
				IPAddresses: []string{"127.0.0.1"},
			},
		},
	}

	dnsNames, ipAddresses := TransportCertSANs(cfg)
	assert.Contains(t, dnsNames, "fleet-controller", "expected fleet-controller DNS SAN from external hostname / server config")
	assert.Contains(t, dnsNames, "localhost")
	assert.Contains(t, dnsNames, "cfgms-internal")
	assert.Contains(t, dnsNames, "controller-standalone")
	assert.Contains(t, ipAddresses, "127.0.0.1")
}

func TestTransportCertSANs_NilConfigReturnsDefaults(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")

	dnsNames, ipAddresses := TransportCertSANs(nil)
	assert.Equal(t, []string{"localhost", "cfgms-internal", "controller-standalone"}, dnsNames)
	assert.Equal(t, []string{"127.0.0.1", "0.0.0.0"}, ipAddresses)
}

func TestTransportCertSANs_ExternalHostnameAsIP(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "192.0.2.10")

	dnsNames, ipAddresses := TransportCertSANs(nil)
	assert.NotContains(t, dnsNames, "192.0.2.10", "IP-literal hostname must not be classified as DNS SAN")
	assert.Contains(t, ipAddresses, "192.0.2.10")
}

func TestTransportCertSANs_InternalAndServerMerge(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")

	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			Server: &config.ServerCertificateConfig{
				DNSNames:    []string{"server-name"},
				IPAddresses: []string{"10.0.0.1"},
			},
			Internal: &config.InternalCertConfig{
				DNSNames:    []string{"internal-name"},
				IPAddresses: []string{"10.0.0.2"},
			},
		},
	}

	dnsNames, ipAddresses := TransportCertSANs(cfg)
	assert.Contains(t, dnsNames, "server-name")
	assert.Contains(t, dnsNames, "internal-name")
	assert.Contains(t, ipAddresses, "10.0.0.1")
	assert.Contains(t, ipAddresses, "10.0.0.2")
}

func TestTransportCertSANs_DedupesAndPreservesOrder(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "localhost")

	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			Server: &config.ServerCertificateConfig{
				DNSNames: []string{"localhost", "fleet-controller"},
			},
		},
	}

	dnsNames, _ := TransportCertSANs(cfg)

	count := 0
	for _, n := range dnsNames {
		if n == "localhost" {
			count++
		}
	}
	assert.Equal(t, 1, count, "localhost must appear once even when present in defaults, config, and env")
	assert.Equal(t, "localhost", dnsNames[0], "first-seen order is preserved across merge")
}
