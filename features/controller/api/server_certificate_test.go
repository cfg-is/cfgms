// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
)

func newServerCertTestManager(t *testing.T) *cert.Manager {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365},
	})
	require.NoError(t, err)
	return mgr
}

func parseServerCert(t *testing.T, c *cert.Certificate) (serial string, dns []string, ips []string) {
	t.Helper()
	parsed, err := cert.ParseCertificateFromPEM(c.CertificatePEM)
	require.NoError(t, err)
	for _, ip := range parsed.IPAddresses {
		ips = append(ips, ip.String())
	}
	return parsed.SerialNumber.String(), parsed.DNSNames, ips
}

func TestGetServerCertificate_ReissuesWhenDNSNamesChange(t *testing.T) {
	s := setupTestServerWithCertMgr(t, newServerCertTestManager(t))
	s.cfg.Certificate.EnableCertManagement = true
	s.cfg.Certificate.Server.DNSNames = []string{"a.test"}
	s.cfg.Certificate.Server.IPAddresses = nil

	first, err := s.getServerCertificate()
	require.NoError(t, err)
	firstSerial, _, _ := parseServerCert(t, first)

	s.cfg.Certificate.Server.DNSNames = []string{"a.test", "b.test"}
	second, err := s.getServerCertificate()
	require.NoError(t, err)
	secondSerial, dns, _ := parseServerCert(t, second)

	assert.Contains(t, dns, "b.test")
	assert.Contains(t, dns, "a.test")
	assert.NotEqual(t, firstSerial, secondSerial)

	// The reissued certificate is now the current one and is reused.
	third, err := s.getServerCertificate()
	require.NoError(t, err)
	thirdSerial, _, _ := parseServerCert(t, third)
	assert.Equal(t, secondSerial, thirdSerial)
}

func TestGetServerCertificate_ReusesCoveringCertificate(t *testing.T) {
	s := setupTestServerWithCertMgr(t, newServerCertTestManager(t))
	s.cfg.Certificate.EnableCertManagement = true
	s.cfg.Certificate.Server.DNSNames = []string{"a.test", "b.test"}
	s.cfg.Certificate.Server.IPAddresses = []string{"10.1.2.3"}

	first, err := s.getServerCertificate()
	require.NoError(t, err)
	firstSerial, _, _ := parseServerCert(t, first)

	second, err := s.getServerCertificate()
	require.NoError(t, err)
	secondSerial, _, _ := parseServerCert(t, second)
	assert.Equal(t, firstSerial, secondSerial)

	// A subset of the issued names, in different case, is still covered.
	s.cfg.Certificate.Server.DNSNames = []string{"A.TEST"}
	s.cfg.Certificate.Server.IPAddresses = nil
	third, err := s.getServerCertificate()
	require.NoError(t, err)
	thirdSerial, _, _ := parseServerCert(t, third)
	assert.Equal(t, firstSerial, thirdSerial)
}

func TestGetServerCertificate_ReissuesWhenIPAddressesChange(t *testing.T) {
	s := setupTestServerWithCertMgr(t, newServerCertTestManager(t))
	s.cfg.Certificate.EnableCertManagement = true
	s.cfg.Certificate.Server.DNSNames = []string{"a.test"}
	s.cfg.Certificate.Server.IPAddresses = []string{"10.1.2.3"}

	first, err := s.getServerCertificate()
	require.NoError(t, err)
	firstSerial, _, _ := parseServerCert(t, first)

	s.cfg.Certificate.Server.IPAddresses = []string{"10.1.2.3", "10.9.9.9"}
	second, err := s.getServerCertificate()
	require.NoError(t, err)
	secondSerial, _, ips := parseServerCert(t, second)

	assert.Contains(t, ips, "10.9.9.9")
	assert.NotEqual(t, firstSerial, secondSerial)
}

func TestGetServerCertificate_ManagementDisabledKeepsCertificate(t *testing.T) {
	s := setupTestServerWithCertMgr(t, newServerCertTestManager(t))
	s.cfg.Certificate.EnableCertManagement = true
	s.cfg.Certificate.Server.DNSNames = []string{"a.test"}
	s.cfg.Certificate.Server.IPAddresses = nil

	first, err := s.getServerCertificate()
	require.NoError(t, err)
	firstSerial, _, _ := parseServerCert(t, first)

	s.cfg.Certificate.EnableCertManagement = false
	s.cfg.Certificate.Server.DNSNames = []string{"a.test", "b.test"}
	second, err := s.getServerCertificate()
	require.NoError(t, err)
	secondSerial, _, _ := parseServerCert(t, second)
	assert.Equal(t, firstSerial, secondSerial)
}

func TestMissingCertificateSANs(t *testing.T) {
	s := setupTestServerWithCertMgr(t, newServerCertTestManager(t))
	s.cfg.Certificate.EnableCertManagement = true
	s.cfg.Certificate.Server.DNSNames = []string{"a.test"}
	s.cfg.Certificate.Server.IPAddresses = nil
	c, err := s.getServerCertificate()
	require.NoError(t, err)

	missing, err := s.missingServerCertSANs(c)
	require.NoError(t, err)
	assert.Empty(t, missing)

	_, err = s.missingServerCertSANs(&cert.Certificate{CertificatePEM: []byte("not pem")})
	assert.Error(t, err)
}
