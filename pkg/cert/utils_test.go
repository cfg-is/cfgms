// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestCert returns a minimal *x509.Certificate with the given validity window.
// The cert does not need to be signed for GetCertificateInfo; it only reads fields.
func makeTestCert(notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(42),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
}

func TestGetCertificateInfo_DaysUntilExpiration_IsRemainingNotLifetime(t *testing.T) {
	// Cert issued 300 days ago, valid for 365 days → ~65 days remaining.
	notBefore := time.Now().Add(-300 * 24 * time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	cert := makeTestCert(notBefore, notAfter)
	info := GetCertificateInfo(cert)
	require.NotNil(t, info)

	// Must be the remaining days (~65), not the total lifetime (365).
	assert.InDelta(t, 65, info.DaysUntilExpiration, 1,
		"DaysUntilExpiration should be remaining days (~65), got %d", info.DaysUntilExpiration)
}

func TestGetCertificateInfo_IsValid_ReflectsCurrentTime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantValid bool
	}{
		{
			name:      "currently valid",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(30 * 24 * time.Hour),
			wantValid: true,
		},
		{
			name:      "expired",
			notBefore: now.Add(-365 * 24 * time.Hour),
			notAfter:  now.Add(-1 * time.Hour),
			wantValid: false,
		},
		{
			name:      "not yet valid",
			notBefore: now.Add(24 * time.Hour),
			notAfter:  now.Add(365 * 24 * time.Hour),
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := makeTestCert(tt.notBefore, tt.notAfter)
			info := GetCertificateInfo(cert)
			require.NotNil(t, info)
			assert.Equal(t, tt.wantValid, info.IsValid)
		})
	}
}

func TestGetCertificateInfo_NeedsRenewal(t *testing.T) {
	now := time.Now()

	// Cert expiring in 15 days → needs renewal.
	soonCert := makeTestCert(now.Add(-350*24*time.Hour), now.Add(15*24*time.Hour))
	info := GetCertificateInfo(soonCert)
	require.NotNil(t, info)
	assert.True(t, info.NeedsRenewal, "cert expiring in 15 days should need renewal")

	// Cert expiring in 60 days → does not need renewal yet.
	laterCert := makeTestCert(now.Add(-300*24*time.Hour), now.Add(60*24*time.Hour))
	info = GetCertificateInfo(laterCert)
	require.NotNil(t, info)
	assert.False(t, info.NeedsRenewal, "cert expiring in 60 days should not need renewal")
}

func TestGetCertificateInfo_ExpiredCert_DaysFlooredAtZero(t *testing.T) {
	now := time.Now()
	cert := makeTestCert(now.Add(-365*24*time.Hour), now.Add(-1*time.Hour))
	info := GetCertificateInfo(cert)
	require.NotNil(t, info)
	assert.Equal(t, 0, info.DaysUntilExpiration, "expired cert DaysUntilExpiration must be clamped to 0, not negative")
}

func TestGetCertificateInfo_NilCert(t *testing.T) {
	assert.Nil(t, GetCertificateInfo(nil))
}
