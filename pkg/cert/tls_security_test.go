// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cert

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateServerCertificate(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name    string
		leaf    *x509.Certificate
		wantErr string
	}{
		{
			name: "valid server certificate",
			leaf: &x509.Certificate{
				NotBefore:   now.Add(-time.Minute),
				NotAfter:    now.Add(time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
		},
		{
			name: "expired",
			leaf: &x509.Certificate{
				NotBefore:   now.Add(-2 * time.Hour),
				NotAfter:    now.Add(-time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			wantErr: "expired",
		},
		{
			name: "not yet valid",
			leaf: &x509.Certificate{
				NotBefore:   now.Add(time.Hour),
				NotAfter:    now.Add(2 * time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			wantErr: "not valid before",
		},
		{
			name: "client authentication only",
			leaf: &x509.Certificate{
				NotBefore:   now.Add(-time.Minute),
				NotAfter:    now.Add(time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			wantErr: "does not permit TLS server authentication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateServerCertificate(tls.Certificate{
				Certificate: [][]byte{{0x01}},
				Leaf:        tt.leaf,
			}, now)
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.Same(t, tt.leaf, got)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			assert.Nil(t, got)
		})
	}
}

func TestValidateServerCertificate_RejectsEmptyChain(t *testing.T) {
	_, err := ValidateServerCertificate(tls.Certificate{}, time.Now())
	require.ErrorContains(t, err, "chain is empty")
}
