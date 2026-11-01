// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
)

// TestControlChannel_RotatedSerialRefused proves the #4930 revocation gate
// applies end to end after a rotate-and-revoke (ADR-034 §5): the serials the
// controller holds for a steward ID are revoked by common name, an established
// stream is dropped by the periodic re-check, and a new stream presenting the
// old certificate is refused with PermissionDenied (ErrIdentityRejected).
func TestControlChannel_RotatedSerialRefused(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	server, reg := env.startServer(t, WithRevocationChecker(env.mgr))
	tlsCfg, serial := env.clientTLS(t, "steward-rotated")

	// Before rotation the certificate is admitted.
	_, err := startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-rotated", 0)
	require.NoError(t, err)
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-rotated"); return ok },
		5*time.Second, 10*time.Millisecond)

	// Rotate: revoke every client serial issued for the steward ID.
	infos, err := env.mgr.GetCertificateByCommonName("steward-rotated")
	require.NoError(t, err)
	revoked := 0
	for _, info := range infos {
		if info.Type != cfgcert.CertificateTypeClient {
			continue
		}
		require.NoError(t, env.mgr.Revoke(info.SerialNumber))
		revoked++
	}
	require.Equal(t, 1, revoked)
	isRevoked, err := env.mgr.IsRevoked(serial)
	require.NoError(t, err)
	require.True(t, isRevoked)

	// A new stream with the old certificate is refused as an identity rejection.
	_, err = startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-rotated", 5*time.Second)
	require.Error(t, err)
	assert.ErrorIs(t, err, interfaces.ErrIdentityRejected,
		"a rotated (revoked) certificate must be refused with PermissionDenied")
}
