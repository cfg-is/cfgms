// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRegistrationRequest_CarriesKeyAlgorithmAndProtection(t *testing.T) {
	ks, err := identity.NewFileKeyStoreForTesting(t.TempDir())
	require.NoError(t, err)
	pub, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	req := buildRegistrationRequest("tok", "", ks)
	assert.Equal(t, "ed25519", req.KeyAlgorithm)
	assert.Equal(t, "file", req.KeyProtectionLevel)
	assert.Equal(t, ks.DeviceID(), req.DeviceID)
	want, err := identity.EncodePublicKey(identity.AlgorithmEd25519, pub)
	require.NoError(t, err)
	assert.Equal(t, want, req.IdentityKeyPub)
	raw, err := base64.StdEncoding.DecodeString(req.IdentityKeyPub)
	require.NoError(t, err)
	assert.Len(t, raw, 32, "ed25519 key is sent raw")
}

func TestBuildRegistrationRequest_NoKeyStore(t *testing.T) {
	req := buildRegistrationRequest("tok", "", nil)
	assert.Empty(t, req.DeviceID)
	assert.Empty(t, req.KeyAlgorithm)
	assert.Empty(t, req.KeyProtectionLevel)
}

func TestEnrichApprovedWithDeviceIdentity_RecordsKeyFields(t *testing.T) {
	ks, err := identity.NewFileKeyStoreForTesting(t.TempDir())
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	reg := &approvedRegistration{}
	enrichApprovedWithDeviceIdentity(reg, ks)
	assert.Equal(t, "ed25519", reg.KeyAlgorithm)
	assert.Equal(t, "file", reg.KeyProtectionLevel)
}
