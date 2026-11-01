// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	stewardreg "github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleRegister_StewardFileKeyRequest posts the request shape the steward builds
// (wire type from features/steward/registration, key from a real FileKeyStore) to the
// real handler and checks key_algorithm and key_protection_level are stored.
func TestHandleRegister_StewardFileKeyRequest(t *testing.T) {
	ks, err := identity.NewFileKeyStoreForTesting(t.TempDir())
	require.NoError(t, err)
	pub, alg, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	encoded, err := identity.EncodePublicKey(alg, pub)
	require.NoError(t, err)

	tokenStore := newTestRegistrationStore(t)
	server, stewards := newHandleRegisterServerWithStewardStore(t, tokenStore, newTestCertManager(t))
	server.SetApprovalHook(&AlwaysApproveHook{})
	tok := &registration.Token{Token: "cfgms_reg_steward_req", TenantID: testTenantID, ControllerURL: "grpc://controller:7443"}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	body, err := json.Marshal(stewardreg.RegistrationRequest{
		Token:              tok.Token,
		CSRPEM:             testValidCSRPEM,
		DeviceID:           ks.DeviceID(),
		IdentityKeyPub:     encoded,
		KeyAlgorithm:       string(ks.Algorithm()),
		KeyProtectionLevel: string(ks.ProtectionLevel()),
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleRegister(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp RegistrationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	stored, err := stewards.GetSteward(context.Background(), resp.StewardID)
	require.NoError(t, err)
	assert.Equal(t, "ed25519", stored.KeyAlgorithm)
	assert.Equal(t, "file", stored.KeyProtectionLevel)
	assert.Equal(t, ks.DeviceID(), stored.DeviceID)
}
