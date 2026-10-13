// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/registration"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// countingVerifier wraps the production verifier and counts invocations, so tests
// can assert that a refused request never reached signature verification.
type countingVerifier struct {
	calls atomic.Int32
	inner defaultPoPVerifier
}

func (c *countingVerifier) Verify(alg KeyAlgorithm, pub crypto.PublicKey, digest, sig []byte) bool {
	c.calls.Add(1)
	return c.inner.Verify(alg, pub, digest, sig)
}

// p256Identity is a real P-256 device key with its wire encoding and DeviceID.
type p256Identity struct {
	priv     *ecdsa.PrivateKey
	der      []byte
	deviceID string
}

func newP256Identity(t *testing.T) p256Identity {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(der)
	return p256Identity{priv: priv, der: der, deviceID: hex.EncodeToString(sum[:])}
}

func (p p256Identity) sign(t *testing.T, digest []byte) []byte {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, p.priv, digest)
	require.NoError(t, err)
	return sig
}

// popDigest is the ADR-011 PoP digest: sha256(nonce || device_id || server_ts_be).
func popDigest(t *testing.T, deviceID string, ch *RefreshChallengeResponse) []byte {
	t.Helper()
	nonceBytes, err := base64.RawURLEncoding.DecodeString(ch.Nonce)
	require.NoError(t, err)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ch.ServerTS)
	h := sha256.New()
	h.Write(nonceBytes)
	h.Write([]byte(deviceID))
	h.Write(ts[:])
	return h.Sum(nil)
}

func completeRequest(ch *RefreshChallengeResponse, sig []byte, alg string) RefreshCompleteRequest {
	return RefreshCompleteRequest{
		TenantID:     testTenantID,
		Nonce:        ch.Nonce,
		IssuedAt:     int64(ch.ServerTS),
		Signature:    base64.RawURLEncoding.EncodeToString(sig),
		CSRPEM:       testValidCSRPEM,
		KeyAlgorithm: alg,
	}
}

// TestDefaultPoPVerifier_P256Vector pins the P-256 PoP construction shared with the
// steward: an ASN.1 DER ECDSA signature over the raw 32-byte digest, with no
// second hash.
func TestDefaultPoPVerifier_P256Vector(t *testing.T) {
	id := newP256Identity(t)
	digest := sha256.Sum256([]byte("pop-vector"))
	sig := id.sign(t, digest[:])
	pub, err := parseDevicePublicKey(KeyAlgorithmECDSAP256, id.der)
	require.NoError(t, err)

	v := defaultPoPVerifier{}
	assert.True(t, v.Verify(KeyAlgorithmECDSAP256, pub, digest[:], sig))

	// A signature over sha256(digest) (a second hash) must not verify.
	double := sha256.Sum256(digest[:])
	assert.False(t, v.Verify(KeyAlgorithmECDSAP256, pub, digest[:], id.sign(t, double[:])))
	// An algorithm/key type mismatch must not verify.
	assert.False(t, v.Verify(KeyAlgorithmEd25519, pub, digest[:], sig))
	assert.False(t, v.Verify(KeyAlgorithm("rsa"), pub, digest[:], sig))
}

func TestHandleRefreshComplete_P256(t *testing.T) {
	id := newP256Identity(t)
	otherP256 := newP256Identity(t)
	edPub, edPriv := newTestEd25519KeyPair(t)

	tests := []struct {
		name       string
		record     business.StewardRecord
		reqAlg     string
		sign       func(t *testing.T, digest []byte) []byte
		wantStatus int
		wantReason string
		wantCalls  int32
	}{
		{
			name:       "valid P-256 PoP verifies",
			record:     business.StewardRecord{IdentityKeyPub: id.der, KeyAlgorithm: "ecdsa-p256"},
			reqAlg:     "ecdsa-p256",
			sign:       id.sign,
			wantStatus: http.StatusAccepted,
			wantCalls:  1,
		},
		{
			name:       "signature by a different P-256 key",
			record:     business.StewardRecord{IdentityKeyPub: id.der, KeyAlgorithm: "ecdsa-p256"},
			reqAlg:     "ecdsa-p256",
			sign:       otherP256.sign,
			wantStatus: http.StatusUnauthorized,
			wantReason: "invalid_pop",
			wantCalls:  1,
		},
		{
			name:       "Ed25519 signature against a P-256 record",
			record:     business.StewardRecord{IdentityKeyPub: id.der, KeyAlgorithm: "ecdsa-p256"},
			reqAlg:     "ecdsa-p256",
			sign:       func(_ *testing.T, d []byte) []byte { return ed25519.Sign(edPriv, d) },
			wantStatus: http.StatusUnauthorized,
			wantReason: "invalid_pop",
			wantCalls:  1,
		},
		{
			name:       "P-256 signature against an Ed25519 record",
			record:     business.StewardRecord{IdentityKeyPub: []byte(edPub)},
			reqAlg:     "",
			sign:       id.sign,
			wantStatus: http.StatusUnauthorized,
			wantReason: "invalid_pop",
			wantCalls:  1,
		},
		{
			name:       "algorithm change ed25519 record, ecdsa-p256 request",
			record:     business.StewardRecord{IdentityKeyPub: []byte(edPub)},
			reqAlg:     "ecdsa-p256",
			sign:       id.sign,
			wantStatus: http.StatusUnauthorized,
			wantReason: "key_algorithm_mismatch",
		},
		{
			name:       "algorithm change ecdsa-p256 record, absent request",
			record:     business.StewardRecord{IdentityKeyPub: id.der, KeyAlgorithm: "ecdsa-p256"},
			reqAlg:     "",
			sign:       id.sign,
			wantStatus: http.StatusUnauthorized,
			wantReason: "key_algorithm_mismatch",
		},
		{
			name:       "unknown request algorithm",
			record:     business.StewardRecord{IdentityKeyPub: []byte(edPub)},
			reqAlg:     "rsa",
			sign:       id.sign,
			wantStatus: http.StatusUnauthorized,
			wantReason: "key_algorithm_mismatch",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t, nil)
			ver := &countingVerifier{}
			f.server.SetPoPVerifier(ver)
			rec := tc.record
			rec.ID, rec.DeviceID, rec.TenantID, rec.Status = "steward-alg", testDeviceID, testTenantID, business.StewardStatusActive
			f.addSteward(t, &rec)

			ch := issueChallenge(t, f.server, testDeviceID, testTenantID)
			resp := postComplete(f.server, testDeviceID, completeRequest(ch, tc.sign(t, popDigest(t, testDeviceID, ch)), tc.reqAlg))

			assert.Equal(t, tc.wantStatus, resp.Code, resp.Body.String())
			assert.Equal(t, tc.wantCalls, ver.calls.Load(), "verifier call count")
			if tc.wantReason != "" {
				entry := f.findAuditAction(t, "refresh_rejected")
				require.NotNil(t, entry)
				assert.Equal(t, tc.wantReason, entry.Details["reason"])
			}
		})
	}
}

func TestHandleRefreshComplete_RevokedP256NeverReachesVerifier(t *testing.T) {
	id := newP256Identity(t)
	f := newRefreshFixture(t, nil)
	ver := &countingVerifier{}
	f.server.SetPoPVerifier(ver)
	f.addSteward(t, &business.StewardRecord{
		ID: "steward-rev-p256", DeviceID: testDeviceID, TenantID: testTenantID,
		Status: business.StewardStatusRevoked, IdentityKeyPub: id.der, KeyAlgorithm: "ecdsa-p256",
	})
	f.plantNonce(t, testDeviceID)

	rec := postComplete(f.server, testDeviceID, RefreshCompleteRequest{
		TenantID: testTenantID, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IssuedAt: 1, Signature: base64.RawURLEncoding.EncodeToString([]byte("x")), KeyAlgorithm: "ecdsa-p256",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, ver.calls.Load(), "a revoked device must never reach the PoP verifier")
}

func TestHandleRefreshClaim_P256Algorithm(t *testing.T) {
	id := newP256Identity(t)
	edPub, _ := newTestEd25519KeyPair(t)

	claim := func(t *testing.T, f *refreshFixture, deviceID, alg string, sign func([]byte) []byte) *httptest.ResponseRecorder {
		ch := issueChallenge(t, f.server, deviceID, testTenantID)
		body, _ := json.Marshal(RefreshClaimRequest{
			PendingID: "no-such-pending", Nonce: ch.Nonce, IssuedAt: int64(ch.ServerTS),
			Signature:    base64.RawURLEncoding.EncodeToString(sign(popDigest(t, deviceID, ch))),
			KeyAlgorithm: alg,
		})
		r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+deviceID+"/refresh/claim", bytes.NewReader(body))
		r = mux.SetURLVars(r, map[string]string{"device_id": deviceID})
		rec := httptest.NewRecorder()
		f.server.handleRefreshClaim(rec, r)
		return rec
	}

	t.Run("valid P-256 proof passes the PoP gate", func(t *testing.T) {
		f := newRefreshFixture(t, nil)
		ver := &countingVerifier{}
		f.server.SetPoPVerifier(ver)
		f.addSteward(t, &business.StewardRecord{ID: "s", DeviceID: testDeviceID, TenantID: testTenantID,
			Status: business.StewardStatusActive, IdentityKeyPub: id.der, KeyAlgorithm: "ecdsa-p256"})
		rec := claim(t, f, testDeviceID, "ecdsa-p256", func(d []byte) []byte { return id.sign(t, d) })
		// Past PoP the unknown pending ID is a 404, not the 401 of a failed proof.
		assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
		assert.Equal(t, int32(1), ver.calls.Load())
	})
	t.Run("algorithm change is refused before the verifier", func(t *testing.T) {
		f := newRefreshFixture(t, nil)
		ver := &countingVerifier{}
		f.server.SetPoPVerifier(ver)
		f.addSteward(t, &business.StewardRecord{ID: "s", DeviceID: testDeviceID, TenantID: testTenantID,
			Status: business.StewardStatusActive, IdentityKeyPub: []byte(edPub)})
		rec := claim(t, f, testDeviceID, "ecdsa-p256", func(d []byte) []byte { return id.sign(t, d) })
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Zero(t, ver.calls.Load())
	})
}

// ---- Registration ------------------------------------------------------------

func TestHandleRegister_KeyAlgorithmValidation(t *testing.T) {
	id := newP256Identity(t)
	other := newP256Identity(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	rawEd, _ := newTestEd25519KeyPair(t)

	b64 := base64.StdEncoding.EncodeToString
	devID := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	tests := []struct {
		name       string
		req        RegistrationRequest
		wantStatus int
	}{
		{"valid P-256", RegistrationRequest{DeviceID: id.deviceID, IdentityKeyPub: b64(id.der), KeyAlgorithm: "ecdsa-p256"}, http.StatusOK},
		{"mismatched device id", RegistrationRequest{DeviceID: other.deviceID, IdentityKeyPub: b64(id.der), KeyAlgorithm: "ecdsa-p256"}, http.StatusBadRequest},
		{"non-P-256 curve", RegistrationRequest{DeviceID: devID(p384DER), IdentityKeyPub: b64(p384DER), KeyAlgorithm: "ecdsa-p256"}, http.StatusBadRequest},
		{"RSA key", RegistrationRequest{DeviceID: devID(rsaDER), IdentityKeyPub: b64(rsaDER), KeyAlgorithm: "ecdsa-p256"}, http.StatusBadRequest},
		{"raw 32-byte key", RegistrationRequest{DeviceID: devID(rawEd), IdentityKeyPub: b64(rawEd), KeyAlgorithm: "ecdsa-p256"}, http.StatusBadRequest},
		{"unknown algorithm", RegistrationRequest{DeviceID: id.deviceID, IdentityKeyPub: b64(id.der), KeyAlgorithm: "rsa-2048"}, http.StatusBadRequest},
		{"PKIX DER under ed25519", RegistrationRequest{DeviceID: id.deviceID, IdentityKeyPub: b64(id.der), KeyAlgorithm: "ed25519"}, http.StatusBadRequest},
		{"explicit ed25519", RegistrationRequest{DeviceID: testValidDeviceID, IdentityKeyPub: testValidIdentityKeyPub, KeyAlgorithm: "ed25519"}, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenStore := newTestRegistrationStore(t)
			server, stewards := newHandleRegisterServerWithStewardStore(t, tokenStore, newTestCertManager(t))
			server.SetApprovalHook(&AlwaysApproveHook{})
			tok := &registration.Token{Token: "cfgms_reg_alg", TenantID: testTenantID, ControllerURL: "grpc://controller:7443"}
			require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

			tc.req.Token, tc.req.CSRPEM = tok.Token, testValidCSRPEM
			rec := postRegisterWithBody(server, tc.req)
			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())

			_, lookupErr := stewards.GetStewardByDeviceID(context.Background(), tc.req.DeviceID)
			if tc.wantStatus == http.StatusOK {
				require.NoError(t, lookupErr)
				var resp RegistrationResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				stored, err := stewards.GetSteward(context.Background(), resp.StewardID)
				require.NoError(t, err)
				assert.Equal(t, tc.req.KeyAlgorithm, stored.KeyAlgorithm)
			} else {
				assert.ErrorIs(t, lookupErr, business.ErrStewardNotFound, "nothing may be stored on a rejected registration")
			}
		})
	}
}

func TestHandleRegister_AlgorithmChangeForExistingDeviceID(t *testing.T) {
	id := newP256Identity(t)
	tokenStore := newTestRegistrationStore(t)
	server, stewards := newHandleRegisterServerWithStewardStore(t, tokenStore, newTestCertManager(t))
	server.SetApprovalHook(&AlwaysApproveHook{})
	tok := &registration.Token{Token: "cfgms_reg_alg_change", TenantID: "test-tenant", ControllerURL: "grpc://controller:7443"}
	require.NoError(t, tokenStore.SaveToken(context.Background(), tok))

	// An existing ed25519 record holds a DeviceID; a P-256 request names it.
	require.NoError(t, stewards.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: "existing", TenantID: "test-tenant", Status: business.StewardStatusActive,
		DeviceID: id.deviceID, IdentityKeyPub: []byte("ed25519-key-bytes-not-checked-here"),
	}))
	rec := postRegisterWithBody(server, RegistrationRequest{
		Token: tok.Token, DeviceID: id.deviceID, IdentityKeyPub: base64.StdEncoding.EncodeToString(id.der),
		KeyAlgorithm: "ecdsa-p256", CSRPEM: testValidCSRPEM,
	})
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	got, err := stewards.GetStewardByDeviceID(context.Background(), id.deviceID)
	require.NoError(t, err)
	assert.Equal(t, "existing", got.ID)
	assert.Empty(t, got.KeyAlgorithm, "the stored algorithm must not change")
}
