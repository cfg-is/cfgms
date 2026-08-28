// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ---- test helpers -------------------------------------------------------------------

// generateTestCSR builds a real, self-signed (in the CSR sense — the request is
// signed by the key it carries the public half of) ECDSA P-256 certificate signing
// request PEM, exactly the shape the lodge endpoint accepts.
func generateTestCSR(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// generateTestCSRWithBadSignature builds a structurally valid CSR whose signature
// bytes have been corrupted, so ParseCertificateRequest succeeds but CheckSignature
// fails — exercising the lodge endpoint's signature-verification rejection path.
func generateTestCSRWithBadSignature(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	corrupted := append([]byte(nil), der...)
	corrupted[len(corrupted)-1] ^= 0xFF
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: corrupted}))
}

// generateTestPrivateKeyPEM builds a PEM-encoded EC private key — the shape the
// lodge endpoint must reject outright regardless of what else the body carries.
func generateTestPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// mintTestEnrolmentToken mints a token via the real router using an mTLS admin
// principal (AssuranceStrong + implicit-admin), exactly as an operator would.
func mintTestEnrolmentToken(t *testing.T, server *Server, tenantID string) EnrolmentTokenResponse {
	t.Helper()
	body, err := json.Marshal(MintEnrolmentTokenRequest{TenantID: tenantID})
	require.NoError(t, err)
	req := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, "mint: %s", rec.Body.String())
	var resp struct {
		Data EnrolmentTokenResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// lodgeCredentialRequest posts to the lodge endpoint through the real router — it is
// registered on the base router (unauthenticated), so this exercises the actual
// wiring, not just the handler in isolation.
func lodgeCredentialRequest(t *testing.T, server *Server, bearerToken string, body LodgeCredentialRequestBody) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/lodge", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

func decodeLodgeResponse(t *testing.T, rec *httptest.ResponseRecorder) LodgeCredentialRequestResponse {
	t.Helper()
	var resp struct {
		Data LodgeCredentialRequestResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// ---- leadership gate (Issue #3717: every mutating handler must call HasLeadership) ---

func TestCredentialRequests_LeadershipGate(t *testing.T) {
	server := setupTestServer(t)
	server.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}

	t.Run("mint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enrolment-tokens", bytes.NewReader([]byte(`{"tenant_id":"t"}`)))
		rec := httptest.NewRecorder()
		server.handleMintEnrolmentToken(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
	t.Run("revoke", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enrolment-tokens/some-id/revoke", nil)
		req = withVars(req, map[string]string{"id": "some-id"})
		rec := httptest.NewRecorder()
		server.handleRevokeEnrolmentToken(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
	t.Run("lodge", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/lodge", nil)
		rec := httptest.NewRecorder()
		server.handleLodgeCredentialRequest(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
	t.Run("deny", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/some-id/deny", nil)
		req = withVars(req, map[string]string{"id": "some-id"})
		rec := httptest.NewRecorder()
		server.handleDenyCredentialRequest(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
}

// ---- mint / revoke ------------------------------------------------------------------

func TestMintAndRevokeEnrolmentToken(t *testing.T) {
	server := setupTestServer(t)

	t.Run("mint success returns the raw token exactly once", func(t *testing.T) {
		resp := mintTestEnrolmentToken(t, server, "test-tenant")
		assert.NotEmpty(t, resp.ID)
		require.NotEmpty(t, resp.Token)
		assert.Len(t, resp.TokenPrefix, 6)
		assert.Equal(t, resp.Token[:6], resp.TokenPrefix)
		assert.Equal(t, "test-tenant", resp.TenantID)
		assert.False(t, resp.Revoked)
		assert.NotEmpty(t, resp.ExpiresAt)
	})

	t.Run("mint missing tenant_id returns 400", func(t *testing.T) {
		req := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("mint unauthorized without a credential", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enrolment-tokens", bytes.NewReader([]byte(`{"tenant_id":"t"}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("revoke success", func(t *testing.T) {
		minted := mintTestEnrolmentToken(t, server, "revoke-tenant")
		req := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens/"+minted.ID+"/revoke", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var resp struct {
			Data EnrolmentTokenResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.True(t, resp.Data.Revoked)
		assert.NotNil(t, resp.Data.RevokedAt)
		assert.Empty(t, resp.Data.Token, "revoke must never return the raw secret")

		// A revoked token can no longer be spent.
		lodgeRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
			CSRPEM: generateTestCSR(t, "revoked-device"),
		})
		assert.Equal(t, http.StatusUnauthorized, lodgeRec.Code)
	})

	t.Run("revoke unknown id returns 404", func(t *testing.T) {
		req := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens/nonexistent-id/revoke", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("revoke already-revoked returns 409", func(t *testing.T) {
		minted := mintTestEnrolmentToken(t, server, "revoke-tenant-2")
		req := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens/"+minted.ID+"/revoke", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		req2 := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens/"+minted.ID+"/revoke", nil)
		rec2 := httptest.NewRecorder()
		server.router.ServeHTTP(rec2, req2)
		assert.Equal(t, http.StatusConflict, rec2.Code)
	})

	t.Run("revoke already-spent token returns 409", func(t *testing.T) {
		minted := mintTestEnrolmentToken(t, server, "spend-tenant")
		lodgeRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
			CSRPEM: generateTestCSR(t, "spend-device"),
		})
		require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())

		req := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens/"+minted.ID+"/revoke", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusConflict, rec.Code)
	})
}

// ---- lodge happy path ----------------------------------------------------------------

func TestLodgeCredentialRequest_Success(t *testing.T) {
	server := setupTestServer(t)
	minted := mintTestEnrolmentToken(t, server, "lodge-tenant")
	csr := generateTestCSR(t, "enrolling-machine")

	rec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
		CSRPEM:   csr,
		Hostname: "laptop-01",
		Label:    "sales laptop",
		Platform: "linux",
		Purpose:  "cli enrolment",
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	resp := decodeLodgeResponse(t, rec)
	assert.NotEmpty(t, resp.RequestID)
	assert.NotEmpty(t, resp.PublicKeyFingerprint)
	assert.NotEmpty(t, resp.PublicKeyFingerprintShort)
	assert.NotEmpty(t, resp.CollectSecret)
	assert.NotEmpty(t, resp.ExpiresAt)
	assert.NotEqual(t, resp.CollectSecret, minted.Token, "collect secret must not equal the enrolment token")

	stored, err := server.getPendingCredentialRequestByID(context.Background(), resp.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "lodge-tenant", stored.TenantID)
	assert.Equal(t, credentialRequestStatusPending, stored.Status)
	assert.Equal(t, resp.PublicKeyFingerprint, stored.PublicKeyFingerprint)
	assert.Equal(t, "laptop-01", stored.Hostname)
	assert.Equal(t, hashCredentialSecret(resp.CollectSecret), stored.CollectSecretHash)
	assert.NotEqual(t, resp.CollectSecret, stored.CollectSecretHash)
}

// [REQUIRED TEST] the lodge endpoint ignores any caller-supplied permission, marker,
// account or tenant claim — the tenant is derived from the token, never the body.
func TestLodgeCredentialRequest_IgnoresUntrustedClaims(t *testing.T) {
	server := setupTestServer(t)
	minted := mintTestEnrolmentToken(t, server, "real-tenant")
	csr := generateTestCSR(t, "device-x")

	rawBody := fmt.Sprintf(`{
		"csr_pem": %q,
		"tenant_id": "evil-tenant",
		"permission": "steward:decommission",
		"permissions": ["*"],
		"account": "root",
		"marker": "admin",
		"implicit_admin": true
	}`, csr)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/lodge", strings.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+minted.Token)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	resp := decodeLodgeResponse(t, rec)
	stored, err := server.getPendingCredentialRequestByID(context.Background(), resp.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "real-tenant", stored.TenantID, "tenant must come from the token, never the body")
}

// [REQUIRED TEST] the lodge endpoint rejects a body containing private key material,
// and rejects a signing request whose own signature does not verify.
func TestLodgeCredentialRequest_RejectsPrivateKeyAndBadSignature(t *testing.T) {
	server := setupTestServer(t)

	t.Run("private key material", func(t *testing.T) {
		minted := mintTestEnrolmentToken(t, server, "pk-tenant")
		rec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
			CSRPEM: generateTestPrivateKeyPEM(t),
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		count, err := server.countPendingCredentialRequests(context.Background(), "pk-tenant")
		require.NoError(t, err)
		assert.Zero(t, count)
	})

	t.Run("signature does not verify", func(t *testing.T) {
		minted := mintTestEnrolmentToken(t, server, "badsig-tenant")
		rec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
			CSRPEM: generateTestCSRWithBadSignature(t, "device-y"),
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		count, err := server.countPendingCredentialRequests(context.Background(), "badsig-tenant")
		require.NoError(t, err)
		assert.Zero(t, count)
	})
}

// [REQUIRED TEST] lodging without a token, with an unknown token, with a revoked
// token, with an expired token, or with an already-spent token returns unauthorized
// and creates no pending record — assert on the store, not only the response code.
func TestLodgeCredentialRequest_UnauthorizedVariantsCreateNoRecord(t *testing.T) {
	server := setupTestServer(t)
	csr := generateTestCSR(t, "variant-device")

	countPending := func(tenant string) int {
		n, err := server.countPendingCredentialRequests(context.Background(), tenant)
		require.NoError(t, err)
		return n
	}

	t.Run("no token", func(t *testing.T) {
		rec := lodgeCredentialRequest(t, server, "", LodgeCredentialRequestBody{CSRPEM: csr})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("unknown token", func(t *testing.T) {
		rec := lodgeCredentialRequest(t, server, "totally-unknown-token-value", LodgeCredentialRequestBody{CSRPEM: csr})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("revoked token", func(t *testing.T) {
		minted := mintTestEnrolmentToken(t, server, "revoked-variant-tenant")
		revokeReq := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens/"+minted.ID+"/revoke", nil)
		revokeRec := httptest.NewRecorder()
		server.router.ServeHTTP(revokeRec, revokeReq)
		require.Equal(t, http.StatusOK, revokeRec.Code)

		before := countPending("revoked-variant-tenant")
		rec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{CSRPEM: csr})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, before, countPending("revoked-variant-tenant"))
	})

	t.Run("expired token", func(t *testing.T) {
		// White-box: construct an already-expired record directly, bypassing mint's
		// fixed TTL so the test does not need to wait an hour.
		rawToken, err := generateRandomHexSecret(enrolmentTokenBytes)
		require.NoError(t, err)
		tok := &enrolmentToken{
			ID:          "et-expired-test",
			TenantID:    "expired-variant-tenant",
			TokenHash:   hashCredentialSecret(rawToken),
			TokenPrefix: enrolmentTokenDisplayPrefix(rawToken),
			CreatedAt:   time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt:   time.Now().UTC().Add(-time.Hour),
		}
		require.NoError(t, server.persistEnrolmentToken(context.Background(), tok))

		before := countPending("expired-variant-tenant")
		rec := lodgeCredentialRequest(t, server, rawToken, LodgeCredentialRequestBody{CSRPEM: csr})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, before, countPending("expired-variant-tenant"))
	})

	t.Run("already-spent token", func(t *testing.T) {
		minted := mintTestEnrolmentToken(t, server, "spent-variant-tenant")
		firstRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{CSRPEM: csr})
		require.Equal(t, http.StatusCreated, firstRec.Code, firstRec.Body.String())

		before := countPending("spent-variant-tenant")
		require.Equal(t, 1, before)

		secondRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{CSRPEM: csr})
		assert.Equal(t, http.StatusUnauthorized, secondRec.Code)
		assert.Equal(t, before, countPending("spent-variant-tenant"),
			"an already-spent token must not create a second pending record")
	})
}

// [REQUIRED TEST] lodging is rate limited per source address and the
// outstanding-request cap refuses new lodges without evicting existing ones.
func TestLodgeCredentialRequest_RateLimitAndOutstandingCap(t *testing.T) {
	t.Run("rate limited per source", func(t *testing.T) {
		server := setupTestServer(t)
		// Mutate the limiter already bound into the route's handler chain in place —
		// routes_credential_requests.go captures s.credentialRequestLodgeLimiter's
		// *pointer* at registration time (during setupTestServer's New() call), so
		// reassigning the struct field here would not affect the already-built chain.
		server.credentialRequestLodgeLimiter.limit = 2

		for i := 0; i < 2; i++ {
			rec := lodgeCredentialRequest(t, server, "", LodgeCredentialRequestBody{})
			require.Equal(t, http.StatusUnauthorized, rec.Code, "requests within budget must reach the handler")
		}
		rec := lodgeCredentialRequest(t, server, "", LodgeCredentialRequestBody{})
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	})

	t.Run("outstanding cap refuses new lodges without evicting existing", func(t *testing.T) {
		server := setupTestServer(t)
		const tenant = "cap-tenant"
		ctx := context.Background()
		for i := 0; i < maxPendingCredentialRequestsPerTenant; i++ {
			require.NoError(t, server.persistPendingCredentialRequest(ctx, &pendingCredentialRequest{
				ID:                   fmt.Sprintf("cr-seed-%d", i),
				TenantID:             tenant,
				Status:               credentialRequestStatusPending,
				PublicKeyFingerprint: fmt.Sprintf("seed-fp-%d", i),
				CreatedAt:            time.Now().UTC(),
				ExpiresAt:            time.Now().UTC().Add(credentialRequestTTL),
				CollectSecretHash:    "seed-hash",
			}))
		}
		before, err := server.countPendingCredentialRequests(ctx, tenant)
		require.NoError(t, err)
		require.Equal(t, maxPendingCredentialRequestsPerTenant, before)

		minted := mintTestEnrolmentToken(t, server, tenant)
		rec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
			CSRPEM: generateTestCSR(t, "cap-device"),
		})
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		after, err := server.countPendingCredentialRequests(ctx, tenant)
		require.NoError(t, err)
		assert.Equal(t, maxPendingCredentialRequestsPerTenant, after,
			"the cap must refuse the new lodge without evicting any existing entry")
	})
}

// ---- list / deny --------------------------------------------------------------------

func TestListAndDenyCredentialRequests(t *testing.T) {
	server := setupTestServer(t)
	minted := mintTestEnrolmentToken(t, server, "list-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "list-device"), Hostname: "host-1", Purpose: "test",
	})
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodgeResp := decodeLodgeResponse(t, lodgeRec)

	t.Run("list shows the pending request scoped to tenant", func(t *testing.T) {
		req := makeAdminRequest(t, "GET", "/api/v1/credential-requests", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var resp struct {
			Data []PendingCredentialRequestInfo `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		var found *PendingCredentialRequestInfo
		for i := range resp.Data {
			if resp.Data[i].ID == lodgeResp.RequestID {
				found = &resp.Data[i]
			}
		}
		require.NotNil(t, found, "lodged request must appear in the pending list")
		assert.Equal(t, "list-tenant", found.TenantID)
		assert.Equal(t, lodgeResp.PublicKeyFingerprint, found.PublicKeyFingerprint)
		assert.Equal(t, lodgeResp.PublicKeyFingerprintShort, found.PublicKeyFingerprintShort)
		assert.Equal(t, "test", found.Purpose)
		assert.NotEmpty(t, found.SourceIP)
		assert.NotEmpty(t, found.ExpiresAt)
	})

	t.Run("deny is terminal and removes it from the pending list", func(t *testing.T) {
		req := makeAdminRequest(t, "POST", "/api/v1/credential-requests/"+lodgeResp.RequestID+"/deny",
			bytes.NewReader([]byte(`{"reason":"unrecognized device"}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		stored, err := server.getPendingCredentialRequestByID(context.Background(), lodgeResp.RequestID)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Equal(t, credentialRequestStatusDenied, stored.Status)

		// Denial is terminal: it can never move to any other status, including a
		// second denial.
		req2 := makeAdminRequest(t, "POST", "/api/v1/credential-requests/"+lodgeResp.RequestID+"/deny", nil)
		rec2 := httptest.NewRecorder()
		server.router.ServeHTTP(rec2, req2)
		assert.Equal(t, http.StatusConflict, rec2.Code)

		listReq := makeAdminRequest(t, "GET", "/api/v1/credential-requests", nil)
		listRec := httptest.NewRecorder()
		server.router.ServeHTTP(listRec, listReq)
		require.Equal(t, http.StatusOK, listRec.Code)
		var listResp struct {
			Data []PendingCredentialRequestInfo `json:"data"`
		}
		require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listResp))
		for _, item := range listResp.Data {
			assert.NotEqual(t, lodgeResp.RequestID, item.ID, "a denied request must not appear in the pending list")
		}
	})

	t.Run("deny unknown id returns 404", func(t *testing.T) {
		req := makeAdminRequest(t, "POST", "/api/v1/credential-requests/nonexistent/deny", nil)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// ---- secrets hashed at rest and never logged/listed ----------------------------------

// [REQUIRED TEST] the enrolment token and the collect secret are persisted hashed and
// never in cleartext, and neither appears in any log line or listing response; only
// the token's short display prefix does.
func TestCredentialRequests_SecretsHashedAtRestAndNeverLogged(t *testing.T) {
	// The logger is injected at construction (setupTestServerWithLogger), not by
	// mutating server.logger afterward — startAPIKeyCleanup's background goroutine
	// reads that field from the moment New() returns, so a later plain-field write
	// races it under -race.
	capLogger := &captureAllLogger{}
	server := setupTestServerWithLogger(t, capLogger)

	minted := mintTestEnrolmentToken(t, server, "secret-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "secret-device"),
	})
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodgeResp := decodeLodgeResponse(t, lodgeRec)

	// Exercise the revoke code path's logging too (the token is already spent, so a
	// 409 is expected and fine — only the log output matters here).
	revokeReq := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens/"+minted.ID+"/revoke", nil)
	revokeRec := httptest.NewRecorder()
	server.router.ServeHTTP(revokeRec, revokeReq)

	tokenMeta, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Tags: []string{"enrolment_token"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: enrolmentTokenSecretType,
			"id":                            minted.ID,
		},
		IncludeExpired: true,
	})
	require.NoError(t, err)
	require.Len(t, tokenMeta, 1)
	for k, v := range tokenMeta[0].Metadata {
		assert.NotEqual(t, minted.Token, v, "metadata key %q must not hold the raw token", k)
		assert.NotContains(t, v, minted.Token, "metadata key %q must not contain the raw token", k)
	}
	assert.Equal(t, minted.Token[:6], tokenMeta[0].Metadata["token_prefix"])
	assert.NotEmpty(t, tokenMeta[0].Metadata["token_hash"])

	reqMeta, err := server.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"id":                            lodgeResp.RequestID,
		},
		IncludeExpired: true,
	})
	require.NoError(t, err)
	require.Len(t, reqMeta, 1)
	for k, v := range reqMeta[0].Metadata {
		assert.NotEqual(t, lodgeResp.CollectSecret, v, "metadata key %q must not hold the raw collect secret", k)
		assert.NotContains(t, v, lodgeResp.CollectSecret, "metadata key %q must not contain the raw collect secret", k)
	}

	logs := capLogger.captured()
	assert.NotContains(t, logs, minted.Token, "the raw enrolment token must never be logged")
	assert.NotContains(t, logs, lodgeResp.CollectSecret, "the raw collect secret must never be logged")

	listReq := makeAdminRequest(t, "GET", "/api/v1/credential-requests", nil)
	listRec := httptest.NewRecorder()
	server.router.ServeHTTP(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code)
	assert.NotContains(t, listRec.Body.String(), lodgeResp.CollectSecret)
	assert.NotContains(t, listRec.Body.String(), minted.Token)
}

// [REQUIRED TEST] Regression for the go/clear-text-logging finding on the lodge
// endpoint. Lodge is unauthenticated, so the bearer value it is handed is entirely
// caller-controlled. Nothing derived from that header — not even a six-character
// prefix — may reach a log line. Only the *resolved store record's* TokenPrefix is
// loggable, and a bearer value that resolves to no record has no such prefix to log.
func TestLodgeCredentialRequest_UnresolvedBearerTokenIsNeverLogged(t *testing.T) {
	capLogger := &captureAllLogger{}
	server := setupTestServerWithLogger(t, capLogger)
	csr := generateTestCSR(t, "unresolved-token-device")

	// Case 1: a bearer value the caller chose freely, matching no store record. Its
	// prefix is deliberately distinctive so a match in the log buffer is unambiguous.
	attackerToken := "zzcanary-caller-controlled-bearer-value-0123456789abcdef"
	rec := lodgeCredentialRequest(t, server, attackerToken, LodgeCredentialRequestBody{CSRPEM: csr})
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())

	// Case 2: a near-miss — a genuine live token with its final character altered. Its
	// first six characters ARE a real credential's, so logging "the prefix of whatever
	// was presented" would write part of a live token to disk. Snapshot the log after
	// minting, because the mint path legitimately logs that record's own prefix.
	minted := mintTestEnrolmentToken(t, server, "nearmiss-tenant")
	beforeLodge := len(capLogger.captured())

	mistyped := minted.Token[:len(minted.Token)-1] + "z" // tokens are hex, so "z" always differs
	require.NotEqual(t, minted.Token, mistyped)
	rec2 := lodgeCredentialRequest(t, server, mistyped, LodgeCredentialRequestBody{CSRPEM: csr})
	require.Equal(t, http.StatusUnauthorized, rec2.Code, rec2.Body.String())

	all := capLogger.captured()
	sinceLodge := all[beforeLodge:]

	assert.NotContains(t, all, attackerToken,
		"the raw caller-supplied bearer value must never be logged")
	assert.NotContains(t, all, attackerToken[:enrolmentTokenDisplayPrefixLen],
		"even a prefix of the caller-supplied bearer value must never be logged")
	assert.NotContains(t, sinceLodge, mistyped,
		"the mistyped bearer value must never be logged")
	assert.NotContains(t, sinceLodge, minted.Token[:enrolmentTokenDisplayPrefixLen],
		"a near-miss must not disclose the prefix of the live token it nearly matched")
}

// ---- audit ----------------------------------------------------------------------------

func TestCredentialRequests_AuditEvents(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	minted := mintTestEnrolmentToken(t, server, "audit-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "audit-device"),
	})
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodgeResp := decodeLodgeResponse(t, lodgeRec)

	denyReq := makeAdminRequest(t, "POST", "/api/v1/credential-requests/"+lodgeResp.RequestID+"/deny", nil)
	denyRec := httptest.NewRecorder()
	server.router.ServeHTTP(denyRec, denyReq)
	require.Equal(t, http.StatusOK, denyRec.Code)

	second := mintTestEnrolmentToken(t, server, "audit-tenant")
	revokeReq := makeAdminRequest(t, "POST", "/api/v1/enrolment-tokens/"+second.ID+"/revoke", nil)
	revokeRec := httptest.NewRecorder()
	server.router.ServeHTTP(revokeRec, revokeReq)
	require.Equal(t, http.StatusOK, revokeRec.Code)

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{TenantID: "audit-tenant"})
	require.NoError(t, err)

	// Two tokens are minted in this test, so "enrolment_token.minted" appears twice —
	// find by (action, resourceID) rather than by action alone.
	findByResource := func(action, resourceID string) *business.AuditEntry {
		t.Helper()
		for _, e := range entries {
			if e.Action == action && e.ResourceID == resourceID {
				return e
			}
		}
		t.Fatalf("no audit entry with action %q and resource_id %q found among %d entries", action, resourceID, len(entries))
		return nil
	}

	mintedEntry := findByResource("enrolment_token.minted", minted.ID)
	assert.Equal(t, "enrolment_token", mintedEntry.ResourceType)

	lodgedEntry := findByResource("credential_request.lodged", lodgeResp.RequestID)
	assert.Equal(t, "credential_request", lodgedEntry.ResourceType)

	deniedEntry := findByResource("credential_request.denied", lodgeResp.RequestID)
	assert.Equal(t, "credential_request", deniedEntry.ResourceType)

	revokedEntry := findByResource("enrolment_token.revoked", second.ID)
	assert.Equal(t, "enrolment_token", revokedEntry.ResourceType)
}

// ---- expiry sweep -----------------------------------------------------------------------

func TestSweepExpiredCredentialRequestsAndTokens(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	rawToken, err := generateRandomHexSecret(enrolmentTokenBytes)
	require.NoError(t, err)
	expiredTok := &enrolmentToken{
		ID:          "et-sweep-test",
		TenantID:    "sweep-tenant",
		TokenHash:   hashCredentialSecret(rawToken),
		TokenPrefix: enrolmentTokenDisplayPrefix(rawToken),
		CreatedAt:   time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().UTC().Add(-time.Hour),
	}
	require.NoError(t, server.persistEnrolmentToken(ctx, expiredTok))

	expiredReq := &pendingCredentialRequest{
		ID:                   "cr-sweep-test",
		TenantID:             "sweep-tenant",
		Status:               credentialRequestStatusPending,
		PublicKeyFingerprint: "sweep-fp",
		CreatedAt:            time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt:            time.Now().UTC().Add(-time.Hour),
		CollectSecretHash:    "sweep-hash",
	}
	require.NoError(t, server.persistPendingCredentialRequest(ctx, expiredReq))

	// A live (non-expired) request must survive the sweep.
	liveMinted := mintTestEnrolmentToken(t, server, "sweep-tenant")
	liveLodgeRec := lodgeCredentialRequest(t, server, liveMinted.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "sweep-device"),
	})
	require.Equal(t, http.StatusCreated, liveLodgeRec.Code, liveLodgeRec.Body.String())
	liveLodgeResp := decodeLodgeResponse(t, liveLodgeRec)

	server.sweepExpiredCredentialRequests(ctx)

	goneTok, err := server.getEnrolmentTokenByID(ctx, expiredTok.ID)
	require.NoError(t, err)
	assert.Nil(t, goneTok, "expired unspent token must be removed by the sweep")

	goneReq, err := server.getPendingCredentialRequestByID(ctx, expiredReq.ID)
	require.NoError(t, err)
	assert.Nil(t, goneReq, "expired pending request must be removed by the sweep")

	stillLive, err := server.getPendingCredentialRequestByID(ctx, liveLodgeResp.RequestID)
	require.NoError(t, err)
	assert.NotNil(t, stillLive, "a live pending request must survive the sweep")

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{TenantID: "sweep-tenant"})
	require.NoError(t, err)
	tokenExpiredEntry := findAuditEntryByAction(t, entries, "enrolment_token.expired")
	assert.Equal(t, expiredTok.ID, tokenExpiredEntry.ResourceID)
	reqExpiredEntry := findAuditEntryByAction(t, entries, "credential_request.expired")
	assert.Equal(t, expiredReq.ID, reqExpiredEntry.ResourceID)
}

// A spent token must survive the sweep even past its expiry — the sweep only removes
// unspent tokens; a spent one has already done its job and its record is inert.
func TestSweepDoesNotRemoveSpentTokens(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	minted := mintTestEnrolmentToken(t, server, "spent-sweep-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "spent-sweep-device"),
	})
	require.Equal(t, http.StatusCreated, lodgeRec.Code)

	tok, err := server.getEnrolmentTokenByID(ctx, minted.ID)
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.NotNil(t, tok.SpentAt)
	// Force it into the past so it would be swept if the sweep ignored SpentAt.
	tok.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	require.NoError(t, server.persistEnrolmentToken(ctx, tok))

	server.sweepExpiredCredentialRequests(ctx)

	stillThere, err := server.getEnrolmentTokenByID(ctx, minted.ID)
	require.NoError(t, err)
	assert.NotNil(t, stillThere, "a spent token must not be removed by the sweep even after its expiry")
}

// ---- orphaned collected-certificate sweep (Issue #3719) ------------------------------

// accountListFailingSecretStore wraps a real SecretStore and fails only the account
// lookups, leaving every other query (notably the sweep's own credential-request
// listing) served by the real store. It is a real SecretStore implementation — no mock
// framework — mirroring errListSecretStore (server_test.go) but narrowed by tag so the
// sweep reaches its account-lookup branch with everything before it succeeding.
type accountListFailingSecretStore struct {
	secretsif.SecretStore
	failErr error
}

func (s *accountListFailingSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	if filter != nil {
		for _, tag := range filter.Tags {
			if tag == "account" {
				return nil, s.failErr
			}
		}
	}
	return s.SecretStore.ListSecrets(ctx, filter)
}

// orphanedCollectFixture describes a request left in exactly the crash window
// sweepOrphanedCollectedCertificates exists to close.
type orphanedCollectFixture struct {
	requestID   string
	serial      string
	accountUser string
	tenantID    string
}

// collectThenOrphan drives a real lodge -> approve -> collect cycle against a real
// certificate manager, then removes the account binding collect wrote. The result is
// precisely the state a crash between signAndBindCollectedCertificate's signing call and
// its bindCertOnAccount call leaves behind: a live, signed certificate whose serial is
// durably recorded on a "collected" request, resolving through no account.
func collectThenOrphan(t *testing.T, server *Server, tenantID, username string, grant ApproveCredentialRequestBody) orphanedCollectFixture {
	t.Helper()
	fx := lodgeAndApprove(t, server, tenantID, username, grant)

	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeCollectResponse(t, rec)
	require.NotEmpty(t, resp.SerialNumber)

	require.NoError(t, server.removeCertBindingFromAccount(context.Background(), fx.accountUser, resp.SerialNumber, "test-setup"))
	acct, err := server.getAccount(context.Background(), fx.accountUser)
	require.NoError(t, err)
	require.NotNil(t, acct)
	for _, b := range acct.CertBindings {
		require.NotEqual(t, resp.SerialNumber, b.Serial, "fixture must leave the collected serial unbound")
	}

	return orphanedCollectFixture{
		requestID:   fx.requestID,
		serial:      resp.SerialNumber,
		accountUser: fx.accountUser,
		tenantID:    tenantID,
	}
}

// countAuditEntries returns how many entries carry the given action and resource ID.
// Unlike findAuditEntryByAction it does not fail on absence — the sweep's skip paths are
// asserted by the absence of an event.
func countAuditEntries(t *testing.T, server *Server, tenantID, action, resourceID string) int {
	t.Helper()
	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: tenantID})
	require.NoError(t, err)
	count := 0
	for _, e := range entries {
		if e.Action == action && (resourceID == "" || e.ResourceID == resourceID) {
			count++
		}
	}
	return count
}

// TestSweepOrphanedCollectedCertificates_RevokesUnboundCertificate is the primary test
// for the sweep: a collected request whose recorded serial appears in no account's
// bindings is the crash window, and the certificate must be revoked so it can never
// resolve through extractAdminPrincipal's bootstrap fallback as implicit root.
func TestSweepOrphanedCollectedCertificates_RevokesUnboundCertificate(t *testing.T) {
	server := setupCollectTestServer(t)
	ctx := context.Background()
	fx := collectThenOrphan(t, server, "sweep-orphan-tenant", "sweep-orphan-owner", ApproveCredentialRequestBody{
		GrantAdminMarker: true,
	})

	require.False(t, server.certManager.IsRevoked(fx.serial), "sanity: the collected certificate starts out live")

	server.sweepOrphanedCollectedCertificates(ctx)

	assert.True(t, server.certManager.IsRevoked(fx.serial),
		"a collected certificate with no account binding must be revoked by the sweep")

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{TenantID: fx.tenantID})
	require.NoError(t, err)
	entry := findAuditEntryByAction(t, entries, "credential_request.orphaned_certificate_revoked")
	assert.Equal(t, fx.requestID, entry.ResourceID)
	assert.Equal(t, "credential_request", entry.ResourceType)

	// The whole point of the revocation: the admin-marked certificate the crash left
	// behind must not authenticate. extractAdminPrincipal checks IsRevoked before it
	// ever reaches the bootstrap-fallback branch, so a synthetic certificate carrying
	// the revoked serial exercises exactly that lookup (chain verification happens at
	// the TLS layer — see extractAdminPrincipal's doc comment).
	serialInt, ok := new(big.Int).SetString(fx.serial, 10)
	require.True(t, ok, "collected serial must be a base-10 integer")
	synthetic := makeAdminCertWithAttrs(t, 0, fx.accountUser, false)
	synthetic.SerialNumber = serialInt
	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", synthetic)
	assert.Nil(t, server.extractAdminPrincipal(req),
		"a certificate the sweep revoked must never resolve as implicit root")
}

// TestSweepOrphanedCollectedCertificates_LeavesBoundCertificateAlone covers the "bound"
// skip path: the ordinary successful collection, where the binding exists. The sweep
// must never touch it — revoking here would destroy every legitimately issued credential
// on the next tick.
func TestSweepOrphanedCollectedCertificates_LeavesBoundCertificateAlone(t *testing.T) {
	server := setupCollectTestServer(t)
	ctx := context.Background()
	fx := lodgeAndApprove(t, server, "sweep-bound-tenant", "sweep-bound-owner", ApproveCredentialRequestBody{
		GrantAdminMarker: true,
	})

	rec := collectCredentialRequest(t, server, fx.requestID, fx.collectSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeCollectResponse(t, rec)

	revokedBefore, err := server.certManager.ListRevoked()
	require.NoError(t, err)

	server.sweepOrphanedCollectedCertificates(ctx)

	assert.False(t, server.certManager.IsRevoked(resp.SerialNumber),
		"a collected certificate that IS bound to its account must survive the sweep")
	revokedAfter, err := server.certManager.ListRevoked()
	require.NoError(t, err)
	assert.Len(t, revokedAfter, len(revokedBefore), "the sweep must revoke nothing when every collection is bound")
	assert.Equal(t, 0, countAuditEntries(t, server, "sweep-bound-tenant",
		"credential_request.orphaned_certificate_revoked", fx.requestID),
		"no orphan event may be emitted for a properly bound certificate")

	// The binding is intact and the certificate still authenticates.
	acct, err := server.getAccount(ctx, fx.accountUser)
	require.NoError(t, err)
	found := false
	for _, b := range acct.CertBindings {
		if b.Serial == resp.SerialNumber {
			found = true
		}
	}
	assert.True(t, found, "the sweep must not disturb the account binding")
}

// TestSweepOrphanedCollectedCertificates_AlreadyRevokedIsSkipped covers the
// already-revoked short-circuit: the collect handler's own post-sign failure path may
// have revoked the certificate already (or a previous sweep tick did), and a later tick
// must not re-revoke or emit a second event for the same request.
func TestSweepOrphanedCollectedCertificates_AlreadyRevokedIsSkipped(t *testing.T) {
	server := setupCollectTestServer(t)
	ctx := context.Background()
	fx := collectThenOrphan(t, server, "sweep-revoked-tenant", "sweep-revoked-owner", ApproveCredentialRequestBody{})

	require.NoError(t, server.certManager.Revoke(fx.serial))
	revokedBefore, err := server.certManager.ListRevoked()
	require.NoError(t, err)

	server.sweepOrphanedCollectedCertificates(ctx)

	revokedAfter, err := server.certManager.ListRevoked()
	require.NoError(t, err)
	assert.Len(t, revokedAfter, len(revokedBefore), "an already-revoked serial must not be revoked a second time")
	assert.True(t, server.certManager.IsRevoked(fx.serial))
	assert.Equal(t, 0, countAuditEntries(t, server, fx.tenantID,
		"credential_request.orphaned_certificate_revoked", fx.requestID),
		"the short-circuit must return before the audit event, so a repeating sweep does not repeat the event")
}

// TestSweepOrphanedCollectedCertificates_AccountLookupErrorDefersToNextSweep covers the
// account-lookup-error path: a store outage must never be read as "no binding exists".
// The certificate is left alone, and the next sweep after the store recovers revokes it.
func TestSweepOrphanedCollectedCertificates_AccountLookupErrorDefersToNextSweep(t *testing.T) {
	server := setupCollectTestServer(t)
	ctx := context.Background()
	fx := collectThenOrphan(t, server, "sweep-lookup-err-tenant", "sweep-lookup-err-owner", ApproveCredentialRequestBody{})

	realStore := server.secretStore
	server.secretStore = &accountListFailingSecretStore{
		SecretStore: realStore,
		failErr:     errors.New("account store temporarily unavailable"),
	}

	server.sweepOrphanedCollectedCertificates(ctx)

	assert.False(t, server.certManager.IsRevoked(fx.serial),
		"a failed account lookup must never be treated as an absent binding")
	assert.Equal(t, 0, countAuditEntries(t, server, fx.tenantID,
		"credential_request.orphaned_certificate_revoked", fx.requestID))

	server.secretStore = realStore
	server.sweepOrphanedCollectedCertificates(ctx)

	assert.True(t, server.certManager.IsRevoked(fx.serial),
		"once the account store recovers, the next sweep must revoke the orphan")
}

// TestSweepOrphanedCollectedCertificates_SkipsRecordsWithNothingToRevoke covers the two
// records the sweep must pass over untouched — a collection that crashed before the
// certificate was signed (no serial) and one carrying no bound account — plus the
// nil-certManager guard.
func TestSweepOrphanedCollectedCertificates_SkipsRecordsWithNothingToRevoke(t *testing.T) {
	server := setupCollectTestServer(t)
	ctx := context.Background()
	now := time.Now().UTC()

	noSerial := &pendingCredentialRequest{
		ID:                   "cr-collected-no-serial",
		TenantID:             "sweep-skip-tenant",
		Status:               credentialRequestStatusCollected,
		PublicKeyFingerprint: "skip-fp-1",
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Hour),
		CollectSecretHash:    "skip-hash-1",
		ApprovedAt:           &now,
		BoundAccountID:       "account-that-does-not-exist",
		CollectedAt:          &now,
	}
	require.NoError(t, server.persistPendingCredentialRequest(ctx, noSerial))

	noAccount := &pendingCredentialRequest{
		ID:                   "cr-collected-no-account",
		TenantID:             "sweep-skip-tenant",
		Status:               credentialRequestStatusCollected,
		PublicKeyFingerprint: "skip-fp-2",
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Hour),
		CollectSecretHash:    "skip-hash-2",
		CollectedAt:          &now,
		CollectedSerial:      "serial-with-no-bound-account",
	}
	require.NoError(t, server.persistPendingCredentialRequest(ctx, noAccount))

	server.sweepOrphanedCollectedCertificates(ctx)

	assert.Equal(t, 0, countAuditEntries(t, server, "sweep-skip-tenant",
		"credential_request.orphaned_certificate_revoked", ""),
		"a record with no serial, or no bound account, has nothing to revoke")
	assert.False(t, server.certManager.IsRevoked("serial-with-no-bound-account"))

	// Both records survive the sweep — it revokes certificates, it never deletes records.
	for _, id := range []string{noSerial.ID, noAccount.ID} {
		stored, err := server.getPendingCredentialRequestByID(ctx, id)
		require.NoError(t, err)
		assert.NotNil(t, stored, "the sweep must not delete collected records")
	}

	// A server with no certificate manager cannot revoke anything: the sweep returns
	// without touching the store rather than panicking.
	noCertServer := setupTestServer(t)
	require.Nil(t, noCertServer.certManager, "sanity: setupTestServer wires no certificate manager")
	noCertServer.sweepOrphanedCollectedCertificates(ctx)
}

// ---- approval record fields (Issue #3718) ---------------------------------------------

// TestPendingCredentialRequest_ApprovalFieldsRoundTrip verifies that the fields the
// approve endpoint writes — ApprovedAt, ApprovedBy, BoundAccountID, GrantedMarkers and
// SelfApproved — survive a persist/reload cycle through the central secret store.
func TestPendingCredentialRequest_ApprovalFieldsRoundTrip(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()

	approvedAt := time.Now().UTC().Truncate(time.Second)
	req := &pendingCredentialRequest{
		ID:                   "cr-approval-roundtrip",
		TenantID:             "roundtrip-tenant",
		Status:               credentialRequestStatusApproved,
		PublicKeyFingerprint: "roundtrip-fp",
		CreatedAt:            time.Now().UTC(),
		ExpiresAt:            time.Now().UTC().Add(time.Hour),
		CollectSecretHash:    "roundtrip-hash",
		ApprovedAt:           &approvedAt,
		ApprovedBy:           "approver-roundtrip",
		BoundAccountID:       "account-roundtrip",
		GrantedMarkers:       []string{credentialMarkerAdmin, credentialMarkerPayloadSigning},
		SelfApproved:         true,
	}
	require.NoError(t, server.persistPendingCredentialRequest(ctx, req))

	reloaded, err := server.getPendingCredentialRequestByID(ctx, req.ID)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, credentialRequestStatusApproved, reloaded.Status)
	require.NotNil(t, reloaded.ApprovedAt)
	assert.True(t, approvedAt.Equal(*reloaded.ApprovedAt))
	assert.Equal(t, "approver-roundtrip", reloaded.ApprovedBy)
	assert.Equal(t, "account-roundtrip", reloaded.BoundAccountID)
	assert.Equal(t, []string{credentialMarkerAdmin, credentialMarkerPayloadSigning}, reloaded.GrantedMarkers)
	assert.True(t, reloaded.SelfApproved)
}

// TestPendingCredentialRequest_UnapprovedRecordHasNoApprovalFields verifies that a
// pending (never-approved) record round-trips with every approval field at its zero
// value — approval must never leave residue on a request that was denied instead.
func TestPendingCredentialRequest_UnapprovedRecordHasNoApprovalFields(t *testing.T) {
	server := setupTestServer(t)
	ctx := context.Background()
	minted := mintTestEnrolmentToken(t, server, "unapproved-tenant")
	lodgeRec := lodgeCredentialRequest(t, server, minted.Token, LodgeCredentialRequestBody{
		CSRPEM: generateTestCSR(t, "unapproved-device"),
	})
	require.Equal(t, http.StatusCreated, lodgeRec.Code)
	lodgeResp := decodeLodgeResponse(t, lodgeRec)

	stored, err := server.getPendingCredentialRequestByID(ctx, lodgeResp.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Nil(t, stored.ApprovedAt)
	assert.Empty(t, stored.ApprovedBy)
	assert.Empty(t, stored.BoundAccountID)
	assert.Empty(t, stored.GrantedMarkers)
	assert.False(t, stored.SelfApproved)
}
