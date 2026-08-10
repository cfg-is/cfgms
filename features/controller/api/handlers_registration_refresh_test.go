// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// ---- Fixture ----------------------------------------------------------------

// refreshFixture wires a Server to the real OSS storage stack used in production:
// the flat-file StewardStore and the SQLite PendingRefreshStore / RefreshPolicyStore
// created by pkgtesting.SetupTestStorage. No store is substituted — every read and
// write in these tests goes through a real storage provider.
type refreshFixture struct {
	server   *Server
	audit    *audit.Manager
	stewards business.StewardStore
	pending  business.PendingRefreshStore
	policies business.RefreshPolicyStore
}

// newRefreshFixture builds a Server for the registration-refresh handler tests.
// Pass a non-nil certMgr for tests that reach certificate issuance (the auto-accept
// and admin-approve paths); pass nil when the test never gets that far.
func newRefreshFixture(t *testing.T, certMgr *cert.Manager) *refreshFixture {
	t.Helper()
	setTestSecretsEnv(t)

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	storageManager := pkgtesting.SetupTestStorage(t)
	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	logger := logging.NewNoopLogger()

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)
	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	server, err := New(
		cfg, logger,
		controllerService, configService, nil, rbacService,
		certMgr, tenantManager, rbacManager,
		nil, nil,
		newTestRegistrationStore(t),
		"", nil,
		auditMgr,
		nil, nil, nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(ctx)
	})

	stewards := storageManager.GetStewardStore()
	pending := storageManager.GetPendingRefreshStore()
	policies := storageManager.GetRefreshPolicyStore()
	require.NotNil(t, stewards, "test storage must provide a real StewardStore")
	require.NotNil(t, pending, "test storage must provide a real PendingRefreshStore")
	require.NotNil(t, policies, "test storage must provide a real RefreshPolicyStore")

	server.SetStewardStore(stewards)
	server.SetPendingRefreshStore(pending)
	server.SetRefreshPolicyStore(policies)

	return &refreshFixture{
		server:   server,
		audit:    auditMgr,
		stewards: stewards,
		pending:  pending,
		policies: policies,
	}
}

// addSteward persists a steward record in the real fleet registry.
func (f *refreshFixture) addSteward(t *testing.T, rec *business.StewardRecord) {
	t.Helper()
	require.NoError(t, f.stewards.RegisterSteward(context.Background(), rec))
}

// addPending persists a pending-refresh entry in the real durable queue.
func (f *refreshFixture) addPending(t *testing.T, entry *business.PendingRefreshEntry) {
	t.Helper()
	require.NoError(t, f.pending.AddPendingRefresh(context.Background(), entry))
}

// setPolicy persists a per-tenant refresh policy in the real policy store.
func (f *refreshFixture) setPolicy(t *testing.T, policy *business.RefreshPolicy) {
	t.Helper()
	require.NoError(t, f.policies.SetPolicy(context.Background(), policy))
}

// pendingCount returns the number of queued refresh entries across all tenants.
func (f *refreshFixture) pendingCount(t *testing.T) int {
	t.Helper()
	entries, err := f.pending.ListPendingRefresh(context.Background(), "")
	require.NoError(t, err)
	return len(entries)
}

// findAuditAction flushes the audit manager and returns the first recorded entry
// with the given action, or nil when no such entry exists.
func (f *refreshFixture) findAuditAction(t *testing.T, action string) *business.AuditEntry {
	t.Helper()
	require.NoError(t, f.audit.Flush(context.Background()))
	entries, err := f.audit.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	for _, e := range entries {
		if e.Action == action {
			return e
		}
	}
	return nil
}

// ---- Helpers ----------------------------------------------------------------

const (
	testDeviceID = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	testTenantID = "test-tenant"
)

// newTestEd25519KeyPair generates a fresh Ed25519 key pair for tests.
func newTestEd25519KeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

// issueChallenge calls handleRefreshChallenge and returns the parsed response.
func issueChallenge(t *testing.T, server *Server, deviceID, tenantID string) *RefreshChallengeResponse {
	t.Helper()
	body, _ := json.Marshal(RefreshChallengeRequest{TenantID: tenantID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+deviceID+"/refresh/challenge", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"device_id": deviceID})
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleRefreshChallenge(rec, r)
	require.Equal(t, http.StatusOK, rec.Code, "challenge must succeed: %s", rec.Body.String())
	var resp RefreshChallengeResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return &resp
}

// buildValidCompleteRequest constructs a valid RefreshCompleteRequest with a correct PoP signature.
func buildValidCompleteRequest(
	t *testing.T,
	deviceID, tenantID string,
	challenge *RefreshChallengeResponse,
	priv ed25519.PrivateKey,
	provenance map[string]string,
) RefreshCompleteRequest {
	t.Helper()
	nonceBytes, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	require.NoError(t, err)

	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], challenge.ServerTS)
	h := sha256.New()
	h.Write(nonceBytes)
	h.Write([]byte(deviceID))
	h.Write(tsBytes[:])
	msg := h.Sum(nil)

	sig := ed25519.Sign(priv, msg)
	return RefreshCompleteRequest{
		TenantID:   tenantID,
		Nonce:      challenge.Nonce,
		IssuedAt:   int64(challenge.ServerTS),
		Signature:  base64.RawURLEncoding.EncodeToString(sig),
		Provenance: provenance,
	}
}

// postComplete sends a POST to handleRefreshComplete and returns the recorder.
func postComplete(server *Server, deviceID string, req RefreshCompleteRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+deviceID+"/refresh/complete", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"device_id": deviceID})
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleRefreshComplete(rec, r)
	return rec
}

// ---- Challenge endpoint tests -----------------------------------------------

func TestHandleRefreshChallenge_UnknownDevice(t *testing.T) {
	f := newRefreshFixture(t, nil)

	body, _ := json.Marshal(RefreshChallengeRequest{TenantID: testTenantID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/unknowndevice/refresh/challenge", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"device_id": "unknowndevice"})
	rec := httptest.NewRecorder()
	f.server.handleRefreshChallenge(rec, r)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRefreshChallenge_KnownActiveDevice(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-1",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	resp := issueChallenge(t, f.server, testDeviceID, testTenantID)
	assert.NotEmpty(t, resp.Nonce)
	assert.NotZero(t, resp.ServerTS)
	// Nonce must decode to 32 bytes.
	raw, err := base64.RawURLEncoding.DecodeString(resp.Nonce)
	require.NoError(t, err)
	assert.Len(t, raw, 32)
}

func TestHandleRefreshChallenge_RevokedDeviceReturns403(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-rev",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusRevoked,
		IdentityKeyPub: []byte(pub),
	})

	body, _ := json.Marshal(RefreshChallengeRequest{TenantID: testTenantID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+testDeviceID+"/refresh/challenge", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"device_id": testDeviceID})
	rec := httptest.NewRecorder()
	f.server.handleRefreshChallenge(rec, r)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	// Verify no nonce was placed in cache.
	_, found := f.server.nonceCache.Get(nonceCacheKeyPrefix + testDeviceID)
	assert.False(t, found, "no nonce must be stored for revoked device")
}

// ---- Complete endpoint tests ------------------------------------------------

// TestHandleRefreshComplete_RevokedBeforePoP asserts the ADR-010 §3
// revocation-before-PoP invariant using only observable behaviour: the request
// carries a signature that cannot verify against the device's identity key, so a
// handler that ran PoP verification first would answer 401 "invalid_pop". The
// observed 403 with audit reason "revoked" therefore proves the revocation gate
// short-circuits before the verifier is consulted.
func TestHandleRefreshComplete_RevokedBeforePoP(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-rev",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusRevoked,
		IdentityKeyPub: []byte(pub),
	})

	// Manually plant a nonce to rule out the "no nonce" 401 path.
	f.server.nonceCache.Set(nonceCacheKeyPrefix+testDeviceID, &nonceEntry{ //nolint:errcheck // in-memory cache; Set only fails on empty key, which is impossible here
		NonceBytes: make([]byte, 32),
		ServerTS:   uint64(time.Now().UnixNano()),
		IssuedAt:   time.Now(),
	}, nonceTTL)

	rec := postComplete(f.server, testDeviceID, RefreshCompleteRequest{
		TenantID:  testTenantID,
		Nonce:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IssuedAt:  time.Now().UnixNano(),
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)), // cannot verify
	})

	assert.Equal(t, http.StatusForbidden, rec.Code)

	entry := f.findAuditAction(t, "refresh_rejected")
	require.NotNil(t, entry, "refresh_rejected audit event expected")
	assert.Equal(t, "revoked", entry.Details["reason"],
		"revocation must be the rejection reason — PoP must never be evaluated for a revoked device")
	assert.Equal(t, "denied", entry.Details["decision"])
}

func TestHandleRefreshComplete_NonceReplay(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	// First attempt: nonce consumed, status 202 (require_approval default).
	rec1 := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusAccepted, rec1.Code, "first complete must succeed: %s", rec1.Body.String())

	// Second attempt with same nonce: nonce was consumed, must get 401.
	rec2 := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code, "nonce replay must be rejected")
}

func TestHandleRefreshComplete_ExpiredNonce(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)
	// Override IssuedAt to simulate a 61-second-old nonce.
	req.IssuedAt = time.Now().Add(-61 * time.Second).UnixNano()

	rec := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "expired")
}

func TestHandleRefreshComplete_InvalidPoP(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	_, wrongPriv := newTestEd25519KeyPair(t) // different key pair
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	// Sign with a DIFFERENT private key — PoP must fail.
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, wrongPriv, nil)

	rec := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleRefreshComplete_Lifecycle_Archived asserts that an archived steward is
// always queued for approval and that the tenant policy is not consulted for it.
// The tenant policy is deliberately set to auto_accept and a real cert manager is
// wired, so a handler that consulted policy for archived stewards would issue a
// certificate and answer 200. The observed 202 proves the archived branch
// short-circuits ahead of the policy gate.
func TestHandleRefreshComplete_Lifecycle_Archived(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-archived",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusArchived,
		IdentityKeyPub: []byte(pub),
	})
	f.setPolicy(t, &business.RefreshPolicy{TenantID: testTenantID, Mode: "auto_accept"})

	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	rec := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusAccepted, rec.Code, "archived steward must be queued: %s", rec.Body.String())

	// Verify pending entry was created.
	assert.Equal(t, 1, f.pendingCount(t), "one pending refresh entry must be created")

	// Verify response body.
	var resp RefreshCompleteResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "queued", resp.Status)
	assert.NotEmpty(t, resp.PendingID)
	assert.Empty(t, resp.ClientCert, "no certificate may be issued for an archived steward")

	// The queue reason records the archived branch, not a policy outcome.
	entry := f.findAuditAction(t, "refresh_queued")
	require.NotNil(t, entry, "refresh_queued audit event expected")
	assert.Equal(t, "archived", entry.Details["reason"],
		"policy must not be consulted for archived stewards")
}

func TestHandleRefreshComplete_CrossTenantReturns403(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-a",
		DeviceID:       testDeviceID,
		TenantID:       "tenant-a",
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	// Manually plant a nonce so we reach the cross-tenant gate.
	f.server.nonceCache.Set(nonceCacheKeyPrefix+testDeviceID, &nonceEntry{ //nolint:errcheck // in-memory cache; Set only fails on empty key, which is impossible here
		NonceBytes: make([]byte, 32),
		ServerTS:   uint64(time.Now().UnixNano()),
		IssuedAt:   time.Now(),
	}, nonceTTL)

	// Request from "tenant-b" for a steward that belongs to "tenant-a".
	rec := postComplete(f.server, testDeviceID, RefreshCompleteRequest{
		TenantID:  "tenant-b",
		Nonce:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IssuedAt:  time.Now().UnixNano(),
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	})
	// Must be 403, not 404, so the steward's existence is acknowledged but access denied.
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleRefreshComplete_AuditEmittedOnAllOutcomes(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)

	outcomes := []struct {
		name     string
		setup    func(t *testing.T, f *refreshFixture) RefreshCompleteRequest
		wantCode int
		wantAct  string
	}{
		{
			name: "revoked device",
			setup: func(t *testing.T, f *refreshFixture) RefreshCompleteRequest {
				f.addSteward(t, &business.StewardRecord{
					ID:             "s-rev",
					DeviceID:       testDeviceID,
					TenantID:       testTenantID,
					Status:         business.StewardStatusRevoked,
					IdentityKeyPub: []byte(pub),
				})
				return RefreshCompleteRequest{
					TenantID:  testTenantID,
					Nonce:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
					IssuedAt:  time.Now().UnixNano(),
					Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
				}
			},
			wantCode: http.StatusForbidden,
			wantAct:  "refresh_rejected",
		},
		{
			name: "valid PoP — queued",
			setup: func(t *testing.T, f *refreshFixture) RefreshCompleteRequest {
				f.addSteward(t, &business.StewardRecord{
					ID:             "s-active",
					DeviceID:       testDeviceID,
					TenantID:       testTenantID,
					Status:         business.StewardStatusActive,
					IdentityKeyPub: []byte(pub),
				})
				ch := issueChallenge(t, f.server, testDeviceID, testTenantID)
				return buildValidCompleteRequest(t, testDeviceID, testTenantID, ch, priv, nil)
			},
			wantCode: http.StatusAccepted,
			wantAct:  "refresh_queued",
		},
	}

	for _, tc := range outcomes {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t, nil)

			req := tc.setup(t, f)
			rec := postComplete(f.server, testDeviceID, req)
			assert.Equal(t, tc.wantCode, rec.Code)

			entry := f.findAuditAction(t, tc.wantAct)
			require.NotNil(t, entry, "expected audit action %q", tc.wantAct)
			assert.NotEmpty(t, entry.Details["device_id"], "device_id in audit")
			assert.NotEmpty(t, entry.Details["tenant_id"], "tenant_id in audit")
		})
	}
}

// TestProvenance_CannotUngateRevoked asserts that perfect provenance cannot
// override revocation. The signature supplied cannot verify, so a handler that
// evaluated provenance or PoP before revocation would answer 401; the observed
// 403 with audit reason "revoked" proves revocation wins outright.
func TestProvenance_CannotUngateRevoked(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "s-rev",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusRevoked,
		IdentityKeyPub: []byte(pub),
		// Perfect provenance — revocation must still win.
		LastProvenanceJSON: `{"hostname":"host1","mac_address":"aa:bb"}`,
	})

	// Plant a nonce so we reach the revocation gate.
	f.server.nonceCache.Set(nonceCacheKeyPrefix+testDeviceID, &nonceEntry{ //nolint:errcheck // in-memory cache; Set only fails on empty key, which is impossible here
		NonceBytes: make([]byte, 32),
		ServerTS:   uint64(time.Now().UnixNano()),
		IssuedAt:   time.Now(),
	}, nonceTTL)

	rec := postComplete(f.server, testDeviceID, RefreshCompleteRequest{
		TenantID:   testTenantID,
		Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IssuedAt:   time.Now().UnixNano(),
		Signature:  base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		Provenance: map[string]string{"hostname": "host1", "mac_address": "aa:bb"},
	})

	assert.Equal(t, http.StatusForbidden, rec.Code)

	entry := f.findAuditAction(t, "refresh_rejected")
	require.NotNil(t, entry, "refresh_rejected audit event expected")
	assert.Equal(t, "revoked", entry.Details["reason"],
		"provenance must not be able to ungate a revoked device")
}

// ---- Admin handler tests ----------------------------------------------------

func TestHandleRefreshApprove_Unauthenticated(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/some-pending-id/approve", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleRefreshApprove_ApprovesEntry(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-approve",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	pendingID := "refresh-approve-test"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	// POST /api/v1/stewards/refresh/{id}/approve is Tier-3 (mTLS-only).
	req := makeAdminRequest(t, http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/approve", nil)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "approve must succeed: %s", rec.Body.String())

	var resp AdminRefreshApproveResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "approved", resp.Status)
	assert.Equal(t, pendingID, resp.PendingID)
	assert.NotEmpty(t, resp.ClientCert, "client cert must be in response")
	assert.NotEmpty(t, resp.ClientKey, "client key must be in response")
	assert.NotEmpty(t, resp.CACert, "CA cert must be in response")

	// Verify the store was updated.
	updated, err := f.pending.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusApproved, updated.Status)
	assert.NotEmpty(t, updated.ClaimBundle, "claim bundle must be stored")

	// Verify audit event was emitted.
	entry := f.findAuditAction(t, "refresh_admin_approved")
	require.NotNil(t, entry, "refresh_admin_approved audit event expected")
	assert.NotEmpty(t, entry.Details["device_id"], "device_id in audit")
	assert.NotEmpty(t, entry.Details["tenant_id"], "tenant_id in audit")
	assert.Equal(t, "approved", entry.Details["decision"])
}

// TestHandleRefreshApprove_RevokedDeviceRejected verifies the security gate added
// for Issue #2098: a steward can be revoked AFTER its refresh is queued as pending.
// The challenge/complete paths reject revoked devices, but the admin approve path
// previously did not. Approving a now-revoked device must NOT issue a cert, must NOT
// promote the device back to "registered" (silently un-revoking it via the status
// persistence added in this story), and must leave the pending entry untouched.
func TestHandleRefreshApprove_RevokedDeviceRejected(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-revoked-pending",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusRevoked, // revoked while a refresh sat pending
		IdentityKeyPub: []byte(pub),
	})

	pendingID := "refresh-revoked-test"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	// POST /api/v1/stewards/refresh/{id}/approve is Tier-3 (mTLS-only).
	// Use admin cert so the handler's own revocation check is exercised.
	req := makeAdminRequest(t, http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/approve", nil)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	// Must be rejected — no certificate may be issued to a revoked device.
	require.Equal(t, http.StatusForbidden, rec.Code, "approving a revoked device must be forbidden: %s", rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "BEGIN", "no certificate material may be returned for a revoked device")

	// The steward must remain revoked — the status promotion must NOT un-revoke it.
	recRev, err := f.stewards.GetStewardByDeviceID(context.Background(), testDeviceID)
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusRevoked, recRev.Status,
		"revoked steward must NOT be promoted to registered on approve")

	// The pending entry must remain pending with no claim bundle.
	entry, err := f.pending.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, entry.Status,
		"pending entry must not be approved for a revoked device")
	assert.Empty(t, entry.ClaimBundle, "no claim bundle may be stored for a revoked device")

	// A security audit event must record the denial with decision+reason.
	auditEntry := f.findAuditAction(t, "refresh_admin_approve_rejected")
	require.NotNil(t, auditEntry, "refresh_admin_approve_rejected security audit event expected")
	assert.Equal(t, "denied", auditEntry.Details["decision"])
	assert.Equal(t, "revoked", auditEntry.Details["reason"])
}

func TestHandleRefreshReject_RejectsEntry(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-reject",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	pendingID := "refresh-reject-test"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	apiKey := NewTestKey(t, f.server, []string{"refresh:reject"})

	body, _ := json.Marshal(AdminRefreshRejectRequest{Reason: "unauthorized device"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/reject", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "reject must succeed: %s", rec.Body.String())

	updated, err := f.pending.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusRejected, updated.Status)

	entry := f.findAuditAction(t, "refresh_admin_rejected")
	require.NotNil(t, entry, "refresh_admin_rejected audit event expected")
	assert.Equal(t, "rejected", entry.Details["decision"])
}

func TestHandleListPendingRefreshes_ReturnsList(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: "refresh-list-1",
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	apiKey := NewTestKey(t, f.server, []string{"refresh:list-pending"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/refresh/pending", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var entries []APIPendingRefreshEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	assert.Len(t, entries, 1)
	assert.Equal(t, "refresh-list-1", entries[0].PendingID)
}

func TestHandleGetRefreshPolicy_ReturnsDefault(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	apiKey := NewTestKey(t, f.server, []string{"refresh:get-policy"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+testTenantID+"/refresh-policy", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "get-policy must succeed: %s", rec.Body.String())
	var policy AdminRefreshPolicyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &policy))
	assert.Equal(t, testTenantID, policy.TenantID)
	assert.Equal(t, "require_approval", policy.Mode)
}

func TestHandleSetRefreshPolicy_SetsMode(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))

	// PUT /api/v1/tenants/{tenant}/refresh-policy is Tier-3 (mTLS-only).
	body, _ := json.Marshal(AdminRefreshPolicyRequest{Mode: "auto_accept"})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/"+testTenantID+"/refresh-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "set-policy must succeed: %s", rec.Body.String())

	policy, err := f.policies.GetPolicy(context.Background(), testTenantID)
	require.NoError(t, err)
	assert.Equal(t, "auto_accept", policy.Mode)
}

func TestHandleSetRefreshPolicy_InvalidMode_Returns400(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))

	// PUT /api/v1/tenants/{tenant}/refresh-policy is Tier-3 (mTLS-only).
	body, _ := json.Marshal(AdminRefreshPolicyRequest{Mode: "invalid_mode"})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/"+testTenantID+"/refresh-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleRefreshApprove_NotFound(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))

	// POST /api/v1/stewards/refresh/{id}/approve is Tier-3 (mTLS-only).
	req := makeAdminRequest(t, http.MethodPost, "/api/v1/stewards/refresh/nonexistent-id/approve", nil)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRefreshReject_Unauthenticated(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/some-id/reject", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ---- Cross-tenant isolation tests for admin handlers -------------------------

func TestHandleApproveRefresh_CrossTenantReturns404(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	pendingID := "refresh-cross-approve"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID, // belongs to "test-tenant"
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	// API key from a different tenant — Tier-3 enforcement blocks at the gate (403 MTLS_REQUIRED)
	// before the handler's own cross-tenant check can fire.
	apiKey := NewEphemeralTestKey(t, f.server, []string{"refresh:approve"}, "other-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/approve", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	// Tier-3: API keys are rejected with 403 MTLS_REQUIRED regardless of tenant.
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Entry must remain pending — nothing was mutated.
	entry, err := f.pending.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, entry.Status)
}

func TestHandleRejectRefresh_CrossTenantReturns404(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	pendingID := "refresh-cross-reject"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID, // belongs to "test-tenant"
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	// API key scoped to a different tenant.
	apiKey := NewEphemeralTestKey(t, f.server, []string{"refresh:reject"}, "other-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/reject", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Entry must remain pending — nothing was mutated.
	entry, err := f.pending.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, entry.Status)
}

func TestHandleListPendingRefreshes_ScopedCallerSeesOnlyOwnTenant(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: "refresh-own-tenant",
		DeviceID:  testDeviceID,
		TenantID:  testTenantID, // caller's own tenant
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: "refresh-other-tenant",
		DeviceID:  "bbbbbbbbbbbbbbbb",
		TenantID:  "other-tenant", // another tenant's entry
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	// Key scoped to testTenantID — must only see its own entries regardless of query param.
	apiKey := NewTestKey(t, f.server, []string{"refresh:list-pending"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/refresh/pending", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var entries []APIPendingRefreshEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	require.Len(t, entries, 1, "scoped caller must only see own-tenant entries")
	assert.Equal(t, testTenantID, entries[0].TenantID)
	assert.Equal(t, "refresh-own-tenant", entries[0].PendingID)
}

func TestHandleGetRefreshPolicy_CrossTenantReturns404(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	// Key scoped to "other-tenant" — must not read policy for testTenantID.
	apiKey := NewEphemeralTestKey(t, f.server, []string{"refresh:get-policy"}, "other-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+testTenantID+"/refresh-policy", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleSetRefreshPolicy_CrossTenantReturns404(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	// API key scoped to "other-tenant" — Tier-3 enforcement blocks at the gate (403 MTLS_REQUIRED)
	// before the handler's own cross-tenant check can fire.
	apiKey := NewEphemeralTestKey(t, f.server, []string{"refresh:set-policy"}, "other-tenant", 5*time.Minute)

	body, _ := json.Marshal(AdminRefreshPolicyRequest{Mode: "reject"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+testTenantID+"/refresh-policy", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	// Tier-3: API keys are rejected with 403 MTLS_REQUIRED regardless of tenant.
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Policy for testTenantID must remain at default — nothing mutated.
	policy, err := f.policies.GetPolicy(context.Background(), testTenantID)
	require.NoError(t, err)
	assert.Equal(t, "require_approval", policy.Mode)
}

func TestRefresh_NoPolicyDefault(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "s-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})
	// No policy row is written for this tenant — the store returns the
	// require_approval default defined by ADR-010 §4.

	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	rec := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusAccepted, rec.Code, "default policy must queue: %s", rec.Body.String())
	assert.Equal(t, 1, f.pendingCount(t), "one pending entry must be created")
}

// TestRefresh_AutoAccept_NoProvenanceBaseline verifies that auto_accept policy issues a
// cert immediately when the steward has no stored provenance (LastProvenanceJSON == "").
// Initial registration never stores provenance, so the first refresh must not be demoted
// to require_approval by a score-of-zero comparison against an absent baseline.
func TestRefresh_AutoAccept_NoProvenanceBaseline(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:                 "s-active",
		DeviceID:           testDeviceID,
		TenantID:           testTenantID,
		Status:             business.StewardStatusActive,
		IdentityKeyPub:     []byte(pub),
		LastProvenanceJSON: "", // no baseline — first refresh after registration
	})
	f.setPolicy(t, &business.RefreshPolicy{TenantID: testTenantID, Mode: "auto_accept"})

	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	rec := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusOK, rec.Code, "auto_accept with no provenance baseline must issue cert immediately: %s", rec.Body.String())
	assert.Equal(t, 0, f.pendingCount(t), "no pending entry must be created for auto_accept with no baseline")

	var resp RefreshCompleteResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "approved", resp.Status)
	assert.NotEmpty(t, resp.ClientCert)
	assert.NotEmpty(t, resp.ClientKey)
	assert.NotEmpty(t, resp.CACert)
}
