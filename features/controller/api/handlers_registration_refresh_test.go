// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	stwreg "github.com/cfgis/cfgms/features/steward/registration"
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
	nonces   business.NonceStore
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
	seedTestRootTenant(t, tenantManager)
	testTenantStores.Store(tenantManager, tenantStore)
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
		nil, // Issue #4208: health alert manager
		nil, // Issue #4208: health trace manager
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
	nonces := storageManager.GetNonceStore()
	require.NotNil(t, stewards, "test storage must provide a real StewardStore")
	require.NotNil(t, pending, "test storage must provide a real PendingRefreshStore")
	require.NotNil(t, policies, "test storage must provide a real RefreshPolicyStore")
	require.NotNil(t, nonces, "test storage must provide a real NonceStore")

	server.SetStewardStore(stewards)
	server.SetPendingRefreshStore(pending)
	server.SetRefreshPolicyStore(policies)
	server.SetNonceStore(nonces)

	return &refreshFixture{
		server:   server,
		audit:    auditMgr,
		stewards: stewards,
		pending:  pending,
		policies: policies,
		nonces:   nonces,
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

// plantNonce writes a nonce directly into the real NonceStore, bypassing the
// challenge handler, so complete-endpoint tests can reach gates beyond the
// nonce lookup without first calling handleRefreshChallenge.
func (f *refreshFixture) plantNonce(t *testing.T, deviceID string) {
	t.Helper()
	entry, err := json.Marshal(&refreshNonceEntry{
		NonceBytes: make([]byte, 32),
		ServerTS:   uint64(time.Now().UnixNano()),
		IssuedAt:   time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, f.nonces.PutNonce(context.Background(), refreshNonceKeyPrefix+deviceID, entry, nonceTTL))
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
		CSRPEM:     testValidCSRPEM,
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
	// Verify no nonce was stored.
	_, found, err := f.nonces.GetAndConsumeNonce(context.Background(), refreshNonceKeyPrefix+testDeviceID)
	require.NoError(t, err)
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
	f.plantNonce(t, testDeviceID)

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

// TestHandleRefreshComplete_CrossNodeNonceHandoff is the [REQUIRED TEST] for
// Issue #3755 (ADR-031 amendment to ADR-011): a nonce issued via one NonceStore
// instance must be consumable via a second, independent instance backed by the
// same durable store — simulating the challenge and completion landing on two
// different controller nodes under any-node service (ADR-031 Decision 1).
// Double-consumption must then fail from either node.
func TestHandleRefreshComplete_CrossNodeNonceHandoff(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	nodeA, nodeB := newTestNonceStorePair(t)

	// Challenge lands on node A.
	f.server.SetNonceStore(nodeA)
	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	// Completion lands on node B — a different controller node sharing the
	// same durable store. It must be able to read and consume the nonce that
	// node A wrote.
	f.server.SetNonceStore(nodeB)
	rec1 := postComplete(f.server, testDeviceID, req)
	require.Equal(t, http.StatusAccepted, rec1.Code,
		"nonce issued via node A must be consumable via node B: %s", rec1.Body.String())

	// Double-consumption must fail on node B (already consumed).
	rec2 := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code, "nonce already consumed must not be usable again on node B")

	// Double-consumption must also fail on node A (same durable store, no
	// leftover entry to find regardless of which node looks).
	f.server.SetNonceStore(nodeA)
	rec3 := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusUnauthorized, rec3.Code, "nonce already consumed must not be usable again on node A")
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

// TestHandleRefreshComplete_ReqTenantIDIsNotASecurityControl replaces the old
// TestHandleRefreshComplete_CrossTenantReturns403: req.TenantID is an
// unauthenticated, caller-asserted field on a pre-authentication endpoint
// (Issue #4350), so it must never gate the outcome — omitting it, or setting it
// to any value at all, must not change what the handshake does. The only thing
// that determines the outcome is proof-of-possession against the resolved
// record's IdentityKeyPub.
func TestHandleRefreshComplete_ReqTenantIDIsNotASecurityControl(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)

	for _, reqTenantID := range []string{"", "test-tenant", "some-other-tenant", "tenant-b"} {
		t.Run("tenant_id="+reqTenantID, func(t *testing.T) {
			f := newRefreshFixture(t, nil)
			f.addSteward(t, &business.StewardRecord{
				ID:             "steward-a",
				DeviceID:       testDeviceID,
				TenantID:       "tenant-a",
				Status:         business.StewardStatusArchived,
				IdentityKeyPub: []byte(pub),
			})

			challenge := issueChallenge(t, f.server, testDeviceID, reqTenantID)
			req := buildValidCompleteRequest(t, testDeviceID, reqTenantID, challenge, priv, nil)
			rec := postComplete(f.server, testDeviceID, req)

			require.Equal(t, http.StatusAccepted, rec.Code,
				"a valid PoP signature must succeed regardless of req.TenantID: %s", rec.Body.String())
		})
	}
}

// TestHandleRefreshComplete_DeviceIDCollisionAcrossTenants covers the
// [REQUIRED TEST] from Issue #4350: two stewards in different tenants share
// one device_id (allowed by design — only same-tenant device_id is unique).
// The pre-authentication refresh handshake uses the unscoped, deterministic
// GetStewardByDeviceID lookup, which always resolves the collision to
// "steward-a" (the lexicographically smallest ID). Every outcome below must be
// attributed to tenant-a — never tenant-b — regardless of what req.TenantID
// asserts, proving the collision cannot be used to act on the other tenant's
// record and that req.TenantID has no effect on which record is acted upon.
func TestHandleRefreshComplete_DeviceIDCollisionAcrossTenants(t *testing.T) {
	pubA, privA := newTestEd25519KeyPair(t)
	pubB, _ := newTestEd25519KeyPair(t)

	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-a",
		DeviceID:       testDeviceID,
		TenantID:       "tenant-a",
		Status:         business.StewardStatusArchived,
		IdentityKeyPub: []byte(pubA),
	})
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-b",
		DeviceID:       testDeviceID,
		TenantID:       "tenant-b",
		Status:         business.StewardStatusArchived,
		IdentityKeyPub: []byte(pubB),
	})

	for _, reqTenantID := range []string{"", "tenant-a", "tenant-b"} {
		t.Run("req_tenant_id="+reqTenantID, func(t *testing.T) {
			challenge := issueChallenge(t, f.server, testDeviceID, reqTenantID)
			req := buildValidCompleteRequest(t, testDeviceID, reqTenantID, challenge, privA, nil)
			rec := postComplete(f.server, testDeviceID, req)
			require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
		})
	}

	entries, err := f.pending.ListPendingRefresh(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for _, e := range entries {
		assert.Equal(t, "tenant-a", e.TenantID,
			"every queued entry must belong to the deterministically-resolved, PoP-confirmed tenant-a record")
		assert.Equal(t, testDeviceID, e.DeviceID)
	}
}

// TestHandleRefreshComplete_DeviceIDCollision_WrongOwnerPoPFails is the other
// half of the same [REQUIRED TEST]: the device that actually belongs to
// tenant-b signs with its own private key. The collision still resolves the
// lookup to tenant-a's record, so tenant-b's real signature cannot verify
// against tenant-a's public key — the handshake fails outright rather than
// silently acting on tenant-a's record on tenant-b's behalf.
func TestHandleRefreshComplete_DeviceIDCollision_WrongOwnerPoPFails(t *testing.T) {
	pubA, _ := newTestEd25519KeyPair(t)
	_, privB := newTestEd25519KeyPair(t)

	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-a",
		DeviceID:       testDeviceID,
		TenantID:       "tenant-a",
		Status:         business.StewardStatusArchived,
		IdentityKeyPub: []byte(pubA),
	})
	f.addSteward(t, &business.StewardRecord{
		ID:       "steward-b",
		DeviceID: testDeviceID,
		TenantID: "tenant-b",
		Status:   business.StewardStatusArchived,
	})

	challenge := issueChallenge(t, f.server, testDeviceID, "")
	req := buildValidCompleteRequest(t, testDeviceID, "", challenge, privB, nil)
	rec := postComplete(f.server, testDeviceID, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"tenant-b's real device must not be able to complete a refresh via the collision")

	entries, err := f.pending.ListPendingRefresh(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, entries, "a failed PoP verification must not queue or act on any record")
}

// TestHandleRefreshChallenge_RevokedSiblingDeviceIDCollision covers the
// [REQUIRED TEST]: a revoked record is still rejected at the refresh gate when
// a non-revoked sibling exists with the same device_id in a different tenant.
// Deterministic resolution picks "steward-a" (revoked) over "steward-b"
// (active), so the challenge must be denied before any nonce is issued —
// revocation-before-PoP still holds even under a device_id collision.
func TestHandleRefreshChallenge_RevokedSiblingDeviceIDCollision(t *testing.T) {
	f := newRefreshFixture(t, nil)
	f.addSteward(t, &business.StewardRecord{
		ID:       "steward-a",
		DeviceID: testDeviceID,
		TenantID: "tenant-a",
		Status:   business.StewardStatusRevoked,
	})
	f.addSteward(t, &business.StewardRecord{
		ID:       "steward-b",
		DeviceID: testDeviceID,
		TenantID: "tenant-b",
		Status:   business.StewardStatusActive,
	})

	body, err := json.Marshal(RefreshChallengeRequest{})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+testDeviceID+"/refresh/challenge", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"device_id": testDeviceID})
	rec := httptest.NewRecorder()
	f.server.handleRefreshChallenge(rec, r)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"deterministic ordering must resolve the collision to the revoked record and deny before any nonce is issued")

	entry := f.findAuditAction(t, "refresh_challenge_rejected")
	require.NotNil(t, entry)
	assert.Equal(t, "revoked", entry.Details["reason"])
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
	f.plantNonce(t, testDeviceID)

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
		CSRPEM:    testValidCSRPEM,
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
	assert.NotEmpty(t, resp.CACert, "CA cert must be in response")

	var rawApproveResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rawApproveResp))
	assert.NotContains(t, rawApproveResp, "client_key",
		"AdminRefreshApproveResponse must never carry client_key (Issue #3781)")

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

// TestHandleApproveRefresh_DeviceIDCollisionAcrossTenants covers the
// [REQUIRED TEST]: handleApproveRefresh with a colliding device_id resolves
// only the steward belonging to entry.TenantID, not a same-device-id steward
// in a different tenant. "steward-0-other-tenant" is named to sort BEFORE
// "steward-a" so that the deterministic-by-ID unscoped lookup (used elsewhere
// in the pre-authentication handshake) would pick the wrong tenant's record if
// this handler had not been fixed to call the tenant-scoped
// GetStewardByDeviceIDForTenant — this test fails under the pre-fix code path.
func TestHandleApproveRefresh_DeviceIDCollisionAcrossTenants(t *testing.T) {
	pubA, _ := newTestEd25519KeyPair(t)
	pubOther, _ := newTestEd25519KeyPair(t)

	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-a",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pubA),
	})
	f.addSteward(t, &business.StewardRecord{
		ID:             "steward-0-other-tenant",
		DeviceID:       testDeviceID,
		TenantID:       "other-tenant",
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pubOther),
	})

	pendingID := "refresh-approve-collision"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID, // resolved and authorized against this tenant
		CSRPEM:    testValidCSRPEM,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	req := makeAdminRequest(t, http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/approve", nil)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "approve must succeed: %s", rec.Body.String())

	entry := f.findAuditAction(t, "refresh_admin_approved")
	require.NotNil(t, entry, "refresh_admin_approved audit event expected")
	assert.Equal(t, testTenantID, entry.TenantID,
		"the approved record must belong to entry.TenantID, never the colliding other-tenant record")

	updated, err := f.pending.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusApproved, updated.Status)
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

// TestHandleListPendingRefreshes_ScopedCallerSeesDescendantNotSibling is the
// [REQUIRED TEST] for Issue #4656: with real tenants msp-a, client-1 (child of
// msp-a), msp-b and msp-ab, a caller scoped to msp-a sees client-1's entries and
// none of msp-b's or the shared-prefix sibling msp-ab's.
func TestHandleListPendingRefreshes_ScopedCallerSeesDescendantNotSibling(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	seedScopeTenants(t, f.server)
	for id, tenantID := range map[string]string{
		"refresh-msp-a":    "msp-a",
		"refresh-client-1": "client-1",
		"refresh-msp-b":    "msp-b",
		"refresh-msp-ab":   "msp-ab",
	} {
		f.addPending(t, &business.PendingRefreshEntry{
			PendingID: id,
			DeviceID:  id,
			TenantID:  tenantID,
			Status:    business.PendingRefreshStatusPending,
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		})
	}

	apiKey := NewEphemeralTestKey(t, f.server, []string{"refresh:list-pending"}, "msp-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/refresh/pending", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var entries []APIPendingRefreshEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	got := map[string]bool{}
	for _, e := range entries {
		got[e.PendingID] = true
	}
	assert.Equal(t, map[string]bool{"refresh-msp-a": true, "refresh-client-1": true}, got)
}

// TestHandleGetRefreshPolicy_ScopedCallerReadsDescendant verifies a caller scoped
// to msp-a reads a descendant's policy and is denied a sibling's.
func TestHandleGetRefreshPolicy_ScopedCallerReadsDescendant(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))
	seedScopeTenants(t, f.server)
	apiKey := NewEphemeralTestKey(t, f.server, []string{"refresh:get-policy"}, "msp-a", 5*time.Minute)

	get := func(tenantID string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID+"/refresh-policy", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		f.server.router.ServeHTTP(rec, req)
		return rec.Code
	}
	assert.Equal(t, http.StatusOK, get("client-1"))
	assert.Equal(t, http.StatusNotFound, get("msp-b"))
	assert.Equal(t, http.StatusNotFound, get("msp-ab"))
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

// TestHandleRefreshComplete_MissingCSRPEM_400 verifies that a refresh-complete
// request with csr_pem unset is rejected before any certificate is signed
// (Issue #3781 AC, mirrors #3780's registration-side test).
func TestHandleRefreshComplete_MissingCSRPEM_400(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:             "s-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)
	req.CSRPEM = "" // intentionally omitted

	rec := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "csr_pem")
	assert.NotContains(t, rec.Body.String(), "BEGIN CERTIFICATE", "no certificate may be signed when csr_pem is missing")
}

// TestHandleRefreshComplete_CSRContainsPrivateKeyMaterial_400 verifies that a csr_pem
// body smuggling private key material alongside the CERTIFICATE REQUEST block is
// rejected (via containsPrivateKeyMaterial) before any certificate is signed
// (Issue #3781 AC).
func TestHandleRefreshComplete_CSRContainsPrivateKeyMaterial_400(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID:             "s-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	smugglePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(smugglePriv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	challenge := issueChallenge(t, f.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)
	req.CSRPEM = testValidCSRPEM + string(keyPEM)

	rec := postComplete(f.server, testDeviceID, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "private key material")
	assert.NotContains(t, rec.Body.String(), "BEGIN CERTIFICATE", "no certificate may be signed when the CSR carries embedded private key material")
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
	assert.NotEmpty(t, resp.CACert)
	assert.Empty(t, resp.IssuerChain, "issuer_chain must be empty for a root-only CA (self-hosted default)")

	var rawResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rawResp))
	assert.NotContains(t, rawResp, "client_key", "refresh complete response must never carry client_key (Issue #3781)")
}

// TestRefresh_AutoAccept_IntermediateCA_IncludesIssuerChain verifies issuer_chain
// is present and non-empty on the refresh-complete response (buildRefreshClaimResponse)
// when the controller's cert manager is backed by an intermediate CA (Issue #3778).
// [REQUIRED TEST]
func TestRefresh_AutoAccept_IntermediateCA_IncludesIssuerChain(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestIntermediateCertManager(t))
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
	require.Equal(t, http.StatusOK, rec.Code, "auto_accept with no provenance baseline must issue cert immediately: %s", rec.Body.String())

	var resp RefreshCompleteResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "approved", resp.Status)
	assert.NotEmpty(t, resp.ClientCert)
	assert.NotEmpty(t, resp.IssuerChain, "issuer_chain must be present and non-empty when the cert manager is backed by an intermediate CA")
}

// TestRefresh_EndToEnd_CompleteToMTLSHandshake drives the full CSR-based
// registration-refresh flow with no mocks: a real pkg/cert-backed controller (via
// the real HTTP router) is refreshed against by a real
// features/steward/registration.HTTPClient, through challenge -> proof-of-possession
// -> CSR submission -> immediate cert issuance, and the resulting controller-signed
// certificate is paired with the steward's own freshly generated local key to
// complete a genuine mTLS handshake against a throwaway listener. It also proves the
// renewed key is provably different from the pre-refresh key — the old key must not
// silently persist as a usable credential for the new certificate (Issue #3781 AC).
func TestRefresh_EndToEnd_CompleteToMTLSHandshake(t *testing.T) {
	certMgr := newTestCertManager(t)
	f := newRefreshFixture(t, certMgr)
	pub, priv := newTestEd25519KeyPair(t)
	f.addSteward(t, &business.StewardRecord{
		ID:             "s-e2e-refresh",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})
	f.setPolicy(t, &business.RefreshPolicy{TenantID: testTenantID, Mode: "auto_accept"})

	ts := httptest.NewServer(f.server.router)
	defer ts.Close()

	stewardClient, err := stwreg.NewHTTPClient(&stwreg.HTTPConfig{
		ControllerURL: ts.URL,
		Logger:        logging.NewNoopLogger(),
	})
	require.NoError(t, err)

	// Step 1: Challenge. The real steward client requests a nonce.
	challenge, err := stewardClient.RefreshChallenge(context.Background(), testDeviceID)
	require.NoError(t, err)

	// Step 2: Compute the proof-of-possession signature exactly as ADR-011 §4
	// specifies, over the steward's device-identity Ed25519 key (unrelated to the
	// mTLS keypair generated below).
	nonceBytes, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	require.NoError(t, err)
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], challenge.ServerTS)
	h := sha256.New()
	h.Write(nonceBytes)
	h.Write([]byte(testDeviceID))
	h.Write(tsBytes[:])
	pop := ed25519.Sign(priv, h.Sum(nil))

	// Step 3: Generate a fresh mTLS keypair for the renewed credential and submit
	// only its public half as a CSR (Issue #3781) — the controller never generates
	// or sees this private key.
	renewedKey, err := stwreg.GenerateStewardKeypair()
	require.NoError(t, err)
	csrPEM, err := stwreg.BuildRegistrationCSR(renewedKey, testDeviceID)
	require.NoError(t, err)

	// A "pre-refresh" key, standing in for whatever mTLS key the steward held
	// before this refresh — generated independently, never submitted anywhere.
	oldKey, err := stwreg.GenerateStewardKeypair()
	require.NoError(t, err)
	oldKeyPEM, err := stwreg.EncodeECDSAPrivateKeyPEM(oldKey)
	require.NoError(t, err)

	completeResp, err := stewardClient.RefreshComplete(context.Background(), testDeviceID, testTenantID,
		challenge.Nonce, int64(challenge.ServerTS), pop, csrPEM)
	require.NoError(t, err)
	require.NotNil(t, completeResp)
	require.NotEmpty(t, completeResp.ClientCert)

	renewedKeyPEM, err := stwreg.EncodeECDSAPrivateKeyPEM(renewedKey)
	require.NoError(t, err)
	require.NotEqual(t, oldKeyPEM, renewedKeyPEM, "the renewed key must differ from the pre-refresh key")

	// The pre-refresh key must NOT pair with the renewed certificate — it must not
	// silently persist as a usable credential for the new cert.
	_, err = tls.X509KeyPair([]byte(completeResp.ClientCert), []byte(oldKeyPEM))
	assert.Error(t, err, "the pre-refresh key must not form a usable pair with the renewed certificate")

	// Step 4: Combine the steward-held renewed key with the controller-issued
	// certificate exactly as the steward's own transport layer does, and complete a
	// real mTLS handshake against a throwaway listener that requires and verifies
	// the client certificate against the same CA.
	stewardTLSCert, err := tls.X509KeyPair([]byte(completeResp.ClientCert), []byte(renewedKeyPEM))
	require.NoError(t, err, "controller-issued certificate and the renewed steward-held key must form a usable TLS pair")

	caCertPool := x509.NewCertPool()
	require.True(t, caCertPool.AppendCertsFromPEM([]byte(completeResp.CACert)))

	listenerCert, err := certMgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "mtls-listener-refresh.test",
		DNSNames:     []string{"mtls-listener-refresh.test"},
		Organization: "CFGMS Test",
		ValidityDays: 1,
	})
	require.NoError(t, err)
	listenerTLSCert, err := tls.X509KeyPair(listenerCert.CertificatePEM, listenerCert.PrivateKeyPEM)
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{listenerTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			accepted <- fmt.Errorf("accepted connection is not a *tls.Conn")
			return
		}
		accepted <- tlsConn.HandshakeContext(context.Background())
	}()

	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{stewardTLSCert},
		RootCAs:      caCertPool,
		ServerName:   "mtls-listener-refresh.test",
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err, "the renewed steward-held key and controller-issued certificate must complete a real mTLS handshake")
	defer func() { _ = clientConn.Close() }()

	require.NoError(t, <-accepted, "the listener must accept and verify the steward's renewed client certificate against the delivered CA")
}

// ---- Root-scoped ADR-025 Decision 1 guard tests for handleApproveRefresh (Issue #3303) ---

// approveRefreshRequest builds a handler-level POST request for the approve endpoint
// with mux vars set and the given principal injected into context.
func approveRefreshRequest(pendingID string, principal *Principal) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/approve", nil)
	req = mux.SetURLVars(req, map[string]string{"pending_id": pendingID})
	ctx := context.WithValue(withCallerTenant(req.Context(), principal.TenantID), principalContextKey, principal)
	return req.WithContext(ctx)
}

// TestHandleApproveRefresh_RootScoped_NoCrossing_Returns404 is the REQUIRED TEST
// (Issue #3303, AC "asserts the guard denies a foreign-tenant/foreign-subtree request"):
// a root-scoped principal without an active crossing for the pending refresh's tenant
// receives 404 "pending refresh not found" — the same existence-oracle response as the
// tenant-scoped denial path — so the endpoint does not disclose pending-refresh
// existence across tenant boundaries.
func TestHandleApproveRefresh_RootScoped_NoCrossing_Returns404(t *testing.T) {
	f := newRefreshFixture(t, nil)
	pendingID := "refresh-root-no-crossing"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID, // "test-tenant" — not under "root" in this hierarchy-less store
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	// root-scoped principal: TenantID == "", RootScoped == true.
	principal := rootScopedPrincipal("root-op-no-crossing")
	req := approveRefreshRequest(pendingID, principal)
	rec := httptest.NewRecorder()
	f.server.handleApproveRefresh(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"root-scoped caller without a crossing must receive 404, not disclose the pending refresh")
	assert.Contains(t, rec.Body.String(), "pending refresh not found")

	// Entry must remain pending — nothing was mutated.
	entry, err := f.pending.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, entry.Status)
}

// TestHandleApproveRefresh_RootScoped_RootTenantItself_ProceedsGuard is the REQUIRED
// TEST counterpart (Issue #3303, AC "allows an in-scope one"): a root-scoped principal
// targeting a pending refresh in the root tenant itself (always allowed, no crossing
// required) passes the guard. The request proceeds past the guard and reaches the steward
// lookup, which returns 404 "steward not found" because the steward is not registered —
// confirming the guard did not block it.
func TestHandleApproveRefresh_RootScoped_RootTenantItself_ProceedsGuard(t *testing.T) {
	f := newRefreshFixture(t, nil)
	pendingID := "refresh-root-tenant-itself"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  "root", // root tenant itself — always allowed for root-scoped principals
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	principal := rootScopedPrincipal("root-op-root-tenant")
	req := approveRefreshRequest(pendingID, principal)
	rec := httptest.NewRecorder()
	f.server.handleApproveRefresh(rec, req)

	// The guard passed — the handler reached the steward lookup, which returns 404
	// "steward not found" (not 404 "pending refresh not found"), proving the guard allowed it.
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "pending refresh not found",
		"response must not be the guard's 404 — handler must have proceeded past the guard")
	assert.Contains(t, rec.Body.String(), "steward not found",
		"handler must have reached the steward lookup after the guard passed")
}

// postClaim proves possession with a fresh challenge and POSTs to handleRefreshClaim.
func postClaim(t *testing.T, server *Server, deviceID, tenantID, pendingID string, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	challenge := issueChallenge(t, server, deviceID, tenantID)
	proof := buildValidCompleteRequest(t, deviceID, tenantID, challenge, priv, nil)
	body, _ := json.Marshal(RefreshClaimRequest{
		PendingID: pendingID,
		Nonce:     proof.Nonce,
		IssuedAt:  proof.IssuedAt,
		Signature: proof.Signature,
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+deviceID+"/refresh/claim", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"device_id": deviceID})
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleRefreshClaim(rec, r)
	return rec
}

// TestHandleRefreshClaim_DeliversApprovedRefresh guards Issue #4532: an approved
// refresh is collected by the steward that proved possession — previously it was
// signed and stored but never delivered, so a steward under require_approval
// re-queued forever.
func TestHandleRefreshClaim_DeliversApprovedRefresh(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID: "steward-claim", DeviceID: testDeviceID, TenantID: testTenantID,
		Status: business.StewardStatusActive, IdentityKeyPub: []byte(pub),
	})
	f.setPolicy(t, &business.RefreshPolicy{TenantID: testTenantID, Mode: "require_approval"})

	queued := postComplete(f.server, testDeviceID, buildValidCompleteRequest(t, testDeviceID, testTenantID, issueChallenge(t, f.server, testDeviceID, testTenantID), priv, nil))
	require.Equal(t, http.StatusAccepted, queued.Code, queued.Body.String())
	var q RefreshCompleteResponse
	require.NoError(t, json.Unmarshal(queued.Body.Bytes(), &q))

	pending := postClaim(t, f.server, testDeviceID, testTenantID, q.PendingID, priv)
	require.Equal(t, http.StatusAccepted, pending.Code, "before approval the claim reports pending: %s", pending.Body.String())

	approve := httptest.NewRecorder()
	f.server.router.ServeHTTP(approve, makeAdminRequest(t, http.MethodPost, "/api/v1/stewards/refresh/"+q.PendingID+"/approve", nil))
	require.Equal(t, http.StatusOK, approve.Code, approve.Body.String())

	claimed := postClaim(t, f.server, testDeviceID, testTenantID, q.PendingID, priv)
	require.Equal(t, http.StatusOK, claimed.Code, claimed.Body.String())
	var bundle RefreshCompleteResponse
	require.NoError(t, json.Unmarshal(claimed.Body.Bytes(), &bundle))
	assert.NotEmpty(t, bundle.ClientCert)
	assert.NotEmpty(t, bundle.CACert)
	assert.Equal(t, "steward-claim", bundle.StewardID, "the bundle carries the identity a steward needs to rebuild its record")
	assert.Equal(t, testTenantID, bundle.TenantID)

	again := postClaim(t, f.server, testDeviceID, testTenantID, q.PendingID, priv)
	assert.Equal(t, http.StatusNotFound, again.Code, "a claimed refresh is delivered once")
}

// TestHandleRefreshClaim_Refusals covers the claim endpoint's refusals: a wrong
// key, another device's pending entry, and a rejected refresh.
func TestHandleRefreshClaim_Refusals(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	_, wrongPriv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID: "steward-claim-r", DeviceID: testDeviceID, TenantID: testTenantID,
		Status: business.StewardStatusActive, IdentityKeyPub: []byte(pub),
	})
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: "refresh-other-device", DeviceID: "other-device", TenantID: testTenantID,
		CSRPEM: testValidCSRPEM, Status: business.PendingRefreshStatusApproved, ClaimBundle: []byte(`{"status":"approved"}`),
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: "refresh-rejected", DeviceID: testDeviceID, TenantID: testTenantID,
		CSRPEM: testValidCSRPEM, Status: business.PendingRefreshStatusRejected,
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	})

	assert.Equal(t, http.StatusUnauthorized, postClaim(t, f.server, testDeviceID, testTenantID, "refresh-rejected", wrongPriv).Code,
		"a claim without the device key's proof is refused")
	assert.Equal(t, http.StatusNotFound, postClaim(t, f.server, testDeviceID, testTenantID, "refresh-other-device", priv).Code,
		"another device's pending refresh is indistinguishable from an unknown one")
	assert.Equal(t, http.StatusForbidden, postClaim(t, f.server, testDeviceID, testTenantID, "refresh-rejected", priv).Code)
	assert.Equal(t, http.StatusNotFound, postClaim(t, f.server, testDeviceID, testTenantID, "refresh-missing", priv).Code)
}

// TestHandleApproveRefresh_AccountBoundRootScope_NoCrossing_Returns404 guards the
// inline crossing check on a {pending_id} route (the middleware boundary is skipped):
// an account-bound root-scope caller without the marker is subject to the boundary
// exactly like a marked one, so without a crossing it gets the same 404 and nothing
// is mutated.
func TestHandleApproveRefresh_AccountBoundRootScope_NoCrossing_Returns404(t *testing.T) {
	f := newRefreshFixture(t, nil)
	pendingID := "refresh-bound-root-no-crossing"
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})

	req := approveRefreshRequest(pendingID, boundRootScopeNoMarker("root-account-refresh"))
	rec := httptest.NewRecorder()
	f.server.handleApproveRefresh(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "pending refresh not found",
		"the crossing guard, not a later lookup, must refuse the request")

	entry, err := f.pending.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, entry.Status)
}

// TestHandleRefreshClaim_ExpiredPendingIsNotAvailable verifies an expired pending
// entry answers 404 so the steward files a new request.
func TestHandleRefreshClaim_ExpiredPendingIsNotAvailable(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID: "steward-exp", DeviceID: testDeviceID, TenantID: testTenantID,
		Status: business.StewardStatusActive, IdentityKeyPub: []byte(pub),
	})
	f.addPending(t, &business.PendingRefreshEntry{
		PendingID: "refresh-expired", DeviceID: testDeviceID, TenantID: testTenantID,
		CSRPEM: testValidCSRPEM, Status: business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC().Add(-8 * 24 * time.Hour), ExpiresAt: time.Now().UTC().Add(-time.Hour),
	})
	assert.Equal(t, http.StatusNotFound, postClaim(t, f.server, testDeviceID, testTenantID, "refresh-expired", priv).Code)
}

// TestHandleRefreshComplete_RequeueSupersedesOpenRequest guards the #4533 review:
// a device that files a new request supersedes its own open one, so repeated
// re-admission attempts keep one open entry per device in the approval queue.
func TestHandleRefreshComplete_RequeueSupersedesOpenRequest(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID: "steward-requeue", DeviceID: testDeviceID, TenantID: testTenantID,
		Status: business.StewardStatusActive, IdentityKeyPub: []byte(pub),
	})
	f.setPolicy(t, &business.RefreshPolicy{TenantID: testTenantID, Mode: "require_approval"})

	for i := 0; i < 3; i++ {
		rec := postComplete(f.server, testDeviceID, buildValidCompleteRequest(t, testDeviceID, testTenantID, issueChallenge(t, f.server, testDeviceID, testTenantID), priv, nil))
		require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	}

	entries, err := f.pending.ListPendingRefresh(context.Background(), testTenantID)
	require.NoError(t, err)
	open := 0
	for _, e := range entries {
		if e.Status == business.PendingRefreshStatusPending {
			open++
		}
	}
	assert.Equal(t, 1, open, "only the newest request stays open")
}

// TestRefreshRoutes_RateLimitedPerSource guards the #4533 review: the public
// refresh handshake has a per-source budget like the other public routes.
func TestRefreshRoutes_RateLimitedPerSource(t *testing.T) {
	f := newRefreshFixture(t, newTestCertManager(t))

	limited := false
	for i := 0; i < 300 && !limited; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/unknown-device/refresh/challenge", bytes.NewReader([]byte(`{}`)))
		r.RemoteAddr = "198.51.100.7:4000"
		rec := httptest.NewRecorder()
		f.server.router.ServeHTTP(rec, r)
		limited = rec.Code == http.StatusTooManyRequests
	}
	assert.True(t, limited, "one source exceeding the per-minute budget is refused with 429")
}

func TestHandleListPendingRefreshes_ResolvesHostnameTenantScoped(t *testing.T) {
	pubA, _ := newTestEd25519KeyPair(t)
	pubOther, _ := newTestEd25519KeyPair(t)

	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID: "steward-a", DeviceID: testDeviceID, TenantID: testTenantID, Hostname: "host-a",
		Status: business.StewardStatusActive, IdentityKeyPub: []byte(pubA),
	})
	// Same device_id in another tenant must never leak its hostname.
	f.addSteward(t, &business.StewardRecord{
		ID: "steward-b", DeviceID: "cccccccccccccccc", TenantID: "other-tenant", Hostname: "host-b-secret",
		Status: business.StewardStatusActive, IdentityKeyPub: []byte(pubOther),
	})
	now := time.Now().UTC()
	for _, e := range []*business.PendingRefreshEntry{
		{PendingID: "r-known", DeviceID: testDeviceID, TenantID: testTenantID},
		{PendingID: "r-unknown", DeviceID: "dddddddddddddddd", TenantID: testTenantID},
		{PendingID: "r-crosstenant", DeviceID: "cccccccccccccccc", TenantID: testTenantID},
	} {
		e.Status = business.PendingRefreshStatusPending
		e.CreatedAt = now
		e.ExpiresAt = now.Add(7 * 24 * time.Hour)
		f.addPending(t, e)
	}

	apiKey := NewTestKey(t, f.server, []string{"refresh:list-pending"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/refresh/pending", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var entries []APIPendingRefreshEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	got := map[string]string{}
	for _, e := range entries {
		got[e.PendingID] = e.Hostname
	}
	assert.Equal(t, map[string]string{"r-known": "host-a", "r-unknown": "", "r-crosstenant": ""}, got)
	assert.NotContains(t, rec.Body.String(), "host-b-secret")
}
