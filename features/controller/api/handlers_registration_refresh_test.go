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
	"sync"
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
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// ---- Test-only in-memory stores ---------------------------------------------

// testStewardStore is a thread-safe in-memory StewardStore for handler tests.
type testStewardStore struct {
	mu       sync.RWMutex
	records  map[string]*business.StewardRecord // keyed by steward ID
	byDevice map[string]*business.StewardRecord // keyed by device ID
}

func newTestStewardStore() *testStewardStore {
	return &testStewardStore{
		records:  make(map[string]*business.StewardRecord),
		byDevice: make(map[string]*business.StewardRecord),
	}
}

func (s *testStewardStore) add(rec *business.StewardRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *rec
	s.records[rec.ID] = &cp
	if rec.DeviceID != "" {
		s.byDevice[rec.DeviceID] = &cp
	}
}

func (s *testStewardStore) RegisterSteward(_ context.Context, r *business.StewardRecord) error {
	s.add(r)
	return nil
}
func (s *testStewardStore) UpdateHeartbeat(_ context.Context, _ string) error { return nil }
func (s *testStewardStore) GetSteward(_ context.Context, id string) (*business.StewardRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return nil, business.ErrStewardNotFound
	}
	cp := *r
	return &cp, nil
}
func (s *testStewardStore) GetStewardByDeviceID(_ context.Context, deviceID string) (*business.StewardRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byDevice[deviceID]
	if !ok {
		return nil, business.ErrStewardNotFound
	}
	cp := *r
	return &cp, nil
}
func (s *testStewardStore) ListStewards(_ context.Context) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (s *testStewardStore) ListStewardsByStatus(_ context.Context, _ business.StewardStatus) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (s *testStewardStore) UpdateStewardStatus(_ context.Context, id string, status business.StewardStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.records[id]; ok {
		r.Status = status
	}
	return nil
}
func (s *testStewardStore) DeregisterSteward(_ context.Context, _ string) error { return nil }
func (s *testStewardStore) GetStewardsSeen(_ context.Context, _ time.Time) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (s *testStewardStore) HealthCheck(_ context.Context) error { return nil }
func (s *testStewardStore) Initialize(_ context.Context) error  { return nil }
func (s *testStewardStore) Close() error                        { return nil }

// testPendingRefreshStore is a thread-safe in-memory PendingRefreshStore.
type testPendingRefreshStore struct {
	mu      sync.RWMutex
	entries map[string]*business.PendingRefreshEntry
}

func newTestPendingRefreshStore() *testPendingRefreshStore {
	return &testPendingRefreshStore{entries: make(map[string]*business.PendingRefreshEntry)}
}

func (s *testPendingRefreshStore) AddPendingRefresh(_ context.Context, e *business.PendingRefreshEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *e
	s.entries[e.PendingID] = &cp
	return nil
}
func (s *testPendingRefreshStore) GetPendingRefreshByID(_ context.Context, id string) (*business.PendingRefreshEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, business.ErrPendingRefreshNotFound
	}
	cp := *e
	return &cp, nil
}
func (s *testPendingRefreshStore) UpdateRefreshStatus(_ context.Context, id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		e.Status = status
	}
	return nil
}
func (s *testPendingRefreshStore) ListPendingRefresh(_ context.Context, tenantID string) ([]*business.PendingRefreshEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*business.PendingRefreshEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if tenantID == "" || e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (s *testPendingRefreshStore) ExpireStaleRefresh(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}
func (s *testPendingRefreshStore) StoreClaimBundle(_ context.Context, id string, bundle []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		e.ClaimBundle = bundle
	}
	return nil
}
func (s *testPendingRefreshStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// testRefreshPolicyStore is a thread-safe in-memory RefreshPolicyStore.
type testRefreshPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*business.RefreshPolicy
}

func newTestRefreshPolicyStore() *testRefreshPolicyStore {
	return &testRefreshPolicyStore{policies: make(map[string]*business.RefreshPolicy)}
}

func (s *testRefreshPolicyStore) GetPolicy(_ context.Context, tenantID string) (*business.RefreshPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.policies[tenantID]; ok {
		cp := *p
		return &cp, nil
	}
	// Default per ADR-010 §4.
	return &business.RefreshPolicy{TenantID: tenantID, Mode: "require_approval"}, nil
}

func (s *testRefreshPolicyStore) SetPolicy(_ context.Context, p *business.RefreshPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *p
	s.policies[p.TenantID] = &cp
	return nil
}

// neverCallPolicyStore panics if GetPolicy is called — used to assert policy is not consulted.
type neverCallPolicyStore struct{}

func (neverCallPolicyStore) GetPolicy(_ context.Context, _ string) (*business.RefreshPolicy, error) {
	panic("GetPolicy must not be called for archived stewards")
}
func (neverCallPolicyStore) SetPolicy(_ context.Context, _ *business.RefreshPolicy) error {
	panic("SetPolicy must not be called")
}

// recordingPoPVerifier counts Verify calls and delegates to an optional func.
type recordingPoPVerifier struct {
	mu    sync.Mutex
	calls int
	fn    func(pub ed25519.PublicKey, msg, sig []byte) bool
}

func (v *recordingPoPVerifier) Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	v.mu.Lock()
	v.calls++
	v.mu.Unlock()
	if v.fn != nil {
		return v.fn(pub, msg, sig)
	}
	return false
}

func (v *recordingPoPVerifier) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

// ---- Server factory for refresh handler tests --------------------------------

// newRefreshTestServer builds a minimal Server with real audit + steward infrastructure
// wired for the registration-refresh handler tests.
func newRefreshTestServer(
	t *testing.T,
	stewardSt *testStewardStore,
	pendingRefreshSt *testPendingRefreshStore,
	policyStore business.RefreshPolicyStore,
) (*Server, *audit.Manager) {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

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
		nil, tenantManager, rbacManager,
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

	server.SetStewardStore(stewardSt)
	if pendingRefreshSt != nil {
		server.SetPendingRefreshStore(pendingRefreshSt)
	}
	if policyStore != nil {
		server.SetRefreshPolicyStore(policyStore)
	}

	return server, auditMgr
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
	ss := newTestStewardStore()
	server, _ := newRefreshTestServer(t, ss, nil, nil)

	body, _ := json.Marshal(RefreshChallengeRequest{TenantID: testTenantID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/unknowndevice/refresh/challenge", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"device_id": "unknowndevice"})
	rec := httptest.NewRecorder()
	server.handleRefreshChallenge(rec, r)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRefreshChallenge_KnownActiveDevice(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-1",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})
	server, _ := newRefreshTestServer(t, ss, nil, nil)

	resp := issueChallenge(t, server, testDeviceID, testTenantID)
	assert.NotEmpty(t, resp.Nonce)
	assert.NotZero(t, resp.ServerTS)
	// Nonce must decode to 32 bytes.
	raw, err := base64.RawURLEncoding.DecodeString(resp.Nonce)
	require.NoError(t, err)
	assert.Len(t, raw, 32)
}

func TestHandleRefreshChallenge_RevokedDeviceReturns403(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-rev",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusRevoked,
		IdentityKeyPub: []byte(pub),
	})
	server, _ := newRefreshTestServer(t, ss, nil, nil)

	body, _ := json.Marshal(RefreshChallengeRequest{TenantID: testTenantID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+testDeviceID+"/refresh/challenge", bytes.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"device_id": testDeviceID})
	rec := httptest.NewRecorder()
	server.handleRefreshChallenge(rec, r)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	// Verify no nonce was placed in cache.
	_, found := server.nonceCache.Get(nonceCacheKeyPrefix + testDeviceID)
	assert.False(t, found, "no nonce must be stored for revoked device")
}

// ---- Complete endpoint tests ------------------------------------------------

func TestHandleRefreshComplete_RevokedBeforePoP(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-rev",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusRevoked,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	server, _ := newRefreshTestServer(t, ss, prs, newTestRefreshPolicyStore())

	verifier := &recordingPoPVerifier{}
	server.SetPoPVerifier(verifier)

	// Manually plant a nonce to rule out the "no nonce" 401 path.
	server.nonceCache.Set(nonceCacheKeyPrefix+testDeviceID, &nonceEntry{ //nolint:errcheck // in-memory cache; Set only fails on empty key, which is impossible here
		NonceBytes: make([]byte, 32),
		ServerTS:   uint64(time.Now().UnixNano()),
		IssuedAt:   time.Now(),
	}, nonceTTL)

	rec := postComplete(server, testDeviceID, RefreshCompleteRequest{
		TenantID:  testTenantID,
		Nonce:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IssuedAt:  time.Now().UnixNano(),
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	})

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 0, verifier.callCount(), "PoPVerifier must not be called for revoked device")
}

func TestHandleRefreshComplete_NonceReplay(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	ps := newTestRefreshPolicyStore()
	server, _ := newRefreshTestServer(t, ss, prs, ps)
	// Use real ed25519.Verify so the first request can succeed (queued for require_approval).
	server.SetPoPVerifier(ed25519PoPVerifier{})

	challenge := issueChallenge(t, server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	// First attempt: nonce consumed, status 202 (require_approval default).
	rec1 := postComplete(server, testDeviceID, req)
	assert.Equal(t, http.StatusAccepted, rec1.Code, "first complete must succeed: %s", rec1.Body.String())

	// Second attempt with same nonce: nonce was consumed, must get 401.
	rec2 := postComplete(server, testDeviceID, req)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code, "nonce replay must be rejected")
}

func TestHandleRefreshComplete_ExpiredNonce(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	server, _ := newRefreshTestServer(t, ss, prs, newTestRefreshPolicyStore())
	server.SetPoPVerifier(ed25519PoPVerifier{})

	challenge := issueChallenge(t, server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)
	// Override IssuedAt to simulate a 61-second-old nonce.
	req.IssuedAt = time.Now().Add(-61 * time.Second).UnixNano()

	rec := postComplete(server, testDeviceID, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "expired")
}

func TestHandleRefreshComplete_InvalidPoP(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	_, wrongPriv := newTestEd25519KeyPair(t) // different key pair
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	server, _ := newRefreshTestServer(t, ss, prs, newTestRefreshPolicyStore())
	server.SetPoPVerifier(ed25519PoPVerifier{})

	challenge := issueChallenge(t, server, testDeviceID, testTenantID)
	// Sign with a DIFFERENT private key — PoP must fail.
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, wrongPriv, nil)

	rec := postComplete(server, testDeviceID, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleRefreshComplete_Lifecycle_Archived(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-archived",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusArchived,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	server, _ := newRefreshTestServer(t, ss, prs, neverCallPolicyStore{})
	server.SetPoPVerifier(ed25519PoPVerifier{})

	challenge := issueChallenge(t, server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	rec := postComplete(server, testDeviceID, req)
	assert.Equal(t, http.StatusAccepted, rec.Code, "archived steward must be queued: %s", rec.Body.String())

	// Verify pending entry was created.
	assert.Equal(t, 1, prs.count(), "one pending refresh entry must be created")

	// Verify response body.
	var resp RefreshCompleteResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "queued", resp.Status)
	assert.NotEmpty(t, resp.PendingID)
}

func TestHandleRefreshComplete_CrossTenantReturns403(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-a",
		DeviceID:       testDeviceID,
		TenantID:       "tenant-a",
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	server, _ := newRefreshTestServer(t, ss, prs, newTestRefreshPolicyStore())
	server.SetPoPVerifier(ed25519PoPVerifier{})

	// Manually plant a nonce so we reach the cross-tenant gate.
	server.nonceCache.Set(nonceCacheKeyPrefix+testDeviceID, &nonceEntry{ //nolint:errcheck // in-memory cache; Set only fails on empty key, which is impossible here
		NonceBytes: make([]byte, 32),
		ServerTS:   uint64(time.Now().UnixNano()),
		IssuedAt:   time.Now(),
	}, nonceTTL)

	// Request from "tenant-b" for a steward that belongs to "tenant-a".
	rec := postComplete(server, testDeviceID, RefreshCompleteRequest{
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
		setup    func(t *testing.T, ss *testStewardStore, server *Server) RefreshCompleteRequest
		wantCode int
		wantAct  string
	}{
		{
			name: "revoked device",
			setup: func(t *testing.T, ss *testStewardStore, server *Server) RefreshCompleteRequest {
				ss.add(&business.StewardRecord{
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
			setup: func(t *testing.T, ss *testStewardStore, server *Server) RefreshCompleteRequest {
				ss.add(&business.StewardRecord{
					ID:             "s-active",
					DeviceID:       testDeviceID,
					TenantID:       testTenantID,
					Status:         business.StewardStatusActive,
					IdentityKeyPub: []byte(pub),
				})
				server.SetPoPVerifier(ed25519PoPVerifier{})
				ch := issueChallenge(t, server, testDeviceID, testTenantID)
				return buildValidCompleteRequest(t, testDeviceID, testTenantID, ch, priv, nil)
			},
			wantCode: http.StatusAccepted,
			wantAct:  "refresh_queued",
		},
	}

	for _, tc := range outcomes {
		t.Run(tc.name, func(t *testing.T) {
			ss := newTestStewardStore()
			prs := newTestPendingRefreshStore()
			server, auditMgr := newRefreshTestServer(t, ss, prs, newTestRefreshPolicyStore())

			req := tc.setup(t, ss, server)
			rec := postComplete(server, testDeviceID, req)
			assert.Equal(t, tc.wantCode, rec.Code)

			require.NoError(t, auditMgr.Flush(context.Background()))
			entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{})
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(entries), 1, "at least one audit event expected")

			found := false
			for _, e := range entries {
				if e.Action == tc.wantAct {
					assert.NotEmpty(t, e.Details["device_id"], "device_id in audit")
					assert.NotEmpty(t, e.Details["tenant_id"], "tenant_id in audit")
					found = true
					break
				}
			}
			assert.True(t, found, "expected audit action %q not found in %v", tc.wantAct, entries)
		})
	}
}

func TestProvenance_CannotUngateRevoked(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "s-rev",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusRevoked,
		IdentityKeyPub: []byte(pub),
		// Perfect provenance — revocation must still win.
		LastProvenanceJSON: `{"hostname":"host1","mac_address":"aa:bb"}`,
	})

	prs := newTestPendingRefreshStore()
	server, _ := newRefreshTestServer(t, ss, prs, newTestRefreshPolicyStore())
	verifier := &recordingPoPVerifier{}
	server.SetPoPVerifier(verifier)

	// Plant a nonce so we reach the revocation gate.
	server.nonceCache.Set(nonceCacheKeyPrefix+testDeviceID, &nonceEntry{ //nolint:errcheck // in-memory cache; Set only fails on empty key, which is impossible here
		NonceBytes: make([]byte, 32),
		ServerTS:   uint64(time.Now().UnixNano()),
		IssuedAt:   time.Now(),
	}, nonceTTL)

	rec := postComplete(server, testDeviceID, RefreshCompleteRequest{
		TenantID:   testTenantID,
		Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IssuedAt:   time.Now().UnixNano(),
		Signature:  base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		Provenance: map[string]string{"hostname": "host1", "mac_address": "aa:bb"},
	})

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 0, verifier.callCount(), "PoP must not be called for revoked device")
}

// ---- Admin handler tests ----------------------------------------------------

// newRefreshAdminTestServer builds a Server with a cert manager for admin handler tests.
func newRefreshAdminTestServer(
	t *testing.T,
	stewardSt *testStewardStore,
	pendingRefreshSt *testPendingRefreshStore,
	policyStore business.RefreshPolicyStore,
) (*Server, *audit.Manager) {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

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

	certMgr := newTestCertManager(t)

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

	server.SetStewardStore(stewardSt)
	if pendingRefreshSt != nil {
		server.SetPendingRefreshStore(pendingRefreshSt)
	}
	if policyStore != nil {
		server.SetRefreshPolicyStore(policyStore)
	}

	return server, auditMgr
}

func TestHandleRefreshApprove_Unauthenticated(t *testing.T) {
	server := setupTestServer(t)
	server.SetStewardStore(newTestStewardStore())
	server.SetPendingRefreshStore(newTestPendingRefreshStore())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/some-pending-id/approve", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleRefreshApprove_ApprovesEntry(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-approve",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	pendingID := "refresh-approve-test"
	require.NoError(t, prs.AddPendingRefresh(context.Background(), &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}))

	server, auditMgr := newRefreshAdminTestServer(t, ss, prs, newTestRefreshPolicyStore())
	apiKey := NewTestKey(t, server, []string{"refresh:approve"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/approve", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "approve must succeed: %s", rec.Body.String())

	var resp AdminRefreshApproveResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "approved", resp.Status)
	assert.Equal(t, pendingID, resp.PendingID)
	assert.NotEmpty(t, resp.ClientCert, "client cert must be in response")
	assert.NotEmpty(t, resp.ClientKey, "client key must be in response")
	assert.NotEmpty(t, resp.CACert, "CA cert must be in response")

	// Verify the store was updated.
	updated, err := prs.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusApproved, updated.Status)
	assert.NotNil(t, updated.ClaimBundle, "claim bundle must be stored")

	// Verify audit event was emitted.
	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	found := false
	for _, e := range entries {
		if e.Action == "refresh_admin_approved" {
			assert.NotEmpty(t, e.Details["device_id"], "device_id in audit")
			assert.NotEmpty(t, e.Details["tenant_id"], "tenant_id in audit")
			assert.Equal(t, "approved", e.Details["decision"])
			found = true
			break
		}
	}
	assert.True(t, found, "refresh_admin_approved audit event expected")
}

func TestHandleRefreshReject_RejectsEntry(t *testing.T) {
	pub, _ := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "steward-reject",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	pendingID := "refresh-reject-test"
	require.NoError(t, prs.AddPendingRefresh(context.Background(), &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}))

	server, auditMgr := newRefreshAdminTestServer(t, ss, prs, newTestRefreshPolicyStore())
	apiKey := NewTestKey(t, server, []string{"refresh:reject"})

	body, _ := json.Marshal(AdminRefreshRejectRequest{Reason: "unauthorized device"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/reject", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "reject must succeed: %s", rec.Body.String())

	updated, err := prs.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusRejected, updated.Status)

	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	found := false
	for _, e := range entries {
		if e.Action == "refresh_admin_rejected" {
			assert.Equal(t, "rejected", e.Details["decision"])
			found = true
			break
		}
	}
	assert.True(t, found, "refresh_admin_rejected audit event expected")
}

func TestHandleListPendingRefreshes_ReturnsList(t *testing.T) {
	ss := newTestStewardStore()
	prs := newTestPendingRefreshStore()
	require.NoError(t, prs.AddPendingRefresh(context.Background(), &business.PendingRefreshEntry{
		PendingID: "refresh-list-1",
		DeviceID:  testDeviceID,
		TenantID:  testTenantID,
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}))

	server, _ := newRefreshAdminTestServer(t, ss, prs, newTestRefreshPolicyStore())
	apiKey := NewTestKey(t, server, []string{"refresh:list-pending"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/refresh/pending", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var entries []APIPendingRefreshEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	assert.Len(t, entries, 1)
	assert.Equal(t, "refresh-list-1", entries[0].PendingID)
}

func TestHandleGetRefreshPolicy_ReturnsDefault(t *testing.T) {
	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), nil, newTestRefreshPolicyStore())
	server.SetRefreshPolicyStore(newTestRefreshPolicyStore())
	apiKey := NewTestKey(t, server, []string{"refresh:get-policy"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+testTenantID+"/refresh-policy", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "get-policy must succeed: %s", rec.Body.String())
	var policy AdminRefreshPolicyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &policy))
	assert.Equal(t, testTenantID, policy.TenantID)
	assert.Equal(t, "require_approval", policy.Mode)
}

func TestHandleSetRefreshPolicy_SetsMode(t *testing.T) {
	ps := newTestRefreshPolicyStore()
	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), nil, ps)
	apiKey := NewTestKey(t, server, []string{"refresh:set-policy"})

	body, _ := json.Marshal(AdminRefreshPolicyRequest{Mode: "auto_accept"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+testTenantID+"/refresh-policy", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "set-policy must succeed: %s", rec.Body.String())

	policy, err := ps.GetPolicy(context.Background(), testTenantID)
	require.NoError(t, err)
	assert.Equal(t, "auto_accept", policy.Mode)
}

func TestHandleSetRefreshPolicy_InvalidMode_Returns400(t *testing.T) {
	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), nil, newTestRefreshPolicyStore())
	apiKey := NewTestKey(t, server, []string{"refresh:set-policy"})

	body, _ := json.Marshal(AdminRefreshPolicyRequest{Mode: "invalid_mode"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+testTenantID+"/refresh-policy", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleRefreshApprove_NotFound(t *testing.T) {
	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), newTestPendingRefreshStore(), nil)
	apiKey := NewTestKey(t, server, []string{"refresh:approve"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/nonexistent-id/approve", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRefreshReject_Unauthenticated(t *testing.T) {
	server := setupTestServer(t)
	server.SetStewardStore(newTestStewardStore())
	server.SetPendingRefreshStore(newTestPendingRefreshStore())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/some-id/reject", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ---- Cross-tenant isolation tests for admin handlers -------------------------

func TestHandleApproveRefresh_CrossTenantReturns404(t *testing.T) {
	prs := newTestPendingRefreshStore()
	pendingID := "refresh-cross-approve"
	require.NoError(t, prs.AddPendingRefresh(context.Background(), &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID, // belongs to "test-tenant"
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}))

	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), prs, nil)
	// API key scoped to a different tenant.
	apiKey := NewEphemeralTestKey(t, server, []string{"refresh:approve"}, "other-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/approve", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// 404 rather than 403 to avoid disclosing pending-refresh existence across tenants.
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Entry must remain pending — nothing was mutated.
	entry, err := prs.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, entry.Status)
}

func TestHandleRejectRefresh_CrossTenantReturns404(t *testing.T) {
	prs := newTestPendingRefreshStore()
	pendingID := "refresh-cross-reject"
	require.NoError(t, prs.AddPendingRefresh(context.Background(), &business.PendingRefreshEntry{
		PendingID: pendingID,
		DeviceID:  testDeviceID,
		TenantID:  testTenantID, // belongs to "test-tenant"
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}))

	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), prs, nil)
	// API key scoped to a different tenant.
	apiKey := NewEphemeralTestKey(t, server, []string{"refresh:reject"}, "other-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/refresh/"+pendingID+"/reject", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Entry must remain pending — nothing was mutated.
	entry, err := prs.GetPendingRefreshByID(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, entry.Status)
}

func TestHandleListPendingRefreshes_ScopedCallerSeesOnlyOwnTenant(t *testing.T) {
	prs := newTestPendingRefreshStore()
	require.NoError(t, prs.AddPendingRefresh(context.Background(), &business.PendingRefreshEntry{
		PendingID: "refresh-own-tenant",
		DeviceID:  testDeviceID,
		TenantID:  testTenantID, // caller's own tenant
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}))
	require.NoError(t, prs.AddPendingRefresh(context.Background(), &business.PendingRefreshEntry{
		PendingID: "refresh-other-tenant",
		DeviceID:  "bbbbbbbbbbbbbbbb",
		TenantID:  "other-tenant", // another tenant's entry
		Status:    business.PendingRefreshStatusPending,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}))

	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), prs, newTestRefreshPolicyStore())
	// Key scoped to testTenantID — must only see its own entries regardless of query param.
	apiKey := NewTestKey(t, server, []string{"refresh:list-pending"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/refresh/pending", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var entries []APIPendingRefreshEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	require.Len(t, entries, 1, "scoped caller must only see own-tenant entries")
	assert.Equal(t, testTenantID, entries[0].TenantID)
	assert.Equal(t, "refresh-own-tenant", entries[0].PendingID)
}

func TestHandleGetRefreshPolicy_CrossTenantReturns404(t *testing.T) {
	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), nil, newTestRefreshPolicyStore())
	// Key scoped to "other-tenant" — must not read policy for testTenantID.
	apiKey := NewEphemeralTestKey(t, server, []string{"refresh:get-policy"}, "other-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+testTenantID+"/refresh-policy", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleSetRefreshPolicy_CrossTenantReturns404(t *testing.T) {
	ps := newTestRefreshPolicyStore()
	server, _ := newRefreshAdminTestServer(t, newTestStewardStore(), nil, ps)
	// Key scoped to "other-tenant" — must not write policy for testTenantID.
	apiKey := NewEphemeralTestKey(t, server, []string{"refresh:set-policy"}, "other-tenant", 5*time.Minute)

	body, _ := json.Marshal(AdminRefreshPolicyRequest{Mode: "reject"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+testTenantID+"/refresh-policy", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Policy for testTenantID must remain at default — nothing mutated.
	policy, err := ps.GetPolicy(context.Background(), testTenantID)
	require.NoError(t, err)
	assert.Equal(t, "require_approval", policy.Mode)
}

func TestRefresh_NoPolicyDefault(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:             "s-active",
		DeviceID:       testDeviceID,
		TenantID:       testTenantID,
		Status:         business.StewardStatusActive,
		IdentityKeyPub: []byte(pub),
	})

	prs := newTestPendingRefreshStore()
	// Policy store returns default (require_approval) — no policy set for this tenant.
	server, _ := newRefreshTestServer(t, ss, prs, newTestRefreshPolicyStore())
	server.SetPoPVerifier(ed25519PoPVerifier{})

	challenge := issueChallenge(t, server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	rec := postComplete(server, testDeviceID, req)
	assert.Equal(t, http.StatusAccepted, rec.Code, "default policy must queue: %s", rec.Body.String())
	assert.Equal(t, 1, prs.count(), "one pending entry must be created")
}

// TestRefresh_AutoAccept_NoProvenanceBaseline verifies that auto_accept policy issues a
// cert immediately when the steward has no stored provenance (LastProvenanceJSON == "").
// Initial registration never stores provenance, so the first refresh must not be demoted
// to require_approval by a score-of-zero comparison against an absent baseline.
func TestRefresh_AutoAccept_NoProvenanceBaseline(t *testing.T) {
	pub, priv := newTestEd25519KeyPair(t)
	ss := newTestStewardStore()
	ss.add(&business.StewardRecord{
		ID:                 "s-active",
		DeviceID:           testDeviceID,
		TenantID:           testTenantID,
		Status:             business.StewardStatusActive,
		IdentityKeyPub:     []byte(pub),
		LastProvenanceJSON: "", // no baseline — first refresh after registration
	})

	prs := newTestPendingRefreshStore()
	ps := newTestRefreshPolicyStore()
	require.NoError(t, ps.SetPolicy(context.Background(), &business.RefreshPolicy{
		TenantID: testTenantID,
		Mode:     "auto_accept",
	}))

	server, _ := newRefreshAdminTestServer(t, ss, prs, ps)
	server.SetPoPVerifier(ed25519PoPVerifier{})

	challenge := issueChallenge(t, server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, priv, nil)

	rec := postComplete(server, testDeviceID, req)
	assert.Equal(t, http.StatusOK, rec.Code, "auto_accept with no provenance baseline must issue cert immediately: %s", rec.Body.String())
	assert.Equal(t, 0, prs.count(), "no pending entry must be created for auto_accept with no baseline")

	var resp RefreshCompleteResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "approved", resp.Status)
	assert.NotEmpty(t, resp.ClientCert)
	assert.NotEmpty(t, resp.ClientKey)
	assert.NotEmpty(t, resp.CACert)
}
