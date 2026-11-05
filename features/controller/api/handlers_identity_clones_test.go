// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	cloneTenant      = "tenant-clone-a"
	cloneOtherTenant = "tenant-clone-b"
	cloneDeviceA     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cloneDeviceB     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type cloneEnv struct {
	server    *Server
	steward   business.StewardStore
	certMgr   *cert.Manager
	tokenSt   registration.Store
	regToken  string
	deviceKey ed25519.PublicKey
}

// newCloneEnv builds a server with real audit, steward, pending and cert stores,
// and a registration token for cloneTenant.
func newCloneEnv(t *testing.T) *cloneEnv {
	t.Helper()
	tokenStore := newTestRegistrationStore(t)
	certMgr := newTestCertManager(t)
	server, stewardSt := newHandleRegisterServerWithStewardStore(t, tokenStore, certMgr)
	const regToken = "cfgms_reg_clone_env"
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token: regToken, TenantID: cloneTenant, ControllerURL: "grpc://controller:7443",
	}))
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &cloneEnv{server: server, steward: stewardSt, certMgr: certMgr, tokenSt: tokenStore, regToken: regToken, deviceKey: pub}
}

func (e *cloneEnv) addSteward(t *testing.T, id, tenantID, deviceID string, status business.StewardStatus) {
	t.Helper()
	require.NoError(t, e.steward.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: id, TenantID: tenantID, Status: status, DeviceID: deviceID,
		IdentityKeyPub: []byte("old-key-material-of-the-original"), KeyProtectionLevel: "file",
		LastProvenanceJSON: `{"hostname":"orig"}`,
	}))
}

func (e *cloneEnv) addPending(t *testing.T, pendingID, tenantID, cloneOf, deviceID string) *business.PendingRegistrationEntry {
	t.Helper()
	entry := &business.PendingRegistrationEntry{
		PendingID: pendingID, StewardID: "steward-queued-" + pendingID, TenantID: tenantID,
		TokenStr: e.regToken, SourceIP: "10.1.2.3", RegisteredAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour), Status: business.PendingRegistrationStatusPending,
		DeviceID: deviceID, IdentityKeyPub: []byte(e.deviceKey), KeyProtectionLevel: "tpm", KeyAlgorithm: "ecdsa-p256",
		CSRPEM: testValidCSRPEM, Hostname: "queued-host", Platform: "linux", CloneOf: cloneOf,
	}
	require.NoError(t, e.server.pendingStore.AddPending(context.Background(), entry))
	return entry
}

func (e *cloneEnv) issueClientCerts(t *testing.T, stewardID string, n int) []string {
	t.Helper()
	serials := make([]string, 0, n)
	for i := 0; i < n; i++ {
		c, err := e.certMgr.GenerateClientCertificate(&cert.ClientCertConfig{CommonName: stewardID, ValidityDays: 1})
		require.NoError(t, err)
		serials = append(serials, c.SerialNumber)
	}
	return serials
}

func (e *cloneEnv) recordConflict(t *testing.T, stewardID, tenantID string) {
	t.Helper()
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSecurityEvent).
		Action(auditActionIdentityConflictDetected).
		User(stewardID, business.AuditUserTypeSystem).
		Resource("steward", stewardID, "").
		Result(business.AuditResultFailure).
		Severity(business.AuditSeverityHigh).
		Detail("steward_id", stewardID).
		Detail("existing_addr", "192.0.2.10:5000").
		Detail("new_addr", "192.0.2.20:6000").
		Detail("existing_serial", "111").
		Detail("new_serial", "222").
		Detail("provenance_divergent_keys", []string{"hostname", "machine_id"})
	require.NoError(t, e.server.auditManager.RecordEvent(context.Background(), b))
	require.NoError(t, e.server.auditManager.Flush(context.Background()))
}

func (e *cloneEnv) auditActions(t *testing.T, action string) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, e.server.auditManager.Flush(context.Background()))
	entries, err := e.server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{Actions: []string{action}})
	require.NoError(t, err)
	return entries
}

func callClone(handler http.HandlerFunc, method, path string, vars map[string]string, callerTenant string, body interface{}) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req = withPrincipal(req, &Principal{ID: "operator", Assurance: session.AssuranceStrong, TenantID: callerTenant})
	if vars != nil {
		req = withVars(req, vars)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decodeCloneData(t *testing.T, rec *httptest.ResponseRecorder, into interface{}) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	require.NoError(t, json.Unmarshal(env.Data, into), rec.Body.String())
}

func TestListIdentityClones_ReturnsEvidenceAndQueuedCopy(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-listed", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	env.recordConflict(t, "steward-listed", cloneTenant)
	env.addPending(t, "pending-listed", cloneTenant, "steward-listed", cloneDeviceB)
	env.addPending(t, "pending-plain", cloneTenant, "", cloneDeviceB[:63]+"c") // not a clone: must not appear

	rec := callClone(env.server.handleListIdentityClones, http.MethodGet, "/api/v1/stewards/identity-clones", nil, cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp identityCloneListResponse
	decodeCloneData(t, rec, &resp)
	require.Len(t, resp.Clones, 1)
	c := resp.Clones[0]
	assert.Equal(t, "steward-listed", c.StewardID)
	assert.Equal(t, 1, c.DetectionCount)
	assert.NotNil(t, c.FirstDetected)
	assert.NotNil(t, c.LastDetected)
	assert.Equal(t, "192.0.2.10:5000", c.ExistingPeer)
	assert.Equal(t, "192.0.2.20:6000", c.OtherPeer)
	assert.Equal(t, []string{"111", "222"}, c.Serials)
	assert.Equal(t, []string{"hostname", "machine_id"}, c.DivergentFields)
	require.Len(t, c.QueuedCopies, 1)
	assert.Equal(t, "pending-listed", c.QueuedCopies[0].PendingID)
	assert.Equal(t, "queued-host", c.QueuedCopies[0].Hostname)
	assert.Equal(t, "10.1.2.3", c.QueuedCopies[0].SourceIP)

	// A caller from another tenant sees neither the evidence nor the queued copy.
	rec = callClone(env.server.handleListIdentityClones, http.MethodGet, "/api/v1/stewards/identity-clones", nil, cloneOtherTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp = identityCloneListResponse{}
	decodeCloneData(t, rec, &resp)
	assert.Empty(t, resp.Clones)
	assert.NotContains(t, rec.Body.String(), "pending-listed")
	assert.NotContains(t, rec.Body.String(), "192.0.2.10")
}

func TestListIdentityClones_QueuedCopyWithoutEvidence(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-quiet", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	env.addPending(t, "pending-quiet", cloneTenant, "steward-quiet", cloneDeviceB)

	rec := callClone(env.server.handleListIdentityClones, http.MethodGet, "/", nil, cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp identityCloneListResponse
	decodeCloneData(t, rec, &resp)
	require.Len(t, resp.Clones, 1)
	assert.Equal(t, 0, resp.Clones[0].DetectionCount)
	require.Len(t, resp.Clones[0].QueuedCopies, 1)
}

// The literal list segment must not be taken by the /stewards/{id} wildcard.
func TestIdentityCloneRoutes_ListNotShadowedByStewardID(t *testing.T) {
	env := newCloneEnv(t)
	apiKey := NewTestKey(t, env.server, []string{"steward:read"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/identity-clones", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	env.server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"clones"`)
}

func TestRotateCredentials_RevokesSerialsAndArchives(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-rot", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	serials := env.issueClientCerts(t, "steward-rot", 2)
	bystander := env.issueClientCerts(t, "steward-bystander", 1)

	rec := callClone(env.server.handleRotateCredentials, http.MethodPost, "/", map[string]string{"id": "steward-rot"}, cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp rotateCredentialsResponse
	decodeCloneData(t, rec, &resp)
	assert.ElementsMatch(t, serials, resp.RevokedSerials)
	assert.Contains(t, resp.NextStep, "cfg refresh approve")

	for _, s := range serials {
		revoked, err := env.certMgr.IsRevoked(s)
		require.NoError(t, err)
		assert.True(t, revoked, "serial %s must be revoked", s)
	}
	revoked, err := env.certMgr.IsRevoked(bystander[0])
	require.NoError(t, err)
	assert.False(t, revoked, "another steward's certificate must not be touched")

	rec2, err := env.steward.GetSteward(context.Background(), "steward-rot")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusArchived, rec2.Status)

	events := env.auditActions(t, auditActionCredentialsRotated)
	require.Len(t, events, 1)
	assert.Equal(t, business.AuditSeverityHigh, events[0].Severity)
	assert.Equal(t, business.AuditEventSecurityEvent, events[0].EventType)
	assert.Equal(t, "steward-rot", events[0].ResourceID)
}

func TestRotateCredentials_OtherTenantAndUnknownRefused(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-rot-x", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	serials := env.issueClientCerts(t, "steward-rot-x", 1)

	rec := callClone(env.server.handleRotateCredentials, http.MethodPost, "/", map[string]string{"id": "steward-rot-x"}, cloneOtherTenant, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	revoked, err := env.certMgr.IsRevoked(serials[0])
	require.NoError(t, err)
	assert.False(t, revoked)
	got, _ := env.steward.GetSteward(context.Background(), "steward-rot-x")
	assert.Equal(t, business.StewardStatusActive, got.Status)

	rec = callClone(env.server.handleRotateCredentials, http.MethodPost, "/", map[string]string{"id": "nobody"}, cloneTenant, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = callClone(env.server.handleRotateCredentials, http.MethodPost, "/", map[string]string{"id": "bad.id"}, cloneTenant, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRotateCredentials_RevokedStewardConflict(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-rot-rv", cloneTenant, cloneDeviceA, business.StewardStatusRevoked)
	rec := callClone(env.server.handleRotateCredentials, http.MethodPost, "/", map[string]string{"id": "steward-rot-rv"}, cloneTenant, nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestMoveIdentity_RebindsRecordAndClaimsUnderOriginalID(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-mv", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	oldSerials := env.issueClientCerts(t, "steward-mv", 2)
	env.addPending(t, "pending-mv", cloneTenant, "steward-mv", cloneDeviceB)

	rec := callClone(env.server.handleMoveIdentity, http.MethodPost, "/", map[string]string{"id": "steward-mv"},
		cloneTenant, map[string]string{"pending_id": "pending-mv"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp moveIdentityResponse
	decodeCloneData(t, rec, &resp)
	assert.ElementsMatch(t, oldSerials, resp.RevokedSerials)

	// The record now describes the queued machine and will re-baseline.
	got, err := env.steward.GetSteward(context.Background(), "steward-mv")
	require.NoError(t, err)
	assert.Equal(t, cloneDeviceB, got.DeviceID)
	assert.Equal(t, []byte(env.deviceKey), got.IdentityKeyPub)
	assert.Equal(t, "tpm", got.KeyProtectionLevel)
	assert.Equal(t, "ecdsa-p256", got.KeyAlgorithm, "the move must carry the key algorithm")
	assert.Empty(t, got.LastProvenanceJSON)

	// The queued entry is approved under the original steward ID.
	entry, err := env.server.pendingStore.GetPendingByID(context.Background(), "pending-mv")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusApproved, entry.Status)
	assert.Equal(t, "steward-mv", entry.StewardID)

	// The ordinary claim signs the certificate with the original ID as CN.
	claimed, err := env.server.buildClaimResponse(context.Background(), entry, env.regToken)
	require.NoError(t, err)
	assert.Equal(t, "steward-mv", claimed.StewardID)
	block, _ := pem.Decode([]byte(claimed.ClientCert))
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "steward-mv", leaf.Subject.CommonName)

	after, err := env.steward.GetSteward(context.Background(), "steward-mv")
	require.NoError(t, err)
	assert.Equal(t, "steward-mv", after.ID)
	assert.Equal(t, cloneDeviceB, after.DeviceID)

	for _, s := range oldSerials {
		revoked, err := env.certMgr.IsRevoked(s)
		require.NoError(t, err)
		assert.True(t, revoked)
	}
	newSerial := leaf.SerialNumber.String()
	revoked, err := env.certMgr.IsRevoked(newSerial)
	require.NoError(t, err)
	assert.False(t, revoked, "the certificate issued at claim must not be revoked")

	events := env.auditActions(t, auditActionIdentityMoved)
	require.Len(t, events, 1)
	assert.Equal(t, business.AuditSeverityHigh, events[0].Severity)
	assert.Equal(t, business.AuditEventSecurityEvent, events[0].EventType)
}

func TestMoveIdentity_RejectsPendingFromOtherTenantOrWithoutCloneOf(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-mv-rej", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	env.addSteward(t, "steward-mv-other", cloneTenant, cloneDeviceA[:63]+"d", business.StewardStatusActive)
	env.addPending(t, "pending-other-tenant", cloneOtherTenant, "steward-mv-rej", cloneDeviceB)
	env.addPending(t, "pending-no-cloneof", cloneTenant, "", cloneDeviceB[:63]+"e")
	env.addPending(t, "pending-wrong-steward", cloneTenant, "steward-mv-other", cloneDeviceB[:63]+"f")
	approved := env.addPending(t, "pending-approved", cloneTenant, "steward-mv-rej", cloneDeviceB[:63]+"9")
	require.NoError(t, env.server.pendingStore.UpdateStatus(context.Background(), approved.PendingID, business.PendingRegistrationStatusApproved))

	for pendingID, want := range map[string]int{
		"pending-other-tenant":  http.StatusNotFound,
		"pending-no-cloneof":    http.StatusNotFound,
		"pending-wrong-steward": http.StatusNotFound,
		"pending-missing":       http.StatusNotFound,
		"pending-approved":      http.StatusConflict,
		"":                      http.StatusBadRequest,
	} {
		rec := callClone(env.server.handleMoveIdentity, http.MethodPost, "/", map[string]string{"id": "steward-mv-rej"},
			cloneTenant, map[string]string{"pending_id": pendingID})
		assert.Equal(t, want, rec.Code, "pending %q: %s", pendingID, rec.Body.String())
	}

	// A caller outside the steward's tenant cannot use a valid queued copy.
	env.addPending(t, "pending-valid", cloneTenant, "steward-mv-rej", cloneDeviceB[:63]+"8")
	rec := callClone(env.server.handleMoveIdentity, http.MethodPost, "/", map[string]string{"id": "steward-mv-rej"},
		cloneOtherTenant, map[string]string{"pending_id": "pending-valid"})
	assert.Equal(t, http.StatusNotFound, rec.Code)

	got, err := env.steward.GetSteward(context.Background(), "steward-mv-rej")
	require.NoError(t, err)
	assert.Equal(t, cloneDeviceA, got.DeviceID, "a refused move must not touch the record")
	assert.Empty(t, env.auditActions(t, auditActionIdentityMoved))
}

func TestMoveIdentity_DeviceConflictChangesNothing(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-mv-c1", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	env.addSteward(t, "steward-mv-c2", cloneTenant, cloneDeviceB, business.StewardStatusActive)
	serials := env.issueClientCerts(t, "steward-mv-c1", 1)
	env.addPending(t, "pending-conflict", cloneTenant, "steward-mv-c1", cloneDeviceB)

	rec := callClone(env.server.handleMoveIdentity, http.MethodPost, "/", map[string]string{"id": "steward-mv-c1"},
		cloneTenant, map[string]string{"pending_id": "pending-conflict"})
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	got, _ := env.steward.GetSteward(context.Background(), "steward-mv-c1")
	assert.Equal(t, cloneDeviceA, got.DeviceID)
	entry, _ := env.server.pendingStore.GetPendingByID(context.Background(), "pending-conflict")
	assert.Equal(t, business.PendingRegistrationStatusPending, entry.Status)
	revoked, _ := env.certMgr.IsRevoked(serials[0])
	assert.False(t, revoked)
}

// TestMoveIdentity_NotAutomatic: no other handler changes a record's DeviceID.
// Approving, denying and claiming a queued copy leaves the original untouched,
// and RebindStewardIdentity has exactly one caller outside the storage layer.
func TestMoveIdentity_NotAutomatic(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-auto", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	approve := env.addPending(t, "pending-auto-approve", cloneTenant, "steward-auto", cloneDeviceB)
	env.addPending(t, "pending-auto-deny", cloneTenant, "steward-auto", cloneDeviceB[:63]+"7")

	rec := callClone(env.server.handleApproveRegistration, http.MethodPost, "/", map[string]string{"id": "pending-auto-approve"}, cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = callClone(env.server.handleDenyRegistration, http.MethodPost, "/", map[string]string{"id": "pending-auto-deny"}, cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	entry, err := env.server.pendingStore.GetPendingByID(context.Background(), approve.PendingID)
	require.NoError(t, err)
	_, err = env.server.buildClaimResponse(context.Background(), entry, env.regToken)
	require.NoError(t, err)

	got, err := env.steward.GetSteward(context.Background(), "steward-auto")
	require.NoError(t, err)
	assert.Equal(t, cloneDeviceA, got.DeviceID, "approve, deny and claim must never rebind the original record")

	var callers []string
	root := filepath.Join("..", "..", "..")
	for _, dir := range []string{"cmd", "features", "pkg"} {
		require.NoError(t, filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			if strings.Contains(filepath.ToSlash(path), "pkg/storage/") {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if bytes.Contains(data, []byte(".RebindStewardIdentity(")) {
				callers = append(callers, filepath.Base(path))
			}
			return nil
		}))
	}
	assert.Equal(t, []string{"handlers_identity_clones.go"}, callers,
		"only the move-identity handler may rebind a steward's device identity")
}

// --- Linking a locked copy to its old identity, Issue #5671 ---

// admitLocked registers a broken-trust copy naming oldID and returns its steward
// ID and pending entry.
func (e *cloneEnv) admitLocked(t *testing.T, oldID string) (string, *business.PendingRegistrationEntry) {
	t.Helper()
	e.server.SetApprovalHook(&AlwaysApproveHook{})
	rec := postRegisterWithBody(e.server, e.lockedRequest(t, oldID, cloneReasonBrokenTrust))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp RegistrationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	entry := e.pendingFor(t, resp.StewardID)
	require.NotNil(t, entry)
	return resp.StewardID, entry
}

func (e *cloneEnv) link(oldID, pendingID string, confirm bool) *httptest.ResponseRecorder {
	body := map[string]interface{}{"pending_id": pendingID}
	if confirm {
		body["confirm_live"] = true
	}
	return callClone(e.server.handleMoveIdentity, http.MethodPost, "/", map[string]string{"id": oldID}, cloneTenant, body)
}

// liveSerials returns the client-certificate serials issued for cn that are not revoked.
func (e *cloneEnv) liveSerials(t *testing.T, cn string) []string {
	t.Helper()
	infos, err := e.certMgr.GetCertificateByCommonName(cn)
	require.NoError(t, err)
	var live []string
	for _, info := range infos {
		if info.Type != cert.CertificateTypeClient {
			continue
		}
		revoked, err := e.certMgr.IsRevoked(info.SerialNumber)
		require.NoError(t, err)
		if !revoked {
			live = append(live, info.SerialNumber)
		}
	}
	return live
}

func TestLinkLockedCopy_RetiresCopyRebindsOldAndSupersedesEntry(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-old-lk", cloneTenant, cloneDeviceA, business.StewardStatusTampered)
	oldSerials := env.issueClientCerts(t, "steward-old-lk", 2)
	copyID, entry := env.admitLocked(t, "steward-old-lk")
	require.NotEmpty(t, env.liveSerials(t, copyID), "the copy holds a live credential before the link")

	rec := env.link("steward-old-lk", entry.PendingID, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp moveIdentityResponse
	decodeCloneData(t, rec, &resp)
	assert.Equal(t, copyID, resp.CopyStewardID)
	assert.ElementsMatch(t, oldSerials, resp.RevokedSerials)

	copyRec, err := env.steward.GetSteward(context.Background(), copyID)
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusDeregistered, copyRec.Status)
	assert.Empty(t, env.liveSerials(t, copyID), "the copy's serials are revoked")
	assert.Empty(t, env.liveSerials(t, "steward-old-lk"), "the old ID's previous credentials are revoked")

	old, err := env.steward.GetSteward(context.Background(), "steward-old-lk")
	require.NoError(t, err)
	assert.Equal(t, entry.DeviceID, old.DeviceID, "the old record holds the copy's device identity")
	assert.Equal(t, entry.IdentityKeyPub, old.IdentityKeyPub)
	assert.Equal(t, business.StewardStatusTampered, old.Status, "the old record keeps its tampered state until restore")

	got, err := env.server.pendingStore.GetPendingByID(context.Background(), entry.PendingID)
	require.NoError(t, err)
	assert.Equal(t, "steward-old-lk", got.StewardID, "the entry was approved under the old ID")
	assert.Equal(t, business.PendingRegistrationStatusDenied, got.Status, "then superseded")
	assert.Error(t, env.server.pendingStore.UpdateStatus(context.Background(), entry.PendingID, business.PendingRegistrationStatusClaimed),
		"a superseded entry can never be claimed")

	steps := map[string]bool{}
	for _, ev := range env.auditActions(t, auditActionLinkStep) {
		steps[ev.Details["step"].(string)] = true
		assert.Equal(t, business.AuditSeverityHigh, ev.Severity)
	}
	for _, name := range []string{linkStepRetireCopy, linkStepRebindOld, linkStepRevokeOld, linkStepApprovePend, linkStepSupersedePend} {
		assert.True(t, steps[name], "an audit event for step %s", name)
	}
	assert.Len(t, env.auditActions(t, auditActionIdentityMoved), 1)
}

func TestLinkLockedCopy_OldRecordKeepsActiveStatus(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-old-act", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	_, entry := env.admitLocked(t, "steward-old-act")
	require.Equal(t, http.StatusOK, env.link("steward-old-act", entry.PendingID, false).Code)
	old, err := env.steward.GetSteward(context.Background(), "steward-old-act")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusActive, old.Status)
}

func TestLinkLockedCopy_RequiresStrongAssurance(t *testing.T) {
	req, ok := permissionAssurance["steward:move-identity"]
	require.True(t, ok)
	assert.Equal(t, session.AssuranceStrong, req.Min)
}

func TestLinkLockedCopy_LiveOldRecordNeedsConfirmation(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-old-live", cloneTenant, cloneDeviceA, business.StewardStatusTampered)
	require.NoError(t, env.steward.UpdateHeartbeat(context.Background(), "steward-old-live", "1.0.0"))
	copyID, entry := env.admitLocked(t, "steward-old-live")

	rec := env.link("steward-old-live", entry.PendingID, false)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "CONFIRM_LIVE_REQUIRED")
	copyRec, err := env.steward.GetSteward(context.Background(), copyID)
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusTampered, copyRec.Status, "a refused link changes nothing")
	assert.NotEmpty(t, env.liveSerials(t, copyID))
	assert.Len(t, env.auditActions(t, auditActionLinkRefused), 1)

	rec = env.link("steward-old-live", entry.PendingID, true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	confirmed := false
	for _, ev := range env.auditActions(t, auditActionLinkStep) {
		if ev.Details["confirm_live"] == true {
			confirmed = true
		}
	}
	assert.True(t, confirmed, "the confirmation is audited")
	moved := env.auditActions(t, auditActionIdentityMoved)
	require.Len(t, moved, 1)
	assert.Equal(t, true, moved[0].Details["confirm_live"])
}

// failingRebindStore is the real steward store with a forced failure at the
// rebind step.
type failingRebindStore struct {
	business.StewardStore
	failures int
}

func (f *failingRebindStore) RebindStewardIdentity(ctx context.Context, id, deviceID string, key []byte, level, alg string) error {
	if f.failures > 0 {
		f.failures--
		return errors.New("injected rebind failure")
	}
	return f.StewardStore.RebindStewardIdentity(ctx, id, deviceID, key, level, alg)
}

// failingApproveStore is the real pending store with a forced failure when the
// entry is approved.
type failingApproveStore struct {
	business.PendingRegistrationStore
	failures int
}

func (f *failingApproveStore) UpdateStatus(ctx context.Context, id, status string) error {
	if status == business.PendingRegistrationStatusApproved && f.failures > 0 {
		f.failures--
		return errors.New("injected approve failure")
	}
	return f.PendingRegistrationStore.UpdateStatus(ctx, id, status)
}

func TestLinkLockedCopy_RebindFailureLeavesOldRecordUntouchedAndRetryCompletes(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-old-rb", cloneTenant, cloneDeviceA, business.StewardStatusTampered)
	copyID, entry := env.admitLocked(t, "steward-old-rb")
	env.server.SetStewardStore(&failingRebindStore{StewardStore: env.steward, failures: 1})

	rec := env.link("steward-old-rb", entry.PendingID, false)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), linkStepRebindOld, "the response names the failed step")

	old, err := env.steward.GetSteward(context.Background(), "steward-old-rb")
	require.NoError(t, err)
	assert.Equal(t, cloneDeviceA, old.DeviceID, "the old record is unchanged")
	assert.Equal(t, business.StewardStatusTampered, old.Status)
	assert.Empty(t, env.liveSerials(t, copyID), "the copy holds no valid credential")
	copyRec, err := env.steward.GetSteward(context.Background(), copyID)
	require.NoError(t, err)
	assert.NotEqual(t, business.StewardStatusActive, copyRec.Status, "and is not adopted")
	pending, err := env.server.pendingStore.GetPendingByID(context.Background(), entry.PendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusPending, pending.Status)
	assert.Len(t, env.auditActions(t, auditActionLinkFailed), 1)

	rec = env.link("steward-old-rb", entry.PendingID, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	old, err = env.steward.GetSteward(context.Background(), "steward-old-rb")
	require.NoError(t, err)
	assert.Equal(t, entry.DeviceID, old.DeviceID)
}

func TestLinkLockedCopy_ApproveFailureNeverLeavesTwoLiveCredentials(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-old-ap", cloneTenant, cloneDeviceA, business.StewardStatusTampered)
	env.issueClientCerts(t, "steward-old-ap", 1)
	copyID, entry := env.admitLocked(t, "steward-old-ap")
	real := env.server.pendingStore
	env.server.SetPendingStore(&failingApproveStore{PendingRegistrationStore: real, failures: 1})

	rec := env.link("steward-old-ap", entry.PendingID, false)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), linkStepApprovePend)

	assert.Empty(t, env.liveSerials(t, copyID), "the copy's credential is gone")
	assert.Empty(t, env.liveSerials(t, "steward-old-ap"), "so is the old identity's: no identity has two live credentials")
	old, err := env.steward.GetSteward(context.Background(), "steward-old-ap")
	require.NoError(t, err)
	assert.Equal(t, cloneDeviceA, old.DeviceID, "the rebind was rolled back")
	assert.Equal(t, business.StewardStatusTampered, old.Status)
	pending, err := real.GetPendingByID(context.Background(), entry.PendingID)
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusPending, pending.Status)
	assert.Equal(t, copyID, pending.StewardID, "the entry is back on the copy")

	require.Equal(t, http.StatusOK, env.link("steward-old-ap", entry.PendingID, false).Code, "a retry completes the link")
}

func TestListIdentityClones_ShowsLockedCopyWithUnverifiedEvidence(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-old-ls", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	require.NoError(t, env.tokenSt.SaveToken(context.Background(), &registration.Token{
		Token: "cfgms_reg_labelled", Label: "front-desk", TenantID: cloneTenant, ControllerURL: "grpc://c:1",
	}))
	env.server.SetApprovalHook(&AlwaysApproveHook{})
	req := env.lockedRequest(t, "steward-old-ls", cloneReasonBrokenTrust)
	req.Token = "cfgms_reg_labelled"
	rec := postRegisterWithBody(env.server, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	// An ordinary queued copy is listed without the locked fields.
	env.addPending(t, "pending-ordinary-ls", cloneTenant, "steward-old-ls", cloneDeviceB)

	rec = callClone(env.server.handleListIdentityClones, http.MethodGet, "/", nil, cloneTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp identityCloneListResponse
	decodeCloneData(t, rec, &resp)
	require.Len(t, resp.Clones, 1)
	var locked, ordinary *identityCloneQueuedCopy
	for i := range resp.Clones[0].QueuedCopies {
		c := &resp.Clones[0].QueuedCopies[i]
		if c.CloneReason != "" {
			locked = c
		} else {
			ordinary = c
		}
	}
	require.NotNil(t, locked)
	require.NotNil(t, ordinary)
	assert.Equal(t, cloneReasonBrokenTrust, locked.CloneReason)
	assert.Equal(t, "locked-host", locked.Hostname)
	assert.Equal(t, "front-desk", locked.TokenLabel)
	require.NotNil(t, locked.ClaimVerified)
	assert.False(t, *locked.ClaimVerified, "the claim is shown as unverified evidence")
	assert.NotNil(t, locked.OldLastSeen)
	assert.Equal(t, "pending-ordinary-ls", ordinary.PendingID)
}

func TestRestoreLockedCopyNamingOldIDIsRefused(t *testing.T) {
	env := newTamperEnv(t)
	env.addSteward(t, "steward-old-rs", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	copyID, _ := env.admitLocked(t, "steward-old-rs")
	rec := env.post(env.server.handleRestoreTamperedSteward, "restore", copyID, cloneTenant, nil)
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "LINK_REQUIRED")
	assert.Equal(t, business.StewardStatusTampered, env.status(t, copyID))
}

func TestMoveIdentity_OrdinaryMoveStillRefusesTamperedSource(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-tamp-src", cloneTenant, cloneDeviceA, business.StewardStatusTampered)
	env.addPending(t, "pending-tamp-src", cloneTenant, "steward-tamp-src", cloneDeviceB)
	rec := env.link("steward-tamp-src", "pending-tamp-src", false)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "STEWARD_NOT_ACTIVE")
}

// An ordinary move leaves an approved entry on the old ID; repeating the request
// must not be taken for a stopped link and supersede the legitimate claim.
func TestMoveIdentity_RepeatedOrdinaryMoveDoesNotSupersede(t *testing.T) {
	env := newCloneEnv(t)
	env.addSteward(t, "steward-mv-rep", cloneTenant, cloneDeviceA, business.StewardStatusActive)
	env.addPending(t, "pending-mv-rep", cloneTenant, "steward-mv-rep", cloneDeviceB)
	require.Equal(t, http.StatusOK, env.link("steward-mv-rep", "pending-mv-rep", false).Code)
	rec := env.link("steward-mv-rep", "pending-mv-rep", false)
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	entry, err := env.server.pendingStore.GetPendingByID(context.Background(), "pending-mv-rep")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusApproved, entry.Status)
}
