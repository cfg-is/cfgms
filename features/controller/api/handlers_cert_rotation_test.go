// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3579: tests for atomic resumable mTLS admin certificate rotation.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotateCertReq sends POST .../certs/rotate/{old_serial} with new serial and
// optional fingerprint in the request body.
func rotateCertReq(t *testing.T, server *Server, principal *Principal, username, oldSerial string, body RotateCertRequest) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/accounts/"+username+"/certs/rotate/"+oldSerial,
		bytes.NewReader(payload))
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"username": username, "old_serial": oldSerial})
	rec := httptest.NewRecorder()
	server.handleRotateCert(rec, req)
	return rec
}

// TestHandleCertRotation_FullSuccess verifies the happy path: bind new cert, revoke old cert,
// remove old binding — exactly one live certificate remains.
func TestHandleCertRotation_FullSuccess(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	oldSerial := provisionTestClientCert(t, certMgr, "alice-old-laptop")
	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial:      oldSerial,
		Fingerprint: "sha256:old",
		Label:       "alice old laptop",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code)
	assert.False(t, certMgr.IsRevoked(oldSerial), "old cert must not be revoked before rotation")

	newSerial := provisionTestClientCert(t, certMgr, "alice-new-laptop")

	rec := rotateCertReq(t, server, strongPrincipal(), "alice", oldSerial, RotateCertRequest{
		Serial:      newSerial,
		Fingerprint: "sha256:new",
	})
	require.Equal(t, http.StatusOK, rec.Code, "rotate: %s", rec.Body.String())

	assert.True(t, certMgr.IsRevoked(oldSerial), "old cert must be revoked after rotation")

	bindings := getCertBindings(t, server, "alice")
	require.Len(t, bindings, 1, "exactly one binding must remain")
	assert.Equal(t, newSerial, bindings[0].Serial)
	assert.False(t, containsSerial(bindings, oldSerial), "old binding must be removed")
}

// TestHandleCertRotation_InterruptedThenResumed simulates a process crash between step 1
// (bind new) and step 2 (revoke+remove old) by calling bindCertOnAccount directly.
// After the simulated interrupt, both certificates are live. A repeated call to
// handleRotateCert must converge to exactly one live certificate without error.
func TestHandleCertRotation_InterruptedThenResumed(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	oldSerial := provisionTestClientCert(t, certMgr, "alice-old-interrupted")
	newSerial := provisionTestClientCert(t, certMgr, "alice-new-interrupted")

	// Bind old cert normally.
	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial: oldSerial,
		Label:  "alice old",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code)

	// Simulate step 1 completing (new cert bound) without step 2 executing (old not yet revoked).
	// This mimics a process crash between bind-new and revoke-old.
	simulatedBinding := CertBinding{
		Serial:      newSerial,
		Fingerprint: "sha256:new",
		BoundAt:     time.Now().UTC(),
	}
	err := server.bindCertOnAccount(context.Background(), "alice", simulatedBinding, "test-principal")
	require.NoError(t, err, "simulated step-1 bind must succeed")

	// Both certs must be live — no lockout window.
	bindings := getCertBindings(t, server, "alice")
	assert.Len(t, bindings, 2, "both certs must be bound after step 1 only")
	assert.True(t, containsSerial(bindings, oldSerial), "old cert must still be bound")
	assert.True(t, containsSerial(bindings, newSerial), "new cert must be bound")
	assert.False(t, certMgr.IsRevoked(oldSerial), "old cert must NOT be revoked before resume")

	// Resume: full handler call with the same arguments.
	// Step 1 is already-done (new serial already bound) — must be skipped without error.
	// Step 2 must complete: revoke old cert and remove old binding.
	rec := rotateCertReq(t, server, strongPrincipal(), "alice", oldSerial, RotateCertRequest{
		Serial:      newSerial,
		Fingerprint: "sha256:new",
	})
	require.Equal(t, http.StatusOK, rec.Code, "resume rotation: %s", rec.Body.String())

	assert.True(t, certMgr.IsRevoked(oldSerial), "old cert must be revoked after resume")

	bindings = getCertBindings(t, server, "alice")
	require.Len(t, bindings, 1, "exactly one binding must remain after resume")
	assert.Equal(t, newSerial, bindings[0].Serial)
	assert.False(t, containsSerial(bindings, oldSerial), "old binding must be removed after resume")
}

// TestHandleCertRotation_IdempotentRetry verifies that repeating a fully-completed rotation
// returns 200 OK with no error, no duplicate binding, and no re-revocation side-effects.
func TestHandleCertRotation_IdempotentRetry(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	oldSerial := provisionTestClientCert(t, certMgr, "alice-old-idempotent")
	newSerial := provisionTestClientCert(t, certMgr, "alice-new-idempotent")

	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial: oldSerial,
	})
	require.Equal(t, http.StatusCreated, bindRec.Code)

	// First rotation — must succeed.
	rec1 := rotateCertReq(t, server, strongPrincipal(), "alice", oldSerial, RotateCertRequest{
		Serial:      newSerial,
		Fingerprint: "sha256:fp",
	})
	require.Equal(t, http.StatusOK, rec1.Code, "first rotation: %s", rec1.Body.String())
	assert.True(t, certMgr.IsRevoked(oldSerial))

	bindings := getCertBindings(t, server, "alice")
	require.Len(t, bindings, 1)
	assert.Equal(t, newSerial, bindings[0].Serial)

	// Second call with identical arguments — must be idempotent.
	rec2 := rotateCertReq(t, server, strongPrincipal(), "alice", oldSerial, RotateCertRequest{
		Serial:      newSerial,
		Fingerprint: "sha256:fp",
	})
	require.Equal(t, http.StatusOK, rec2.Code, "idempotent retry: %s", rec2.Body.String())

	// Exactly one binding — no duplicate created.
	bindings = getCertBindings(t, server, "alice")
	require.Len(t, bindings, 1, "no duplicate binding on idempotent retry")
	assert.Equal(t, newSerial, bindings[0].Serial)

	// Old cert remains revoked, not double-revoked or un-revoked.
	assert.True(t, certMgr.IsRevoked(oldSerial), "old cert must stay revoked")
}

// TestHandleCertRotation_OldBindingNotFound verifies that rotating a serial that is
// not bound to the account (and new serial also not bound) returns 404.
func TestHandleCertRotation_OldBindingNotFound(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	oldSerial := provisionTestClientCert(t, certMgr, "alice-never-bound")
	newSerial := provisionTestClientCert(t, certMgr, "alice-new-never")

	rec := rotateCertReq(t, server, strongPrincipal(), "alice", oldSerial, RotateCertRequest{
		Serial: newSerial,
	})
	assert.Equal(t, http.StatusNotFound, rec.Code, "old binding not found: %s", rec.Body.String())
}

// TestHandleCertRotation_SameSerialRejected verifies that rotating to the same serial is rejected.
func TestHandleCertRotation_SameSerialRejected(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	serial := provisionTestClientCert(t, certMgr, "alice-same")
	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: serial})
	require.Equal(t, http.StatusCreated, bindRec.Code)

	rec := rotateCertReq(t, server, strongPrincipal(), "alice", serial, RotateCertRequest{
		Serial: serial, // same as old
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "same serial must be rejected: %s", rec.Body.String())
}

// TestHandleCertRotation_NewSerialCrossAccountConflict verifies that rotating to a new
// serial that is already bound to a different account returns 409.
func TestHandleCertRotation_NewSerialCrossAccountConflict(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")
	createTestAccount(t, server, "bob")

	oldSerial := provisionTestClientCert(t, certMgr, "alice-to-rotate")
	newSerial := provisionTestClientCert(t, certMgr, "bob-existing")

	// Bind old to alice.
	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: oldSerial})
	require.Equal(t, http.StatusCreated, bindRec.Code)

	// Bind the "new" serial to bob first.
	bindRec2 := bindCertReq(t, server, strongPrincipal(), "bob", BindCertRequest{Serial: newSerial})
	require.Equal(t, http.StatusCreated, bindRec2.Code)

	// Alice tries to rotate to bob's serial — must conflict.
	rec := rotateCertReq(t, server, strongPrincipal(), "alice", oldSerial, RotateCertRequest{
		Serial: newSerial,
	})
	assert.Equal(t, http.StatusConflict, rec.Code, "cross-account new serial must return 409: %s", rec.Body.String())

	// Old binding must remain intact on alice (rotation did not proceed).
	bindings := getCertBindings(t, server, "alice")
	assert.True(t, containsSerial(bindings, oldSerial), "old binding must be intact after conflict")
}

// TestHandleCertRotation_SucceedsOnNonAuthoritativeNode is the [REQUIRED TEST] for
// handlers_cert_bindings.go (Issue #3761, ADR-031 Decision 1): handleRotateCert used
// to refuse with 503 and leave the bindings untouched when the serving node held no
// lease-backed leadership. Any-node service means every cluster node performs the
// rotation — the shared account store and the certificate manager are the
// serialization points, not leadership — so rotating against a real, deliberately
// non-authoritative *ha.Manager (ClusterMode, no lease ever acquired) must return 200,
// bind the new serial and revoke the old one.
func TestHandleCertRotation_SucceedsOnNonAuthoritativeNode(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	oldSerial := provisionTestClientCert(t, certMgr, "alice-leader-test")
	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{Serial: oldSerial})
	require.Equal(t, http.StatusCreated, bindRec.Code)

	newSerial := provisionTestClientCert(t, certMgr, "alice-leader-new")

	// A real HA manager that holds no lease: HasLeadership() == false.
	server.haManager = newNonAuthoritativeHAManager(t)

	rec := rotateCertReq(t, server, strongPrincipal(), "alice", oldSerial, RotateCertRequest{
		Serial: newSerial,
	})
	require.Equal(t, http.StatusOK, rec.Code, "rotation must succeed regardless of leadership: %s", rec.Body.String())

	// The rotation must have completed both steps on the non-authoritative node.
	bindings := getCertBindings(t, server, "alice")
	assert.True(t, containsSerial(bindings, newSerial), "new binding must exist")
	assert.False(t, containsSerial(bindings, oldSerial), "old binding must be removed")
	assert.True(t, certMgr.IsRevoked(oldSerial), "old cert must be revoked")
}

// TestHandleCertRotation_AccountNotFound verifies 404 when the account does not exist.
func TestHandleCertRotation_AccountNotFound(t *testing.T) {
	server, certMgr := setupCertBindingServer(t)

	oldSerial := provisionTestClientCert(t, certMgr, "ghost-old")
	newSerial := provisionTestClientCert(t, certMgr, "ghost-new")

	rec := rotateCertReq(t, server, strongPrincipal(), "ghost", oldSerial, RotateCertRequest{
		Serial: newSerial,
	})
	assert.Equal(t, http.StatusNotFound, rec.Code, "nonexistent account: %s", rec.Body.String())
}

// TestHandleCertRotation_InvalidSerial verifies that an invalid old_serial in the path
// is rejected with 400.
func TestHandleCertRotation_InvalidSerial(t *testing.T) {
	server, _ := setupCertBindingServer(t)
	createTestAccount(t, server, "alice")

	// Use invalid old_serial (certSerialRE would reject this).
	rec := rotateCertReq(t, server, strongPrincipal(), "alice", "../../etc/passwd", RotateCertRequest{
		Serial: "validnewserial",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "invalid old serial must be rejected")
}

// TestHandleCertRotation_NoCertManager verifies that rotation is refused with 503 when
// the old binding still exists but no certificate manager is configured (revocation
// would be impossible, leaving a valid credential without any account binding).
func TestHandleCertRotation_NoCertManager(t *testing.T) {
	server := setupTestServer(t)
	require.Nil(t, server.certManager, "this test requires a server with no cert manager")

	createTestAccount(t, server, "alice")
	const oldSerial = "aabb1122ccdd"
	const newSerial = "eeff33445566"

	bindRec := bindCertReq(t, server, strongPrincipal(), "alice", BindCertRequest{
		Serial: oldSerial,
		Label:  "no-cert-manager old",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code)

	rec := rotateCertReq(t, server, strongPrincipal(), "alice", oldSerial, RotateCertRequest{
		Serial: newSerial,
	})
	// Must be refused — we cannot revoke the old cert, so we cannot safely complete the rotation.
	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"rotation must fail when cert manager is unavailable: %s", rec.Body.String())

	// Old binding must remain intact.
	listRec := listCertsReq(t, server, testAdminPrincipal(), "alice")
	require.Equal(t, http.StatusOK, listRec.Code)
	var resp struct {
		Data []CertBindingInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(listRec.Body).Decode(&resp))
	assert.True(t, containsSerial(resp.Data, oldSerial), "old binding must be intact after refused rotation")
}
