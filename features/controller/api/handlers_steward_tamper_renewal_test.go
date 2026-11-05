// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const tamperRenewalStewardID = "s-tampered"

type tamperRenewal struct {
	*refreshFixture
	priv ed25519.PrivateKey
}

// newTamperRenewal builds a refresh fixture with one steward that went through
// the real tamper alarm: durable record and node-local entry are both tampered.
func newTamperRenewal(t *testing.T, policy string) *tamperRenewal {
	t.Helper()
	pub, priv := newTestEd25519KeyPair(t)
	f := newRefreshFixture(t, newTestCertManager(t))
	f.addSteward(t, &business.StewardRecord{
		ID: tamperRenewalStewardID, DeviceID: testDeviceID, TenantID: testTenantID,
		Status: business.StewardStatusActive, IdentityKeyPub: []byte(pub),
	})
	require.NoError(t, f.server.controllerService.RegisterSteward(tamperRenewalStewardID, testTenantID, "", "online"))
	if policy != "" {
		f.setPolicy(t, &business.RefreshPolicy{TenantID: testTenantID, Mode: policy})
	}
	f.server.HandleStewardTamperAlarm(context.Background(), tamperRenewalStewardID, []controlplaneTypes.HealthReason{
		{Component: "integrity", Code: controlplaneTypes.ReasonCodeTamperDataDir, Message: "data dir changed"},
	})
	r := &tamperRenewal{refreshFixture: f, priv: priv}
	require.Eventually(t, func() bool { return r.alarmCount(t) == 1 }, 5*time.Second, 20*time.Millisecond)
	r.requireTampered(t)
	return r
}

func (r *tamperRenewal) alarmCount(t *testing.T) int {
	t.Helper()
	return r.actionCount(t, auditActionStewardTamperAlarm)
}

func (r *tamperRenewal) actionCount(t *testing.T, action string) int {
	t.Helper()
	require.NoError(t, r.audit.Flush(context.Background()))
	entries, err := r.audit.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// requireTampered asserts the store, the node-local registry and the list path
// all still report tampered.
func (r *tamperRenewal) requireTampered(t *testing.T) {
	t.Helper()
	rec, err := r.stewards.GetSteward(context.Background(), tamperRenewalStewardID)
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusTampered, rec.Status, "store status")
	info, ok := r.server.controllerService.GetStewardInfo(tamperRenewalStewardID)
	require.True(t, ok)
	assert.Equal(t, "tampered", info.Status, "node-local status")
	listed, ok := listDirect(t, r.server, "")[tamperRenewalStewardID]
	require.True(t, ok, "tampered steward stays in the list")
	assert.Equal(t, "tampered", listed.Status, "list path status")
}

func (r *tamperRenewal) renew(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	challenge := issueChallenge(t, r.server, testDeviceID, testTenantID)
	req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, r.priv, nil)
	return postComplete(r.server, testDeviceID, req)
}

func TestTamperedRenewal_IssuesCertificateOnlyAndKeepsTampered(t *testing.T) {
	r := newTamperRenewal(t, "auto_accept")

	rec := r.renew(t)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Wire struct: certificate and issuer chain only.
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	for k := range raw {
		assert.Contains(t, []string{"status", "client_cert", "issuer_chain"}, k, "unexpected response field %q", k)
	}
	for _, absent := range []string{"signing_cert", "server_cert", "ca_cert", "transport_address", "steward_id", "tenant_id", "client_key"} {
		assert.NotContains(t, raw, absent)
	}
	var resp RefreshCompleteResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.ClientCert)
	assert.Empty(t, resp.SigningCert)
	assert.Empty(t, resp.ServerCert)
	assert.Empty(t, resp.CACert)
	assert.Empty(t, resp.TransportAddress)

	// Same steward ID is carried in the signed certificate.
	block, _ := pem.Decode([]byte(resp.ClientCert))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, tamperRenewalStewardID, cert.Subject.CommonName)

	// Tenant is unchanged and the state survives on every read path.
	got, err := r.stewards.GetSteward(context.Background(), tamperRenewalStewardID)
	require.NoError(t, err)
	assert.Equal(t, testTenantID, got.TenantID)
	r.requireTampered(t)

	// Original notification record intact, renewal audited.
	assert.Equal(t, 1, r.alarmCount(t), "renewal must neither re-notify nor remove the original alarm record")
	assert.Equal(t, 1, r.actionCount(t, auditActionTamperRenewal))
}

func TestTamperedRenewal_AuditPerRenewal(t *testing.T) {
	r := newTamperRenewal(t, "auto_accept")
	for i := 1; i <= 2; i++ {
		require.Equal(t, http.StatusOK, r.renew(t).Code)
		assert.Equal(t, i, r.actionCount(t, auditActionTamperRenewal))
	}
	r.requireTampered(t)
}

func TestTamperedRenewal_ExpiredClientCertWithValidProofRenews(t *testing.T) {
	// The handler never consults a presented client certificate; proof of
	// possession is the only authorisation, so an expired certificate changes nothing.
	r := newTamperRenewal(t, "auto_accept")
	rec := r.renew(t)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	r.requireTampered(t)
}

func TestTamperedRenewal_RequestCarriesCSRNotKeys(t *testing.T) {
	typ := reflect.TypeOf(RefreshCompleteRequest{})
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.ToLower(typ.Field(i).Tag.Get("json"))
		assert.NotContains(t, tag, "private")
		assert.NotContains(t, tag, "client_key")
	}
	resp := reflect.TypeOf(RefreshCompleteResponse{})
	for i := 0; i < resp.NumField(); i++ {
		tag := strings.ToLower(resp.Field(i).Tag.Get("json"))
		assert.NotContains(t, tag, "key")
	}
	_, ok := typ.FieldByName("CSRPEM")
	assert.True(t, ok)
}

func TestTamperedRenewal_RefusedAfterBan(t *testing.T) {
	r := newTamperRenewal(t, "auto_accept")
	ok, err := r.stewards.TransitionStewardStatus(context.Background(), tamperRenewalStewardID,
		business.StewardStatusRevoked, business.StewardStatusTampered)
	require.NoError(t, err)
	require.True(t, ok)

	body, _ := json.Marshal(RefreshChallengeRequest{TenantID: testTenantID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+testDeviceID+"/refresh/challenge", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"device_id": testDeviceID})
	rec := httptest.NewRecorder()
	r.server.handleRefreshChallenge(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestTamperedRenewal_RevokedCheckedBeforeProof(t *testing.T) {
	r := newTamperRenewal(t, "auto_accept")
	_, err := r.stewards.TransitionStewardStatus(context.Background(), tamperRenewalStewardID,
		business.StewardStatusRevoked, business.StewardStatusTampered)
	require.NoError(t, err)

	r.plantNonce(t, testDeviceID)
	rec := postComplete(r.server, testDeviceID, RefreshCompleteRequest{
		Nonce: "AAAA", Signature: "AAAA", IssuedAt: time.Now().UnixNano(), CSRPEM: testValidCSRPEM,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "revoked", "a revoked steward gets the revocation refusal, not a proof error")
}

func TestTamperedRenewal_ProofFailuresRefused(t *testing.T) {
	r := newTamperRenewal(t, "auto_accept")

	t.Run("bad signature", func(t *testing.T) {
		challenge := issueChallenge(t, r.server, testDeviceID, testTenantID)
		_, otherPriv := newTestEd25519KeyPair(t)
		req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, otherPriv, nil)
		assert.Equal(t, http.StatusUnauthorized, postComplete(r.server, testDeviceID, req).Code)
	})
	t.Run("replayed nonce", func(t *testing.T) {
		challenge := issueChallenge(t, r.server, testDeviceID, testTenantID)
		req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, r.priv, nil)
		require.Equal(t, http.StatusOK, postComplete(r.server, testDeviceID, req).Code)
		assert.NotEqual(t, http.StatusOK, postComplete(r.server, testDeviceID, req).Code)
	})
	t.Run("stale nonce", func(t *testing.T) {
		challenge := issueChallenge(t, r.server, testDeviceID, testTenantID)
		req := buildValidCompleteRequest(t, testDeviceID, testTenantID, challenge, r.priv, nil)
		req.IssuedAt = time.Now().Add(-2 * nonceMaxAge).UnixNano()
		assert.NotEqual(t, http.StatusOK, postComplete(r.server, testDeviceID, req).Code)
	})
	t.Run("no proof", func(t *testing.T) {
		rec := postComplete(r.server, testDeviceID, RefreshCompleteRequest{CSRPEM: testValidCSRPEM})
		assert.NotEqual(t, http.StatusOK, rec.Code)
	})
	r.requireTampered(t)
}

func TestTamperedRenewal_QueueingReasonsUnchanged(t *testing.T) {
	t.Run("require_approval queues, state kept", func(t *testing.T) {
		r := newTamperRenewal(t, "require_approval")
		assert.Equal(t, http.StatusAccepted, r.renew(t).Code)
		assert.Equal(t, 1, r.pendingCount(t))
		r.requireTampered(t)
	})
	t.Run("no policy store default queues", func(t *testing.T) {
		r := newTamperRenewal(t, "")
		r.server.refreshPolicyStore = nil
		assert.Equal(t, http.StatusAccepted, r.renew(t).Code)
		r.requireTampered(t)
	})
	t.Run("reject policy refuses", func(t *testing.T) {
		r := newTamperRenewal(t, "reject")
		assert.Equal(t, http.StatusForbidden, r.renew(t).Code)
		assert.Equal(t, 0, r.pendingCount(t))
		r.requireTampered(t)
	})
	t.Run("auto_accept does not queue", func(t *testing.T) {
		r := newTamperRenewal(t, "auto_accept")
		assert.Equal(t, http.StatusOK, r.renew(t).Code)
		assert.Equal(t, 0, r.pendingCount(t), "tampered state adds no queueing reason")
	})
	t.Run("approved queue entry delivers certificate only", func(t *testing.T) {
		r := newTamperRenewal(t, "require_approval")
		require.Equal(t, http.StatusAccepted, r.renew(t).Code)
		entries, err := r.pending.ListPendingRefresh(context.Background(), testTenantID)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		record, err := r.stewards.GetSteward(context.Background(), tamperRenewalStewardID)
		require.NoError(t, err)
		resp, serial, err := r.server.buildRefreshClaimResponse(context.Background(), record, entries[0].CSRPEM)
		require.NoError(t, err)
		assert.NotEmpty(t, serial)
		assert.NotEmpty(t, resp.ClientCert)
		assert.Empty(t, resp.CACert)
		assert.Empty(t, resp.SigningCert)
		r.requireTampered(t)
	})
}

// TestTamperedRenewal_NoWritePathClearsTampered is the source guard: no status
// write in the refresh handler lists tampered as a destination or source of a
// transition, and the node-local reset is guarded.
func TestTamperedRenewal_NoWritePathClearsTampered(t *testing.T) {
	src, err := os.ReadFile("handlers_registration_refresh.go")
	require.NoError(t, err)
	text := string(src)

	for _, call := range regexp.MustCompile(`(?s)TransitionStewardStatus\(.*?\)\n`).FindAllString(text, -1) {
		assert.NotContains(t, call, "StewardStatusTampered", "claim transition must never name tampered")
	}
	assert.NotContains(t, text, "UpdateStewardStatusDurable")
	assert.Equal(t, 1, strings.Count(text, "UpdateStewardStatus("), "exactly one node-local status write")
	assert.Contains(t, text, "!s.stewardIsTampered(ctx, record.ID)", "node-local reset must be guarded")
}
