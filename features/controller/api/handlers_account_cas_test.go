// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #5165: [REQUIRED TEST] compare-and-swap coverage for the three account-write
// paths that used to overwrite the whole record with persistAccount:
// handlePasskeyEnrollFinish, handleUpdateAccount and handleRevokeEnrollmentLink.
//
// Each test opens the read-to-write window deterministically: raceSecretStore wraps
// the real secret store and, on the handler's read of the account record, commits a
// competing write (a disable, a credential removal, a first-passkey enrollment)
// right after the read returns. The handler then holds a stale version, so a
// compare-and-swap write loses; a plain overwrite would silently undo the
// competing write. Each test asserts the 409 and that the stored record is the
// competing writer's, unchanged by the handler.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
)

// raceSecretStore is a test implementation of SecretStore that delegates to a real
// store and runs a hook once, right after the first ListSecrets read of the armed
// account's record returns.
type raceSecretStore struct {
	secretsif.SecretStore

	mu       sync.Mutex
	username string
	hook     func()
}

// arm schedules hook to run once after the next read of username's account record.
func (r *raceSecretStore) arm(username string, hook func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.username = username
	r.hook = hook
}

func (r *raceSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	metas, err := r.SecretStore.ListSecrets(ctx, filter)
	r.mu.Lock()
	var hook func()
	if r.hook != nil && filter != nil && filter.Metadata["username"] == r.username {
		hook, r.hook = r.hook, nil
	}
	r.mu.Unlock()
	if hook != nil {
		hook()
	}
	return metas, err
}

// casRaceServer returns a test server whose secret store is wrapped in a raceSecretStore.
func casRaceServer(t *testing.T) (*Server, *raceSecretStore) {
	t.Helper()
	server := setupTestServer(t)
	race := &raceSecretStore{SecretStore: server.secretStore}
	server.secretStore = race
	return server, race
}

// commitCompetingWrite applies mutate to the stored record through a compare-and-swap,
// as a concurrent admin request would.
func commitCompetingWrite(t *testing.T, server *Server, username string, mutate func(a *account)) {
	t.Helper()
	cur, err := server.loadAccountFromStore(context.Background(), username, "")
	require.NoError(t, err)
	require.NotNil(t, cur)
	next := *cur
	mutate(&next)
	_, ok, err := server.persistAccountCAS(context.Background(), &next, "competing-writer")
	require.NoError(t, err)
	require.True(t, ok, "competing write must commit")
}

func casStoredAccount(t *testing.T, server *Server, username string) *account {
	t.Helper()
	dropAccountCache(server)
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	require.NotNil(t, acct)
	return acct
}

func createCASAccount(t *testing.T, server *Server, username string, perms []string) {
	t.Helper()
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username, TenantID: "tenant-a", Permissions: perms})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
}

// seedCredential gives the stored account one passkey credential.
func seedCredential(t *testing.T, server *Server, username string) {
	t.Helper()
	commitCompetingWrite(t, server, username, func(a *account) {
		a.Credentials = []WebAuthnCredential{{ID: []byte("cred-1"), PublicKey: []byte("pk"), RegisteredAt: time.Now().UTC()}}
	})
}

func TestUpdateAccount_LostSwap_DisableNotUndone(t *testing.T) {
	server, race := casRaceServer(t)
	createCASAccount(t, server, "cas-upd-disable", []string{"steward:list"})

	race.arm("cas-upd-disable", func() {
		commitCompetingWrite(t, server, "cas-upd-disable", func(a *account) { a.Disabled = true })
	})
	perms := []string{"steward:list", "steward:read"}
	rec := putAccount(t, server, testAdminPrincipal(), "cas-upd-disable", AccountUpdateRequest{Permissions: &perms})

	assert.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "ACCOUNT_MODIFIED", errCode(t, rec.Body.Bytes()))
	stored := casStoredAccount(t, server, "cas-upd-disable")
	assert.True(t, stored.Disabled, "the concurrent disable must survive")
	assert.Equal(t, []string{"steward:list"}, stored.Permissions, "the lost update must not be written")
}

func TestUpdateAccount_LostSwap_CredentialRemovalNotRestored(t *testing.T) {
	server, race := casRaceServer(t)
	createCASAccount(t, server, "cas-upd-cred", []string{"steward:list"})
	seedCredential(t, server, "cas-upd-cred")

	race.arm("cas-upd-cred", func() {
		commitCompetingWrite(t, server, "cas-upd-cred", func(a *account) { a.Credentials = nil })
	})
	perms := []string{"steward:list", "steward:read"}
	rec := putAccount(t, server, testAdminPrincipal(), "cas-upd-cred", AccountUpdateRequest{Permissions: &perms})

	assert.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "ACCOUNT_MODIFIED", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, casStoredAccount(t, server, "cas-upd-cred").Credentials, "the revoked credential must not be restored")
}

func TestUpdateAccount_LostSwap_ResetCredentialsReturnsNoLinkAndKeepsSessions(t *testing.T) {
	server, race := casRaceServer(t)
	createCASAccount(t, server, "cas-upd-reset", []string{"steward:list"})
	seedCredential(t, server, "cas-upd-reset")

	webCfg := session.Config{IdleTimeout: time.Hour, AbsoluteTimeout: 12 * time.Hour, GraceWindow: 30 * time.Second}
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	server.SetWebSessionManager(session.NewManager(webCfg, store, time.Now))
	acct := casStoredAccount(t, server, "cas-upd-reset")
	_, token, err := server.webSessionManager.Issue(context.Background(), acct.ID, "web-login", "default")
	require.NoError(t, err)
	before := casStoredAccount(t, server, "cas-upd-reset")

	race.arm("cas-upd-reset", func() {
		commitCompetingWrite(t, server, "cas-upd-reset", func(a *account) { a.Disabled = true })
	})
	rec := putAccount(t, server, testAdminPrincipal(), "cas-upd-reset", AccountUpdateRequest{ResetCredentials: true})

	assert.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "enrollment_magic_link", "a link minted for a lost write must never be returned")
	_, err = server.webSessionManager.Validate(context.Background(), token)
	assert.NoError(t, err, "no session may be revoked on a lost swap")
	stored := casStoredAccount(t, server, "cas-upd-reset")
	assert.Len(t, stored.Credentials, 1, "credentials must not be wiped")
	assert.Equal(t, before.EnrollmentLinkHash, stored.EnrollmentLinkHash, "no new link hash may be stored")
	assert.True(t, stored.Disabled)
}

func TestRevokeEnrollmentLink_LostSwap_FirstPasskeyNotLost(t *testing.T) {
	server, race := casRaceServer(t)
	createCASAccount(t, server, "cas-rev-enroll", nil)

	race.arm("cas-rev-enroll", func() {
		commitCompetingWrite(t, server, "cas-rev-enroll", func(a *account) {
			a.Credentials = []WebAuthnCredential{{ID: []byte("first"), PublicKey: []byte("pk"), RegisteredAt: time.Now().UTC()}}
			a.EnrollmentLinkRevoked = true
		})
	})
	rec := revokeEnrollmentLink(t, server, testAdminPrincipal(), "cas-rev-enroll")

	assert.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "ACCOUNT_MODIFIED", errCode(t, rec.Body.Bytes()))
	stored := casStoredAccount(t, server, "cas-rev-enroll")
	require.Len(t, stored.Credentials, 1, "the first passkey must not be lost")
	assert.Equal(t, []byte("first"), stored.Credentials[0].ID)
}

func TestRevokeEnrollmentLink_LostSwap_DisableNotReverted(t *testing.T) {
	server, race := casRaceServer(t)
	createCASAccount(t, server, "cas-rev-disable", nil)

	race.arm("cas-rev-disable", func() {
		commitCompetingWrite(t, server, "cas-rev-disable", func(a *account) { a.Disabled = true })
	})
	rec := revokeEnrollmentLink(t, server, testAdminPrincipal(), "cas-rev-disable")

	assert.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "ACCOUNT_MODIFIED", errCode(t, rec.Body.Bytes()))
	stored := casStoredAccount(t, server, "cas-rev-disable")
	assert.True(t, stored.Disabled, "the concurrent disable must survive")
	assert.False(t, stored.EnrollmentLinkRevoked, "the lost revocation must not be written")
}

func TestPasskeyEnrollFinish_LostSwap_DisableNotReverted(t *testing.T) {
	// W3C Level 3 §16.2 NoneES256 spec test vector (same as TestPasskeyEnrollFinish).
	const (
		rpID        = "example.org"
		origin      = "https://example.org"
		attObjHex   = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220" //nolint:gosec // spec test vector
		clientHex   = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
		credIDHex   = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec // spec test vector
		challengeHx = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
		username    = "cas-enroll-disable"
	)
	attObj, err := hex.DecodeString(attObjHex)
	require.NoError(t, err)
	cdj, err := hex.DecodeString(clientHex)
	require.NoError(t, err)
	credID, err := hex.DecodeString(credIDHex)
	require.NoError(t, err)
	chal, err := hex.DecodeString(challengeHx)
	require.NoError(t, err)

	server, race := casRaceServer(t)
	wa, err := NewWebAuthnFromConfig(rpID, rpID, []string{origin})
	require.NoError(t, err)
	server.SetWebAuthn(wa)
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
	rawToken := parseCreateResponse(t, rec).EnrollmentMagicLink
	require.NotEmpty(t, rawToken)

	acct := casStoredAccount(t, server, username)
	injectEnrollSession(server, rawToken, webauthn.SessionData{
		Challenge:        base64.RawURLEncoding.EncodeToString(chal),
		UserID:           []byte(acct.ID),
		UserVerification: protocol.VerificationPreferred,
		RelyingPartyID:   rpID,
		CredParams: []protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
		},
	}, 10*time.Minute)

	race.arm(username, func() {
		commitCompetingWrite(t, server, username, func(a *account) { a.Disabled = true })
	})
	body := finishBody(t, base64.RawURLEncoding.EncodeToString(credID),
		base64.RawURLEncoding.EncodeToString(cdj), base64.RawURLEncoding.EncodeToString(attObj))
	rec = doEnrollFinish(t, server, rawToken, body)

	assert.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "ACCOUNT_MODIFIED", errCode(t, rec.Body.Bytes()))
	stored := casStoredAccount(t, server, username)
	assert.True(t, stored.Disabled, "the concurrent disable must survive")
	assert.Empty(t, stored.Credentials, "no credential may be stored on a lost swap")
	assert.False(t, bytes.Contains(rec.Body.Bytes(), credID))
}

func TestCreateAccountReset_LostSwap_DisableNotUndone(t *testing.T) {
	server, race := casRaceServer(t)
	createCASAccount(t, server, "cas-reset-disable", []string{"steward:list"})
	seedCredential(t, server, "cas-reset-disable")

	race.arm("cas-reset-disable", func() {
		commitCompetingWrite(t, server, "cas-reset-disable", func(a *account) { a.Disabled = true })
	})
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: "cas-reset-disable", TenantID: "tenant-a", Permissions: []string{"steward:list"}, ResetCredentials: true,
	})

	assert.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "ACCOUNT_MODIFIED", errCode(t, rec.Body.Bytes()))
	assert.NotContains(t, rec.Body.String(), "enrollment_magic_link", "a link minted for a lost write must never be returned")
	stored := casStoredAccount(t, server, "cas-reset-disable")
	assert.True(t, stored.Disabled, "the concurrent disable must survive")
	assert.Len(t, stored.Credentials, 1, "credentials must not be wiped by a lost reset")
}

func TestPasskeyEnroll_DisabledAccountRefused(t *testing.T) {
	const username = "cas-enroll-disabled"
	server := setupTestServer(t)
	wa, err := NewWebAuthnFromConfig("example.org", "example.org", []string{"https://example.org"})
	require.NoError(t, err)
	server.SetWebAuthn(wa)
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{Username: username})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())
	rawToken := parseCreateResponse(t, rec).EnrollmentMagicLink
	require.NotEmpty(t, rawToken)

	commitCompetingWrite(t, server, username, func(a *account) { a.Disabled = true })

	rec = doEnrollBegin(t, server, rawToken)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "begin body: %s", rec.Body.String())

	acct := casStoredAccount(t, server, username)
	injectEnrollSession(server, rawToken, webauthn.SessionData{
		UserID:         []byte(acct.ID),
		RelyingPartyID: "example.org",
	}, 10*time.Minute)
	rec = doEnrollFinish(t, server, rawToken, finishBody(t, "AA", "AA", "AA"))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "finish body: %s", rec.Body.String())
	assert.Empty(t, casStoredAccount(t, server, username).Credentials, "a disabled account must not gain a credential")
}

// Issue #5205 [REQUIRED TEST]: a certificate bound between the offboarding read and the
// disable write is revoked, and the stored account is disabled and keeps the binding.
func TestOffboarding_CertBoundDuringDisable_IsRevoked(t *testing.T) {
	srv, certMgr := setupCertBindingServer(t)
	race := &raceSecretStore{SecretStore: srv.secretStore}
	srv.secretStore = race
	createTestAccount(t, srv, "off-race-cert")
	serial := provisionTestClientCert(t, certMgr, "off-race-laptop")

	race.arm("off-race-cert", func() {
		commitCompetingWrite(t, srv, "off-race-cert", func(a *account) {
			a.CertBindings = append(a.CertBindings, CertBinding{Serial: serial, Fingerprint: "fp", BoundAt: time.Now().UTC()})
		})
	})
	rec := deleteAccount(t, srv, strongPrincipal(), "off-race-cert")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	revoked, err := certMgr.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revoked, "the concurrently bound certificate must be revoked")
}

// The retry must stop at the disable: a lost final attempt leaves the record as the
// competing writer left it, and a credential revocation committed mid-flight survives.
func TestOffboarding_ConcurrentWrites_PreservedAndExhaustedReturns409(t *testing.T) {
	t.Run("revoked credential survives the retry", func(t *testing.T) {
		srv, certMgr := setupCertBindingServer(t)
		race := &raceSecretStore{SecretStore: srv.secretStore}
		srv.secretStore = race
		createTestAccount(t, srv, "off-race-revoked")
		serial := provisionTestClientCert(t, certMgr, "off-race-revoked-laptop")
		rec := bindCertReq(t, srv, strongPrincipal(), "off-race-revoked", BindCertRequest{Serial: serial})
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		// Without a cert manager the cascade stops after the disable, leaving the written
		// record in the store to inspect.
		srv.certManager = nil

		race.arm("off-race-revoked", func() {
			commitCompetingWrite(t, srv, "off-race-revoked", func(a *account) {
				a.RevokedCredentialIDs = [][]byte{[]byte("revoked-1")}
			})
		})
		rec = deleteAccount(t, srv, strongPrincipal(), "off-race-revoked")
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())

		stored := casStoredAccount(t, srv, "off-race-revoked")
		assert.True(t, stored.Disabled)
		assert.Equal(t, [][]byte{[]byte("revoked-1")}, stored.RevokedCredentialIDs)
		assert.Len(t, stored.CertBindings, 1)
	})

	t.Run("every attempt losing returns 409 and revokes nothing", func(t *testing.T) {
		srv, certMgr := setupCertBindingServer(t)
		race := &raceSecretStore{SecretStore: srv.secretStore}
		srv.secretStore = race
		createTestAccount(t, srv, "off-race-lost")
		serial := provisionTestClientCert(t, certMgr, "off-race-lost-laptop")
		rec := bindCertReq(t, srv, strongPrincipal(), "off-race-lost", BindCertRequest{Serial: serial})
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

		var hook func()
		hook = func() {
			commitCompetingWrite(t, srv, "off-race-lost", func(a *account) {
				a.RevokedCredentialIDs = append(a.RevokedCredentialIDs, []byte{byte(len(a.RevokedCredentialIDs))})
			})
			race.arm("off-race-lost", hook)
		}
		race.arm("off-race-lost", hook)
		rec = deleteAccount(t, srv, strongPrincipal(), "off-race-lost")
		race.arm("", nil)

		assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
		assert.Equal(t, "ACCOUNT_MODIFIED", errCode(t, rec.Body.Bytes()))
		revoked, err := certMgr.IsRevoked(serial)
		require.NoError(t, err)
		assert.False(t, revoked, "no certificate may be revoked after a lost final attempt")
		stored := casStoredAccount(t, srv, "off-race-lost")
		assert.False(t, stored.Disabled)
		assert.Len(t, stored.RevokedCredentialIDs, 3, "competing writes preserved")
	})
}

// Issue #5205 [REQUIRED TEST]: a moved reset whose old-tenant record is disabled before
// the old record's removal fails, leaves the old record disabled and no destination.
func TestCreateAccount_MovedReset_OldRecordChanged_409(t *testing.T) {
	srv, race := casRaceServer(t)
	createCASAccount(t, srv, "moved-race", []string{"steward:list"})

	// The disable lands right after the handler's read, before the old-record removal.
	race.arm("moved-race", func() {
		commitCompetingWrite(t, srv, "moved-race", func(a *account) { a.Disabled = true })
	})
	rec := postAccount(t, srv, testAdminPrincipal(), AccountRequest{Username: "moved-race", TenantID: "tenant-b"})
	race.arm("", nil)

	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Equal(t, "ACCOUNT_MODIFIED", errCode(t, rec.Body.Bytes()))
	metas, err := srv.secretStore.ListSecrets(context.Background(), &secretsif.SecretFilter{
		Metadata: map[string]string{"username": "moved-race"},
	})
	require.NoError(t, err)
	require.Len(t, metas, 1, "exactly one live record must remain")
	assert.Equal(t, "tenant-a", metas[0].TenantID)
	assert.Equal(t, "true", metas[0].Metadata["disabled"])
}
