// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configsignature "github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
)

const actionTestSteward = "steward-1"

func testAction() operatorpayload.Action {
	return operatorpayload.Action{
		Verb:       "restart",
		TargetKind: "service",
		TargetName: "spooler",
		Parameters: map[string]string{"force": "true"},
	}
}

func actionEnvelope(t *testing.T, a operatorpayload.Action, targets []string, nonce string, expiresAt time.Time) operatorpayload.Envelope {
	t.Helper()
	content, err := operatorpayload.ActionContent(a)
	require.NoError(t, err)
	return operatorpayload.Envelope{Content: content, Shell: operatorpayload.ActionShell, Targets: targets, Nonce: nonce, ExpiresAt: expiresAt}
}

// signActionX509 issues an operator certificate from server's CA with the given marker
// and signs the action envelope with it.
func signActionX509(t *testing.T, server *Server, env operatorpayload.Envelope, marker func(*x509.Certificate)) (*OperatorProof, string) {
	t.Helper()
	operator, err := server.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "test-operator", ValidityDays: 1, KeySize: 2048, ClientID: "test-operator",
		TemplateModifier: marker,
	})
	require.NoError(t, err)
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)
	signer, err := configsignature.NewSigner(&configsignature.SignerConfig{
		PrivateKeyPEM: operator.PrivateKeyPEM, CertificatePEM: operator.CertificatePEM,
	})
	require.NoError(t, err)
	signed, err := signer.Sign(canonical)
	require.NoError(t, err)
	return &OperatorProof{X509: &OperatorX509Proof{
		Algorithm: string(signed.Algorithm), Value: signed.Signature, PublicKey: string(operator.CertificatePEM),
	}}, operator.SerialNumber
}

// testSignerAccountID is the account the action and terminal tests' operator certificates are
// bound to; it is also the principal ID those tests authenticate as.
const testSignerAccountID = "op-1"

// signActionX509Bound is signActionX509 with a certificate bound to accountID, the shape
// handleRequestSigningCredential issues. The account is created holding operator-payload:sign
// when it does not exist yet, so a request authenticated as it passes the binding check.
func signActionX509Bound(t *testing.T, server *Server, accountID string, env operatorpayload.Envelope) (*OperatorProof, string) {
	t.Helper()
	if acct, err := server.getAccountByID(context.Background(), accountID); err != nil || acct == nil {
		seedOperatorAccount(t, server, accountID, true)
	}
	return signActionX509(t, server, env, boundSigningMarker(accountID))
}

// signerCtx is the request context of the principal the test certificates are bound to.
func signerCtx() context.Context {
	return ctxWithPrincipal(&Principal{ID: testSignerAccountID, Name: "session:" + testSignerAccountID, AccountBound: true})
}

func ctxWithPrincipal(p *Principal) context.Context {
	return context.WithValue(context.Background(), principalContextKey, p)
}

func newActionX509Server(t *testing.T) *Server {
	t.Helper()
	server := setupTestServer(t)
	server.certManager = newTLSTestCertManager(t)
	return server
}

func TestVerifyOperatorActionEnvelope_X509_ReturnsSerial(t *testing.T) {
	server := newActionX509Server(t)
	exp := time.Now().Add(3 * time.Minute)
	env := actionEnvelope(t, testAction(), []string{actionTestSteward}, "nonce-1", exp)
	proof, serial := signActionX509Bound(t, server, testSignerAccountID, env)

	got, err := server.verifyOperatorActionEnvelope(signerCtx(), actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
	require.NoError(t, err)
	assert.Equal(t, serial, got)
}

func TestVerifyOperatorActionEnvelope_X509_ChangedActionRefused(t *testing.T) {
	server := newActionX509Server(t)
	exp := time.Now().Add(3 * time.Minute)
	env := actionEnvelope(t, testAction(), []string{actionTestSteward}, "nonce-1", exp)
	proof, _ := signActionX509Bound(t, server, testSignerAccountID, env)

	other := testAction()
	other.Verb = "stop"
	_, err := server.verifyOperatorActionEnvelope(signerCtx(), actionTestSteward, other, env.Targets, env.Nonce, exp, *proof)
	require.Error(t, err)
}

func TestVerifyOperatorActionEnvelope_AdmissionWindowAndTargets(t *testing.T) {
	server := newActionX509Server(t)
	tests := []struct {
		name    string
		exp     time.Time
		targets []string
		steward string
	}{
		{"already expired", time.Now().Add(-time.Second), []string{actionTestSteward}, actionTestSteward},
		{"expiry beyond five minutes", time.Now().Add(operatorpayload.ActionEnvelopeMaxTTL + time.Minute), []string{actionTestSteward}, actionTestSteward},
		{"targets are a different steward", time.Now().Add(time.Minute), []string{"steward-2"}, actionTestSteward},
		{"targets include extra steward", time.Now().Add(time.Minute), []string{actionTestSteward, "steward-2"}, actionTestSteward},
		{"no addressed steward", time.Now().Add(time.Minute), []string{actionTestSteward}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := actionEnvelope(t, testAction(), tc.targets, "nonce-1", tc.exp)
			proof, _ := signActionX509Bound(t, server, testSignerAccountID, env)
			_, err := server.verifyOperatorActionEnvelope(signerCtx(), tc.steward, testAction(), tc.targets, env.Nonce, tc.exp, *proof)
			require.Error(t, err)
		})
	}
}

func TestVerifyOperatorActionEnvelope_X509_RevokedAndNonSigningCertRefused(t *testing.T) {
	server := newActionX509Server(t)
	exp := time.Now().Add(time.Minute)
	env := actionEnvelope(t, testAction(), []string{actionTestSteward}, "nonce-1", exp)

	t.Run("revoked", func(t *testing.T) {
		proof, serial := signActionX509Bound(t, server, testSignerAccountID, env)
		require.NoError(t, server.certManager.Revoke(serial))
		_, err := server.verifyOperatorActionEnvelope(signerCtx(), actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
	})
	t.Run("not a payload-signing certificate", func(t *testing.T) {
		proof, _ := signActionX509(t, server, env, nil)
		_, err := server.verifyOperatorActionEnvelope(signerCtx(), actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "payload-signing")
	})
}

func TestVerifyOperatorActionEnvelope_ProofMustCarryExactlyOneCredential(t *testing.T) {
	server := newActionX509Server(t)
	exp := time.Now().Add(time.Minute)
	env := actionEnvelope(t, testAction(), []string{actionTestSteward}, "nonce-1", exp)
	proof, _ := signActionX509Bound(t, server, testSignerAccountID, env)

	_, err := server.verifyOperatorActionEnvelope(signerCtx(), actionTestSteward, testAction(), env.Targets, env.Nonce, exp, OperatorProof{})
	require.Error(t, err)

	both := *proof
	both.WebAuthn = &OperatorWebAuthnProof{AuthenticatorData: []byte{1}, ClientDataJSON: []byte{1}, Signature: []byte{1}, CredentialID: []byte{1}}
	_, err = server.verifyOperatorActionEnvelope(signerCtx(), actionTestSteward, testAction(), env.Targets, env.Nonce, exp, both)
	require.Error(t, err)
}

// --- WebAuthn ---

// actionProof builds an operator WebAuthn proof for the fixture's credential: a real ES256
// assertion whose challenge is challengeHash, moved off the valid default by opts.
func actionProof(t *testing.T, priv *ecdsa.PrivateKey, credID []byte, challengeHash [sha256.Size]byte, opts ...webauthntest.Option) *OperatorWebAuthnProof {
	t.Helper()
	a := webauthntest.Assert(t, priv, credID, tvRPID, tvOrigin, base64.RawURLEncoding.EncodeToString(challengeHash[:]), opts...)
	return &OperatorWebAuthnProof{AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature, CredentialID: credID}
}

// webAuthnActionFixture is a WebAuthn-configured server with one account holding one
// real credential and the operator-payload:sign grant.
type webAuthnActionFixture struct {
	server    *Server
	username  string
	principal *Principal
	priv      *ecdsa.PrivateKey
	credID    []byte
}

func newWebAuthnActionFixture(t *testing.T) *webAuthnActionFixture {
	t.Helper()
	server, username := setupOperatorPayloadSignServer(t)
	credID := []byte("action-cred")
	priv, pub := generateSyntheticCredential(t)
	injectSignCredential(t, server, username, credID, pub, 0)
	setAccountGrant(t, server, username, true)
	return &webAuthnActionFixture{server: server, username: username, principal: principalForAccount(t, server, username), priv: priv, credID: credID}
}

func setAccountGrant(t *testing.T, server *Server, username string, grant bool) {
	t.Helper()
	acct, err := server.getAccount(context.Background(), username)
	require.NoError(t, err)
	acct.Permissions = nil
	if grant {
		acct.Permissions = []string{OperatorPayloadSignGrant}
	}
	require.NoError(t, server.persistAccount(context.Background(), acct, "test"))
	server.cacheAccount(acct)
}

func (f *webAuthnActionFixture) ctx() context.Context {
	return context.WithValue(context.Background(), principalContextKey, f.principal)
}

func (f *webAuthnActionFixture) proofFor(t *testing.T, env operatorpayload.Envelope, opts ...webauthntest.Option) OperatorProof {
	t.Helper()
	hash, err := operatorpayload.ChallengeHash(env)
	require.NoError(t, err)
	return OperatorProof{WebAuthn: actionProof(t, f.priv, f.credID, hash, opts...)}
}

func TestVerifyOperatorActionEnvelope_WebAuthn_ValidAssertion(t *testing.T) {
	f := newWebAuthnActionFixture(t)
	exp := time.Now().Add(3 * time.Minute)
	env := actionEnvelope(t, testAction(), []string{actionTestSteward}, "nonce-1", exp)

	got, err := f.server.verifyOperatorActionEnvelope(f.ctx(), actionTestSteward, testAction(), env.Targets, env.Nonce, exp, f.proofFor(t, env))
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(f.credID), got)
}

func TestVerifyOperatorActionEnvelope_WebAuthn_RefusalCases(t *testing.T) {
	exp := time.Now().Add(3 * time.Minute)
	targets := []string{actionTestSteward}

	t.Run("assertion over a different envelope", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		other := testAction()
		other.Verb = "stop"
		proof := f.proofFor(t, actionEnvelope(t, other, targets, "nonce-1", exp))
		_, err := f.server.verifyOperatorActionEnvelope(f.ctx(), actionTestSteward, testAction(), targets, "nonce-1", exp, proof)
		require.Error(t, err)
	})
	t.Run("credential not registered to the caller", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		env := actionEnvelope(t, testAction(), targets, "nonce-1", exp)
		proof := f.proofFor(t, env)
		proof.WebAuthn.CredentialID = []byte("someone-elses-cred")
		_, err := f.server.verifyOperatorActionEnvelope(f.ctx(), actionTestSteward, testAction(), targets, "nonce-1", exp, proof)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not registered")
	})
	t.Run("assertion signed by a key other than the stored one", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		forged, _ := generateSyntheticCredential(t)
		f.priv = forged
		env := actionEnvelope(t, testAction(), targets, "nonce-1", exp)
		_, err := f.server.verifyOperatorActionEnvelope(f.ctx(), actionTestSteward, testAction(), targets, "nonce-1", exp, f.proofFor(t, env))
		require.Error(t, err)
	})
	t.Run("account lacks the operator-payload:sign grant", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		setAccountGrant(t, f.server, f.username, false)
		env := actionEnvelope(t, testAction(), targets, "nonce-1", exp)
		_, err := f.server.verifyOperatorActionEnvelope(f.ctx(), actionTestSteward, testAction(), targets, "nonce-1", exp, f.proofFor(t, env))
		require.Error(t, err)
		assert.Contains(t, err.Error(), OperatorPayloadSignGrant)
	})
	t.Run("no authenticated principal", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		env := actionEnvelope(t, testAction(), targets, "nonce-1", exp)
		_, err := f.server.verifyOperatorActionEnvelope(context.Background(), actionTestSteward, testAction(), targets, "nonce-1", exp, f.proofFor(t, env))
		require.Error(t, err)
	})
	t.Run("unexpected origin", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		env := actionEnvelope(t, testAction(), targets, "nonce-1", exp)
		// Re-signed over the other origin, so the origin is the only thing wrong.
		proof := f.proofFor(t, env, webauthntest.WithOrigin("https://evil.example"))
		_, err := f.server.verifyOperatorActionEnvelope(f.ctx(), actionTestSteward, testAction(), targets, "nonce-1", exp, proof)
		require.Error(t, err)
	})
}

// TestVerifyOperatorActionEnvelope_WebAuthn_AfterSignCeremony drives the real
// sign/begin -> sign/finish ceremony, then verifies the same assertion: the verifier
// must not check or advance the sign count finish already advanced.
func TestVerifyOperatorActionEnvelope_WebAuthn_AfterSignCeremony(t *testing.T) {
	f := newWebAuthnActionFixture(t)
	content, err := operatorpayload.ActionContent(testAction())
	require.NoError(t, err)
	beginBody, err := json.Marshal(OperatorPayloadSignBeginRequest{Selector: "all", Content: content, Shell: operatorpayload.ActionShell})
	require.NoError(t, err)

	const sessID = "action-sess"
	beginRec := doSignBegin(t, f.server, f.principal, sessID, bytes.NewReader(beginBody))
	require.Equal(t, http.StatusOK, beginRec.Code, "body: %s", beginRec.Body.String())
	var begin struct {
		Data OperatorPayloadSignBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &begin))

	finishBody := webauthntest.Assert(t, f.priv, f.credID, tvRPID, tvOrigin, begin.Data.Assertion.Response.Challenge.String(), webauthntest.WithSignCount(1)).Reader()
	finishRec := doSignFinish(t, f.server, f.principal, sessID, finishBody)
	require.Equal(t, http.StatusOK, finishRec.Code, "body: %s", finishRec.Body.String())
	var finish struct {
		Data OperatorPayloadSignFinishResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(finishRec.Body.Bytes(), &finish))

	proof := OperatorProof{WebAuthn: &OperatorWebAuthnProof{
		AuthenticatorData: finish.Data.AuthenticatorData,
		ClientDataJSON:    finish.Data.ClientDataJSON,
		Signature:         finish.Data.Signature,
		CredentialID:      finish.Data.CredentialID,
	}}
	env := finish.Data.Envelope
	got, err := f.server.verifyOperatorActionEnvelope(f.ctx(), actionTestSteward, testAction(), env.Targets, env.Nonce, env.ExpiresAt, proof)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(f.credID), got)

	acct, err := f.server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	require.Len(t, acct.Credentials, 1)
	assert.Equal(t, uint32(1), acct.Credentials[0].SignCount, "the verifier must leave the sign count where finish put it")
}

// --- manifest ---

func TestBuildWebAuthnManifestForSteward_CarriesRosterAndSignature(t *testing.T) {
	f := newWebAuthnActionFixture(t)
	f.server.certManager = newTLSTestCertManager(t)
	ensureSharedSigningCertificate(t, f.server.certManager)
	acct, err := f.server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	acct.RootScope = true
	require.NoError(t, f.server.persistAccount(context.Background(), acct, "test"))
	f.server.cacheAccount(acct)
	require.NoError(t, f.server.controllerService.RegisterSteward(actionTestSteward, "client-1", "", "active"))

	manifestJSON, err := f.server.buildWebAuthnManifestForSteward(context.Background(), actionTestSteward)
	require.NoError(t, err)

	var signed SignedRevocationManifest
	require.NoError(t, json.Unmarshal([]byte(manifestJSON), &signed))
	assert.NotNil(t, signed.Signature)
	assert.NotEmpty(t, signed.SignerCertificatePEM)
	require.NotNil(t, signed.Manifest.WebAuthnRelyingParty)
	assert.Equal(t, tvRPID, signed.Manifest.WebAuthnRelyingParty.ID)
	require.Len(t, signed.Manifest.AuthorizedWebAuthnCredentials, 1)
	assert.Equal(t, f.credID, signed.Manifest.AuthorizedWebAuthnCredentials[0].CredentialID)
}

func TestBuildWebAuthnManifestForSteward_UnknownStewardRefused(t *testing.T) {
	f := newWebAuthnActionFixture(t)
	f.server.certManager = newTLSTestCertManager(t)
	_, err := f.server.buildWebAuthnManifestForSteward(context.Background(), "no-such-steward")
	require.Error(t, err)
}

// --- X.509 binding to the authenticated principal ---

func TestVerifyOperatorActionEnvelope_X509_BoundToTheAuthenticatedPrincipal(t *testing.T) {
	server := newActionX509Server(t)
	exp := time.Now().Add(3 * time.Minute)
	env := actionEnvelope(t, testAction(), []string{actionTestSteward}, "nonce-1", exp)
	proof, serial := signActionX509Bound(t, server, "acct-a", env)
	seedOperatorAccount(t, server, "acct-b", true)

	verifyAs := func(p *Principal) (string, error) {
		return server.verifyOperatorActionEnvelope(ctxWithPrincipal(p), actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
	}

	t.Run("owner is accepted", func(t *testing.T) {
		got, err := verifyAs(&Principal{ID: "acct-a", AccountBound: true})
		require.NoError(t, err)
		assert.Equal(t, serial, got)
	})
	t.Run("another account is refused with the serial for the audit", func(t *testing.T) {
		got, err := verifyAs(&Principal{ID: "acct-b", AccountBound: true})
		require.Error(t, err)
		assert.Equal(t, serial, got, "the serial accompanies a binding refusal so it can be audited")
		assert.Equal(t, "signing certificate is not bound to the dispatching principal", operatorCertBindingReason(err))
	})
	t.Run("a different session of the owning account is accepted: binding is the account ID, not the name", func(t *testing.T) {
		_, err := verifyAs(&Principal{ID: "acct-a", Name: "a-completely-different-display-name", Channel: AuthChannelWebCookie, AccountBound: true})
		require.NoError(t, err)
	})
	t.Run("principal that is not account-bound is refused", func(t *testing.T) {
		_, err := verifyAs(&Principal{ID: "acct-a", AccountBound: false})
		require.Error(t, err)
		assert.NotEmpty(t, operatorCertBindingReason(err))
	})
	t.Run("no principal in the context is refused", func(t *testing.T) {
		_, err := server.verifyOperatorActionEnvelope(context.Background(), actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
		require.Error(t, err)
		assert.NotEmpty(t, operatorCertBindingReason(err))
	})
	t.Run("the account named by the certificate no longer exists", func(t *testing.T) {
		_, err := verifyAs(&Principal{ID: "acct-a", AccountBound: true})
		require.NoError(t, err)
		other := newActionX509Server(t) // a server that has never heard of acct-a
		other.certManager = server.certManager
		_, err = other.verifyOperatorActionEnvelope(ctxWithPrincipal(&Principal{ID: "acct-a", AccountBound: true}),
			actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
		require.Error(t, err)
		assert.NotEmpty(t, operatorCertBindingReason(err))
	})
}

func TestVerifyOperatorActionEnvelope_X509_OwnerAuthorityIsRecheckedPerRequest(t *testing.T) {
	exp := time.Now().Add(3 * time.Minute)
	env := actionEnvelope(t, testAction(), []string{actionTestSteward}, "nonce-1", exp)

	for name, mutate := range map[string]func(*account){
		"disabled":      func(a *account) { a.Disabled = true },
		"grant removed": func(a *account) { a.Permissions = nil },
	} {
		t.Run(name, func(t *testing.T) {
			server := newActionX509Server(t)
			proof, _ := signActionX509Bound(t, server, "acct-a", env)
			ctx := ctxWithPrincipal(&Principal{ID: "acct-a", AccountBound: true})
			_, err := server.verifyOperatorActionEnvelope(ctx, actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
			require.NoError(t, err, "sanity: accepted while authorized")

			acct, err := server.getAccountByID(context.Background(), "acct-a")
			require.NoError(t, err)
			mutate(acct)
			require.NoError(t, server.persistAccount(context.Background(), acct, "test"))
			server.cacheAccount(acct)

			_, err = server.verifyOperatorActionEnvelope(ctx, actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
			require.Error(t, err)
			assert.Contains(t, operatorCertBindingReason(err), OperatorPayloadSignGrant)
		})
	}

	t.Run("root-scope account holds the grant implicitly", func(t *testing.T) {
		server := newActionX509Server(t)
		acct := &account{ID: "acct-root", Username: "user-acct-root", RootScope: true, CreatedAt: time.Now()}
		require.NoError(t, server.persistAccount(context.Background(), acct, "test"))
		server.cacheAccount(acct)
		proof, _ := signActionX509(t, server, env, boundSigningMarker("acct-root"))
		_, err := server.verifyOperatorActionEnvelope(ctxWithPrincipal(&Principal{ID: "acct-root", AccountBound: true}),
			actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
		require.NoError(t, err)
	})
}

func TestVerifyOperatorActionEnvelope_X509_CertificateWithoutBindingRefused(t *testing.T) {
	server := newActionX509Server(t)
	seedOperatorAccount(t, server, "acct-a", true)
	exp := time.Now().Add(3 * time.Minute)
	env := actionEnvelope(t, testAction(), []string{actionTestSteward}, "nonce-1", exp)
	proof, serial := signActionX509(t, server, env, cert.SetPayloadSigningMarker) // marker only, as issued before the binding existed

	got, err := server.verifyOperatorActionEnvelope(ctxWithPrincipal(&Principal{ID: "acct-a", AccountBound: true}),
		actionTestSteward, testAction(), env.Targets, env.Nonce, exp, *proof)
	require.Error(t, err)
	assert.Equal(t, serial, got)
	assert.Equal(t, "signing certificate is not bound to an account", operatorCertBindingReason(err))
}
