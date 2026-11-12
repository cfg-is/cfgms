// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/operatorroster"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// testSignerAccountID is the account the test operator certificates are bound to.
const testSignerAccountID = "acct-test-operator"

// boundPayloadSigning issues a payload-signing certificate bound to testSignerAccountID, the
// shape handleRequestSigningCredential issues. A payload-signing certificate without the
// binding is refused by the steward, so every test that expects acceptance uses this.
func boundPayloadSigning(template *x509.Certificate) {
	cert.SetPayloadSigningMarker(template)
	if err := cert.SetAccountBinding(template, testSignerAccountID); err != nil {
		panic(err) // a constant, valid account ID: unreachable
	}
}

// rosterManifestForTest is the test's own statement of the manifest the controller signs,
// including the X.509 signer roster, declared independently of the production mirror
// (revocationManifestPayload) so a field the mirror drops fails strict verification instead of
// cancelling out on both sides.
type rosterManifestForTest struct {
	Kind                  string                                `json:"kind"`
	Version               int64                                 `json:"version"`
	IssuedAt              time.Time                             `json:"issued_at"`
	RevokedSerials        []string                              `json:"revoked_serials"`
	AuthorizedX509Signers []operatorroster.AuthorizedX509Signer `json:"authorized_x509_signers,omitempty"`
}

// rootScopeSignerEntry is the roster entry the controller builds for a root-scope account
// that holds operator-payload:sign and owns signer.
func rootScopeSignerEntry(signer *cert.Certificate) operatorroster.AuthorizedX509Signer {
	return operatorroster.AuthorizedX509Signer{
		Kind:      operatorroster.AuthorizedX509SignerKind,
		Serial:    signer.SerialNumber,
		AccountID: testSignerAccountID,
		RootScope: true,
		Grants:    []string{operatorPayloadSignGrant},
	}
}

// signRosterManifest signs a manifest carrying signers with a CodeSigning certificate issued by
// ca, exactly as the controller's signRevocationManifest does, and returns the served bytes.
func signRosterManifest(t *testing.T, ca *cert.CA, version int64, issuedAt time.Time, revoked []string, signers ...operatorroster.AuthorizedX509Signer) []byte {
	t.Helper()
	if revoked == nil {
		revoked = []string{}
	}
	manifest := rosterManifestForTest{
		Kind: "operator-cert-revocation", Version: version, IssuedAt: issuedAt.UTC().Truncate(time.Second),
		RevokedSerials: revoked, AuthorizedX509Signers: signers,
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	signingCert := sigTestManifestSigningCert(t, ca)
	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: signingCert.CertificatePEM, PrivateKeyPEM: signingCert.PrivateKeyPEM,
	})
	require.NoError(t, err)
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	out, err := json.Marshal(struct {
		Manifest             rosterManifestForTest      `json:"manifest"`
		Signature            *signature.ConfigSignature `json:"signature"`
		SignerCertificatePEM string                     `json:"signer_certificate_pem"`
	}{manifest, sig, string(signingCert.CertificatePEM)})
	require.NoError(t, err)
	return out
}

// newRosterVerifier returns a RevocationVerifier that has strictly verified a fresh manifest
// listing signers.
func newRosterVerifier(t *testing.T, ca *cert.CA, caPool *x509.CertPool, signers ...operatorroster.AuthorizedX509Signer) *operatorroster.RevocationVerifier {
	t.Helper()
	v := operatorroster.NewRevocationVerifier(caPool)
	require.NoError(t, v.VerifyManifest(signRosterManifest(t, ca, 1, time.Now(), nil, signers...), stewardtypes.ModuleTrustModeStrict))
	return v
}

// authorizeOperators gives h a verified roster authorizing signers as root-scope operators
// holding operator-payload:sign, so envelope verification reaches the checks under test.
func authorizeOperators(t *testing.T, h *Handler, ca *cert.CA, caPool *x509.CertPool, signers ...*cert.Certificate) {
	t.Helper()
	entries := make([]operatorroster.AuthorizedX509Signer, 0, len(signers))
	for _, signer := range signers {
		entries = append(entries, rootScopeSignerEntry(signer))
	}
	h.revocationVerifier = newRosterVerifier(t, ca, caPool, entries...)
}

func testAction() operatorpayload.Action {
	return operatorpayload.Action{
		Verb:       "restart",
		TargetKind: "service",
		TargetName: "nginx",
		Parameters: map[string]string{"grace": "30s", "mode": "graceful"},
	}
}

func testActionContent(t *testing.T, a operatorpayload.Action) []byte {
	t.Helper()
	content, err := operatorpayload.ActionContent(a)
	require.NoError(t, err)
	return content
}

// signedActionParams builds the command params carrying an X.509-signed action
// envelope (Shell = ActionShell) signed by an operator payload-signing certificate.
func signedActionParams(t *testing.T, signer *cert.Certificate, content []byte, targets []string, nonce string, expiresAt time.Time) map[string]interface{} {
	t.Helper()
	params := sigTestOperatorEnvelopeParams(t, signer.PrivateKeyPEM, string(signer.CertificatePEM), content, operatorpayload.ActionShell, "unused")
	env := operatorpayload.Envelope{Content: content, Shell: operatorpayload.ActionShell, Targets: targets, Nonce: nonce, ExpiresAt: expiresAt}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)
	params["signature_value"] = sigTestSignWithCert(t, signer.PrivateKeyPEM, canonical)
	params["targets"] = targets
	params["nonce"] = nonce
	params["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	delete(params, "script_content")
	delete(params, "shell")
	return params
}

func envelopeCmd(params map[string]interface{}) *cpTypes.Command {
	return &cpTypes.Command{ID: "cmd-1", StewardID: "steward-test", Params: params}
}

func TestVerifyOperatorEnvelope_X509ActionAccepted(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	h := newHandlerWithSigning(t, nil, true, caPool)
	authorizeOperators(t, h, ca, caPool, signer)

	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	require.NoError(t, h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell))
}

func TestVerifyOperatorEnvelope_X509TamperedActionRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)

	orig := testAction()
	tampered := map[string]func(*operatorpayload.Action){
		"verb":        func(a *operatorpayload.Action) { a.Verb = "stop" },
		"target name": func(a *operatorpayload.Action) { a.TargetName = "sshd" },
		"target kind": func(a *operatorpayload.Action) { a.TargetKind = "package" },
		"parameter":   func(a *operatorpayload.Action) { a.Parameters = map[string]string{"grace": "0s", "mode": "graceful"} },
		"added param": func(a *operatorpayload.Action) {
			a.Parameters = map[string]string{"grace": "30s", "mode": "graceful", "x": "y"}
		},
		"removed para": func(a *operatorpayload.Action) { a.Parameters = map[string]string{"mode": "graceful"} },
	}
	for name, mutate := range tampered {
		t.Run(name, func(t *testing.T) {
			h := newHandlerWithSigning(t, nil, true, caPool)
			authorizeOperators(t, h, ca, caPool, signer)
			signed := testActionContent(t, orig)
			params := signedActionParams(t, signer, signed, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))

			changed := testAction()
			mutate(&changed)
			err := h.verifyOperatorEnvelope(envelopeCmd(params), testActionContent(t, changed), operatorpayload.ActionShell)
			require.ErrorIs(t, err, ErrUnauthenticatedCommand)
		})
	}
}

func TestVerifyOperatorEnvelope_TargetsOmitStewardRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	h := newHandlerWithSigning(t, nil, true, caPool)
	authorizeOperators(t, h, ca, caPool, signer)

	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"other-steward"}, sigTestNonce(t), time.Now().Add(time.Minute))
	err := h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "not in the signed target list")
}

func TestVerifyOperatorEnvelope_ExpiredRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	h := newHandlerWithSigning(t, nil, true, caPool)
	authorizeOperators(t, h, ca, caPool, signer)

	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(-time.Minute))
	err := h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "expired")
}

func TestVerifyOperatorEnvelope_ReusedNonceRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	h := newHandlerWithSigning(t, nil, true, caPool)
	authorizeOperators(t, h, ca, caPool, signer)

	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	require.NoError(t, h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell))

	err := h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "nonce already used")
}

func TestVerifyOperatorEnvelope_NoCredentialRejected(t *testing.T) {
	h := newHandlerWithSigning(t, nil, true, nil)
	err := h.verifyOperatorEnvelope(envelopeCmd(map[string]interface{}{}), []byte("x"), operatorpayload.ActionShell)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
}

// TestVerifyOperatorEnvelope_StewardActionNoCARootsRefused is a [REQUIRED TEST] for
// Issue #5356: a steward_action envelope is refused under nil roots and under an empty
// pool, even though its signature verifies, and the refusal leaves the nonce unconsumed
// (the same envelope is accepted once the CA is configured).
func TestVerifyOperatorEnvelope_StewardActionNoCARootsRefused(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	content := testActionContent(t, testAction())

	for name, roots := range map[string]*x509.CertPool{"nil roots": nil, "empty pool": x509.NewCertPool()} {
		t.Run(name, func(t *testing.T) {
			h := newHandlerWithSigning(t, nil, true, roots)
			params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))

			err := h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
			require.ErrorIs(t, err, ErrUnauthenticatedCommand)

			// Nonce not consumed: with roots configured the same envelope verifies.
			h.controllerCARoots = caPool
			authorizeOperators(t, h, ca, caPool, signer)
			require.NoError(t, h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell))
		})
	}
}

func TestVerifyOperatorEnvelope_WebAuthnActionAccepted(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-action-001")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})
	h := newHandlerWithSigning(t, nil, true, caPool)

	content := testActionContent(t, testAction())
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, operatorpayload.ActionShell,
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	require.NoError(t, h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell))

	// A changed verb under the same assertion fails.
	changed := testAction()
	changed.Verb = "stop"
	params2 := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, operatorpayload.ActionShell,
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	err := h.verifyOperatorEnvelope(envelopeCmd(params2), testActionContent(t, changed), operatorpayload.ActionShell)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
}

// A captured, valid action envelope re-sent as EXECUTE_SCRIPT is refused before any
// verification or execution, by the explicit shell reject in preflightScriptSignature.
func TestExecuteScript_ActionEnvelopeReplayedAsScriptRefused(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	h := newHandlerWithSigning(t, nil, true, caPool)
	authorizeOperators(t, h, ca, caPool, signer)

	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	params["script_content"] = base64.StdEncoding.EncodeToString(content)
	params["shell"] = operatorpayload.ActionShell
	params["execution_id"] = "replay-001"

	err := h.preflightScriptSignature(envelopeCmd(params))
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "reserved for steward actions")

	// Refused before verification: the nonce was never consumed.
	assert.True(t, h.envelopeNonceCache.Add(params["nonce"].(string)))

	sc := testSignedCommandWithParams("replay-001", cpTypes.CommandExecuteScript, params)
	require.ErrorIs(t, h.HandleCommand(context.Background(), sc), ErrUnauthenticatedCommand)
}

// The shell is part of the signed bytes: a script envelope does not verify as an
// action, and an action envelope does not verify as a script.
func TestVerifyOperatorEnvelope_CrossUseRefused(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)

	t.Run("script envelope refused as action", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		authorizeOperators(t, h, ca, caPool, signer)
		content := []byte(echoScriptBody("hi"))
		params := sigTestOperatorEnvelopeParams(t, signer.PrivateKeyPEM, string(signer.CertificatePEM), content, platformShell(), "steward-test")
		err := h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	})

	t.Run("action envelope refused by inline script path", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		authorizeOperators(t, h, ca, caPool, signer)
		content := testActionContent(t, testAction())
		params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
		params["script_content"] = base64.StdEncoding.EncodeToString(content)
		params["shell"] = platformShell() // swap the shell: signature covers ActionShell
		err := h.preflightScriptSignature(envelopeCmd(params))
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	})
}

// A captured, valid terminal-open envelope re-sent as EXECUTE_SCRIPT is refused before
// any verification or execution.
func TestExecuteScript_TerminalEnvelopeReplayedAsScriptRefused(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	h := newHandlerWithSigning(t, nil, true, caPool)
	authorizeOperators(t, h, ca, caPool, signer)

	content, err := operatorpayload.TerminalContent("steward-test", platformShell())
	require.NoError(t, err)
	params := terminalParams(t, signer, content, operatorpayload.TerminalShell, []string{"steward-test"}, time.Now().Add(time.Minute))
	params["script_content"] = base64.StdEncoding.EncodeToString(content)
	params["shell"] = operatorpayload.TerminalShell
	params["execution_id"] = "replay-term-001"

	err = h.preflightScriptSignature(envelopeCmd(params))
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "reserved for terminal sessions")

	// Refused before verification: the nonce was never consumed.
	assert.True(t, h.envelopeNonceCache.Add(params["nonce"].(string)))

	sc := testSignedCommandWithParams("replay-term-001", cpTypes.CommandExecuteScript, params)
	require.ErrorIs(t, h.HandleCommand(context.Background(), sc), ErrUnauthenticatedCommand)
}

// signedContextParams builds X.509-signed inline-script envelope params whose signed
// envelope carries signedContext, with no execution_context param delivered.
func signedContextParams(t *testing.T, signer *cert.Certificate, content []byte, shell, signedContext string) map[string]interface{} {
	t.Helper()
	targets := []string{"steward-test"}
	nonce := sigTestNonce(t)
	expiresAt := time.Now().Add(time.Minute)
	params := sigTestOperatorEnvelopeParamsFull(t, signer.PrivateKeyPEM, string(signer.CertificatePEM), content, shell, targets, nonce, expiresAt)
	env := operatorpayload.Envelope{Content: content, Shell: shell, Targets: targets, Nonce: nonce, ExpiresAt: expiresAt, ExecutionContext: signedContext}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)
	params["signature_value"] = sigTestSignWithCert(t, signer.PrivateKeyPEM, canonical)
	return params
}

// TestVerifyOperatorEnvelope_ExecutionContextBound proves the delivered
// execution_context must equal the signed one.
func TestVerifyOperatorEnvelope_ExecutionContextBound(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	content := []byte("echo hi")

	tests := []struct {
		name      string
		signed    string
		delivered interface{} // nil = absent
		wantErr   bool
	}{
		{"match", "logged_in_user", "logged_in_user", false},
		{"signed user delivered system", "logged_in_user", "system", true},
		{"signed user delivered absent", "logged_in_user", nil, true},
		{"signed user delivered other", "logged_in_user", "root", true},
		{"signed empty delivered system", "", "system", true},
		{"signed empty delivered absent", "", nil, false},
		{"signed empty delivered empty", "", "", false},
		{"non-string", "", 42, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandlerWithSigning(t, nil, true, caPool)
			authorizeOperators(t, h, ca, caPool, signer)
			params := signedContextParams(t, signer, content, "bash", tc.signed)
			if tc.delivered != nil {
				params["execution_context"] = tc.delivered
			}
			err := h.verifyOperatorEnvelope(envelopeCmd(params), content, "bash")
			if tc.wantErr {
				require.ErrorIs(t, err, ErrUnauthenticatedCommand)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- X.509 signer binding and roster (the steward half of the account binding) ---

// verifyActionAs signs a steward-action envelope with signer and verifies it on h.
func verifyActionAs(t *testing.T, h *Handler, signer *cert.Certificate) error {
	t.Helper()
	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	return h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
}

// A payload-signing certificate with no account binding is refused even when the roster lists
// its serial: every signer must trace to an account, with no unbound fallback.
func TestVerifyOperatorEnvelope_X509UnboundCertificateRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	legacy := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker) // marker only, as issued before the binding existed
	h := newHandlerWithSigning(t, nil, true, caPool)
	authorizeOperators(t, h, ca, caPool, legacy)

	err := verifyActionAs(t, h, legacy)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "not bound to an account")
}

func TestVerifyOperatorEnvelope_X509SignerAbsentFromRosterRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	other := sigTestOperatorCert(t, ca, boundPayloadSigning)

	t.Run("roster lists a different certificate", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		authorizeOperators(t, h, ca, caPool, other)
		err := verifyActionAs(t, h, signer)
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
		assert.Contains(t, err.Error(), "not in the authorized signer roster")
	})
	t.Run("empty roster", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		authorizeOperators(t, h, ca, caPool)
		require.ErrorIs(t, verifyActionAs(t, h, signer), ErrUnauthenticatedCommand)
	})
	t.Run("no revocation verifier configured", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		h.revocationVerifier = nil
		err := verifyActionAs(t, h, signer)
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
		assert.Contains(t, err.Error(), "requires a revocation verifier")
	})
	t.Run("no manifest verified yet", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		h.revocationVerifier = operatorroster.NewRevocationVerifier(caPool)
		err := verifyActionAs(t, h, signer)
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
		require.ErrorIs(t, err, operatorroster.ErrRevocationStateUnknown)
	})
}

// The roster owner and the certificate's own binding must agree: an entry for the serial that
// names another account does not authorize a certificate bound to this one.
func TestVerifyOperatorEnvelope_X509RosterEntryForAnotherAccountRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	entry := rootScopeSignerEntry(signer)
	entry.AccountID = "acct-someone-else"

	h := newHandlerWithSigning(t, nil, true, caPool)
	h.revocationVerifier = newRosterVerifier(t, ca, caPool, entry)
	err := verifyActionAs(t, h, signer)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "different owning account")
}

// The owner lost operator-payload:sign after issuance: an entry without the grant authorizes
// nothing, and an account that was disabled is simply absent from the next roster.
func TestVerifyOperatorEnvelope_X509OwnerLostGrantRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)

	t.Run("entry without the grant", func(t *testing.T) {
		entry := rootScopeSignerEntry(signer)
		entry.Grants = []string{"some:other-grant"}
		h := newHandlerWithSigning(t, nil, true, caPool)
		h.revocationVerifier = newRosterVerifier(t, ca, caPool, entry)
		err := verifyActionAs(t, h, signer)
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
		assert.Contains(t, err.Error(), "not granted")
	})
	t.Run("newer roster drops the signer", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		now := time.Now()
		h.revocationVerifier = operatorroster.NewRevocationVerifier(caPool)
		require.NoError(t, h.revocationVerifier.VerifyManifest(signRosterManifest(t, ca, 1, now.Add(-time.Minute), nil, rootScopeSignerEntry(signer)), stewardtypes.ModuleTrustModeStrict))
		require.NoError(t, verifyActionAs(t, h, signer), "sanity: authorized while listed")

		require.NoError(t, h.revocationVerifier.VerifyManifest(signRosterManifest(t, ca, 1, now, nil), stewardtypes.ModuleTrustModeStrict))
		require.ErrorIs(t, verifyActionAs(t, h, signer), ErrUnauthenticatedCommand)
	})
}

func TestVerifyOperatorEnvelope_X509RosterTenantMustCoverSteward(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	tenantEntry := func(tenant string, covered ...string) operatorroster.AuthorizedX509Signer {
		e := rootScopeSignerEntry(signer)
		e.RootScope, e.TenantID, e.CoveredTenantIDs = false, tenant, covered
		return e
	}

	tests := []struct {
		name          string
		stewardTenant string
		entry         operatorroster.AuthorizedX509Signer
		wantErr       string
	}{
		{"own tenant", "tenant-a", tenantEntry("tenant-a"), ""},
		{"covered descendant tenant", "tenant-a-child", tenantEntry("tenant-a", "tenant-a-child"), ""},
		{"other tenant", "tenant-b", tenantEntry("tenant-a", "tenant-a-child"), "does not cover this steward"},
		{"steward with no tenant", "", tenantEntry("tenant-a"), "does not cover this steward"},
		{"entry with no tenant and not root scope", "tenant-a", tenantEntry(""), "does not cover this steward"},
		{"root scope entry covers any tenant", "tenant-b", rootScopeSignerEntry(signer), ""},
		{"root scope entry that also names a tenant covers nothing", "tenant-a", func() operatorroster.AuthorizedX509Signer {
			e := rootScopeSignerEntry(signer)
			e.TenantID = "tenant-a"
			return e
		}(), "does not cover this steward"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandlerWithSigning(t, nil, true, caPool)
			h.tenantID = tc.stewardTenant
			h.revocationVerifier = newRosterVerifier(t, ca, caPool, tc.entry)
			err := verifyActionAs(t, h, signer)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrUnauthenticatedCommand)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestVerifyOperatorEnvelope_X509StaleRosterRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)

	t.Run("older than the freshness bound", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		h.revocationVerifier = operatorroster.NewRevocationVerifier(caPool)
		stale := time.Now().Add(-webauthnManifestMaxAge - time.Minute)
		require.NoError(t, h.revocationVerifier.VerifyManifest(signRosterManifest(t, ca, 1, stale, nil, rootScopeSignerEntry(signer)), stewardtypes.ModuleTrustModeStrict))
		err := verifyActionAs(t, h, signer)
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
		assert.Contains(t, err.Error(), "freshness window")
	})
	t.Run("just inside the freshness bound", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		h.revocationVerifier = operatorroster.NewRevocationVerifier(caPool)
		fresh := time.Now().Add(-webauthnManifestMaxAge + time.Minute)
		require.NoError(t, h.revocationVerifier.VerifyManifest(signRosterManifest(t, ca, 1, fresh, nil, rootScopeSignerEntry(signer)), stewardtypes.ModuleTrustModeStrict))
		require.NoError(t, verifyActionAs(t, h, signer))
	})
	t.Run("an older manifest cannot roll the roster back", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		h.revocationVerifier = operatorroster.NewRevocationVerifier(caPool)
		now := time.Now()
		require.NoError(t, h.revocationVerifier.VerifyManifest(signRosterManifest(t, ca, 1, now, nil), stewardtypes.ModuleTrustModeStrict))
		// A captured, still-fresh manifest that lists the signer must not displace the newer roster.
		require.NoError(t, h.revocationVerifier.VerifyManifest(signRosterManifest(t, ca, 1, now.Add(-2*time.Minute), nil, rootScopeSignerEntry(signer)), stewardtypes.ModuleTrustModeStrict))
		require.ErrorIs(t, verifyActionAs(t, h, signer), ErrUnauthenticatedCommand)
	})
}

// A certificate listed in the roster is still refused once revoked: the revocation list and the
// roster are independent checks and both must pass.
func TestVerifyOperatorEnvelope_X509RevokedSignerStillRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	h := newHandlerWithSigning(t, nil, true, caPool)
	h.revocationVerifier = operatorroster.NewRevocationVerifier(caPool)
	require.NoError(t, h.revocationVerifier.VerifyManifest(
		signRosterManifest(t, ca, 1, time.Now(), []string{signer.SerialNumber}, rootScopeSignerEntry(signer)), stewardtypes.ModuleTrustModeStrict))

	err := verifyActionAs(t, h, signer)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "revoked")
}

// The roster is only ever taken from a manifest whose signature the steward verified: in
// controller mode an unverifiable manifest still carries revocations but yields no roster.
func TestVerifyOperatorEnvelope_X509RosterFromUnverifiableManifestRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	rogueCA, _ := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, boundPayloadSigning)
	h := newHandlerWithSigning(t, nil, true, caPool)
	h.revocationVerifier = operatorroster.NewRevocationVerifier(caPool)
	require.NoError(t, h.revocationVerifier.VerifyManifest(
		signRosterManifest(t, rogueCA, 1, time.Now(), nil, rootScopeSignerEntry(signer)), stewardtypes.ModuleTrustModeController))

	err := verifyActionAs(t, h, signer)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "no verified operator signer roster")
}
