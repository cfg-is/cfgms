// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

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
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)
	h := newHandlerWithSigning(t, nil, true, caPool)

	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	require.NoError(t, h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell))
}

func TestVerifyOperatorEnvelope_X509TamperedActionRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)

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
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)
	h := newHandlerWithSigning(t, nil, true, caPool)

	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"other-steward"}, sigTestNonce(t), time.Now().Add(time.Minute))
	err := h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "not in the signed target list")
}

func TestVerifyOperatorEnvelope_ExpiredRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)
	h := newHandlerWithSigning(t, nil, true, caPool)

	content := testActionContent(t, testAction())
	params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(-time.Minute))
	err := h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "expired")
}

func TestVerifyOperatorEnvelope_ReusedNonceRejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)
	h := newHandlerWithSigning(t, nil, true, caPool)

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
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)
	h := newHandlerWithSigning(t, nil, true, caPool)

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
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)

	t.Run("script envelope refused as action", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		content := []byte(echoScriptBody("hi"))
		params := sigTestOperatorEnvelopeParams(t, signer.PrivateKeyPEM, string(signer.CertificatePEM), content, platformShell(), "steward-test")
		err := h.verifyOperatorEnvelope(envelopeCmd(params), content, operatorpayload.ActionShell)
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	})

	t.Run("action envelope refused by inline script path", func(t *testing.T) {
		h := newHandlerWithSigning(t, nil, true, caPool)
		content := testActionContent(t, testAction())
		params := signedActionParams(t, signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
		params["script_content"] = base64.StdEncoding.EncodeToString(content)
		params["shell"] = platformShell() // swap the shell: signature covers ActionShell
		err := h.preflightScriptSignature(envelopeCmd(params))
		require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	})
}
