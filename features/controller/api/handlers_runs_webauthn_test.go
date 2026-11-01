// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/session"
)

const runCmdContent = "hostname"

// newWebAuthnRunFixture returns a WebAuthn-configured server wired for run dispatch over two
// registered stewards, an account holding a real credential and the signing grant, and its principal.
func newWebAuthnRunFixture(t *testing.T) (*webAuthnActionFixture, *Principal, []string) {
	t.Helper()
	f := newWebAuthnActionFixture(t)
	ids := []string{"steward-1", "steward-2"}
	var results []fleet.StewardResult
	for _, id := range ids {
		require.NoError(t, f.server.controllerService.RegisterSteward(id, "client-"+id, "", "active"))
		results = append(results, fleet.StewardResult{ID: id})
	}
	f.server.SetRunManager(newTestRunManager(t), newTestRunQueue(t))
	f.server.fleetQuery = &staticRunFleetQuery{results: results}
	f.server.certManager = newTLSTestCertManager(t)
	ensureSharedSigningCertificate(t, f.server.certManager)

	acct, err := f.server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	acct.RootScope = true
	require.NoError(t, f.server.persistAccount(context.Background(), acct, "test"))
	f.server.cacheAccount(acct)

	p := &Principal{ID: acct.ID, Name: f.username, Assurance: session.AssuranceStrong, GlobalScope: true}
	return f, p, ids
}

// webAuthnRunBody builds the request body the web posts after sign/finish: the proof over
// env and the envelope fields unchanged.
func webAuthnRunBody(t *testing.T, f *webAuthnActionFixture, env operatorpayload.Envelope) map[string]interface{} {
	t.Helper()
	proof := f.proofFor(t, env).WebAuthn
	b64 := base64.StdEncoding.EncodeToString
	return map[string]interface{}{
		"target":  "id:steward-1,steward-2",
		"content": b64(env.Content),
		"shell":   env.Shell,
		"webauthn": map[string]interface{}{
			"authenticator_data": b64(proof.AuthenticatorData),
			"client_data_json":   b64(proof.ClientDataJSON),
			"signature":          b64(proof.Signature),
			"credential_id":      b64(proof.CredentialID),
		},
		"targets":    env.Targets,
		"nonce":      env.Nonce,
		"expires_at": env.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

func runCmdEnvelope(targets []string) operatorpayload.Envelope {
	return operatorpayload.Envelope{
		Content: []byte(runCmdContent), Shell: "bash", Targets: targets,
		Nonce: "run-nonce-1", ExpiresAt: time.Now().Add(3 * time.Minute).Truncate(time.Second),
	}
}

func TestRunCommand_WebAuthnProofForTwoTargetsQueuesOneCommandEach(t *testing.T) {
	f, p, ids := newWebAuthnRunFixture(t)
	env := runCmdEnvelope(ids)
	body := webAuthnRunBody(t, f, env)

	rec := postRunWithPrincipal(t, f.server.handlePostRunCommand, "/api/v1/runs/command", p, body)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	wa := body["webauthn"].(map[string]interface{})
	for _, id := range ids {
		queued := f.server.runExecutionQueue.PeekForDevice(id)
		require.Len(t, queued, 1, id)
		md := queued[0].Metadata
		assert.Equal(t, wa["authenticator_data"], md["webauthn_authenticator_data"])
		assert.Equal(t, wa["client_data_json"], md["webauthn_client_data_json"])
		assert.Equal(t, wa["signature"], md["webauthn_signature"])
		assert.Equal(t, wa["credential_id"], md["webauthn_credential_id"])
		assert.Equal(t, ids, md["targets"])
		assert.Equal(t, env.Nonce, md["nonce"])
		assert.Empty(t, md["signature_value"], "no X.509 signature is forwarded")

		want, err := f.server.buildWebAuthnManifestForSteward(context.Background(), id)
		require.NoError(t, err)
		var got, exp SignedRevocationManifest
		require.NoError(t, json.Unmarshal([]byte(md["webauthn_manifest"].(string)), &got), id)
		require.NoError(t, json.Unmarshal([]byte(want), &exp))
		assert.Equal(t, exp.Manifest.AuthorizedWebAuthnCredentials, got.Manifest.AuthorizedWebAuthnCredentials, id)
	}
}

func TestRunCommand_WebAuthnProofRefusedWhenRequestDiffersFromSignedEnvelope(t *testing.T) {
	f, p, ids := newWebAuthnRunFixture(t)
	post := func(mutate func(map[string]interface{})) {
		t.Helper()
		body := webAuthnRunBody(t, f, runCmdEnvelope(ids))
		mutate(body)
		rec := postRunWithPrincipal(t, f.server.handlePostRunCommand, "/api/v1/runs/command", p, body)
		require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
		assert.Contains(t, rec.Body.String(), "INVALID_SIGNATURE")
	}

	post(func(b map[string]interface{}) { b["targets"] = []string{"steward-1"} })
	post(func(b map[string]interface{}) { b["targets"] = []string{"steward-1", "steward-2", "steward-3"} })
	post(func(b map[string]interface{}) { b["content"] = base64.StdEncoding.EncodeToString([]byte("whoami")) })
	post(func(b map[string]interface{}) { b["shell"] = "sh" })
	post(func(b map[string]interface{}) { b["nonce"] = "other-nonce" })
	post(func(b map[string]interface{}) {
		b["expires_at"] = time.Now().Add(4 * time.Minute).UTC().Format(time.RFC3339)
	})
	post(func(b map[string]interface{}) {
		b["signature"] = map[string]interface{}{"algorithm": "a", "value": "v", "public_key": "k"}
	})
	post(func(b map[string]interface{}) { delete(b, "webauthn") })

	for _, id := range ids {
		assert.Empty(t, f.server.runExecutionQueue.PeekForDevice(id), "refused request must queue nothing")
	}
}

func TestRunCommand_WebAuthnProofRefusedWhenExpiredOrTooFar(t *testing.T) {
	f, p, ids := newWebAuthnRunFixture(t)
	for _, exp := range []time.Time{
		time.Now().Add(-time.Minute).Truncate(time.Second),
		time.Now().Add(operatorpayload.ActionEnvelopeMaxTTL + time.Hour).Truncate(time.Second),
	} {
		env := runCmdEnvelope(ids)
		env.ExpiresAt = exp
		rec := postRunWithPrincipal(t, f.server.handlePostRunCommand, "/api/v1/runs/command", p, webAuthnRunBody(t, f, env))
		require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
		assert.Contains(t, rec.Body.String(), "INVALID_SIGNATURE")
	}
	assert.Empty(t, f.server.runExecutionQueue.PeekForDevice("steward-1"))
}

func TestRunCommand_WebAuthnProofRefusedForAnotherAccountsCredential(t *testing.T) {
	f, _, ids := newWebAuthnRunFixture(t)
	other := &account{ID: "other-account-id", Username: "other-op", RootScope: true, Permissions: []string{OperatorPayloadSignGrant}, CreatedAt: time.Now()}
	require.NoError(t, f.server.persistAccount(context.Background(), other, "test"))
	f.server.cacheAccount(other)
	p := &Principal{ID: other.ID, Name: other.Username, Assurance: session.AssuranceStrong, GlobalScope: true}

	rec := postRunWithPrincipal(t, f.server.handlePostRunCommand, "/api/v1/runs/command", p, webAuthnRunBody(t, f, runCmdEnvelope(ids)))
	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "INVALID_SIGNATURE")
	assert.Empty(t, f.server.runExecutionQueue.PeekForDevice("steward-1"))
}

func TestRunCommand_BothOrNeitherProofRefused(t *testing.T) {
	f, p, ids := newWebAuthnRunFixture(t)
	body := webAuthnRunBody(t, f, runCmdEnvelope(ids))
	body["signature"] = map[string]interface{}{"algorithm": "a", "value": "v", "public_key": "k"}
	rec := postRunWithPrincipal(t, f.server.handlePostRunCommand, "/api/v1/runs/command", p, body)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_SIGNATURE")

	delete(body, "signature")
	delete(body, "webauthn")
	rec = postRunWithPrincipal(t, f.server.handlePostRunCommand, "/api/v1/runs/command", p, body)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_SIGNATURE")
}
