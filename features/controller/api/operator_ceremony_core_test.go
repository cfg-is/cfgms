// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

func coreEnvelope(t *testing.T) operatorpayload.Envelope {
	t.Helper()
	// Already past: VerifyAssertion has no expiry check, so a stored Publication verifies.
	return actionEnvelope(t, testAction(), []string{actionTestSteward}, "core-nonce", time.Now().Add(-time.Hour))
}

func coreAccount(t *testing.T, f *webAuthnActionFixture) *account {
	t.Helper()
	acct, err := f.server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	return acct
}

func TestVerifyAssertion_ValidWithoutCallerOrExpiry(t *testing.T) {
	f := newWebAuthnActionFixture(t)
	env := coreEnvelope(t)
	proof := f.proofFor(t, env).WebAuthn

	// No principal in any context: the account is passed explicitly.
	cred, err := f.server.VerifyAssertion(coreAccount(t, f), env, proof)
	require.NoError(t, err)
	assert.Equal(t, f.credID, cred.ID)
}

func TestVerifyAssertion_Refusals(t *testing.T) {
	t.Run("key not registered to the account", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		env := coreEnvelope(t)
		forged, _ := generateSyntheticCredential(t)
		f.priv = forged
		_, err := f.server.VerifyAssertion(coreAccount(t, f), env, f.proofFor(t, env).WebAuthn)
		require.Error(t, err)
	})
	t.Run("credential id not on the account", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		env := coreEnvelope(t)
		proof := f.proofFor(t, env).WebAuthn
		proof.CredentialID = []byte("other-cred")
		_, err := f.server.VerifyAssertion(coreAccount(t, f), env, proof)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not registered")
	})
	t.Run("challenge differs from the envelope hash", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		env := coreEnvelope(t)
		other := env
		other.Nonce = "different"
		_, err := f.server.VerifyAssertion(coreAccount(t, f), env, f.proofFor(t, other).WebAuthn)
		require.Error(t, err)
	})
	t.Run("user verification unset", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		env := coreEnvelope(t)
		// UP only; re-signed so only the UV flag is wrong.
		hash, err := operatorpayload.ChallengeHash(env)
		require.NoError(t, err)
		proof := signActionAssertionFlags(t, f, hash, 0x01)
		_, err = f.server.VerifyAssertion(coreAccount(t, f), env, proof)
		require.Error(t, err)
	})
	t.Run("nil account", func(t *testing.T) {
		f := newWebAuthnActionFixture(t)
		env := coreEnvelope(t)
		_, err := f.server.VerifyAssertion(nil, env, f.proofFor(t, env).WebAuthn)
		require.Error(t, err)
	})
}

// signActionAssertionFlags is signActionAssertion with a caller-chosen authenticator
// flags byte.
func signActionAssertionFlags(t *testing.T, f *webAuthnActionFixture, hash [sha256.Size]byte, flags byte) *OperatorWebAuthnProof {
	t.Helper()
	p := signActionAssertion(t, f.priv, f.credID, hash)
	p.AuthenticatorData[32] = flags
	cdHash := sha256.Sum256(p.ClientDataJSON)
	digest := sha256.Sum256(append(append([]byte{}, p.AuthenticatorData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, f.priv, digest[:])
	require.NoError(t, err)
	p.Signature = sig
	return p
}

func TestVerifyAssertion_StillVerifiesAfterCredentialSignsAgain(t *testing.T) {
	f := newWebAuthnActionFixture(t)
	content, err := operatorpayload.ActionContent(testAction())
	require.NoError(t, err)
	beginBody, err := json.Marshal(OperatorPayloadSignBeginRequest{Selector: "all", Content: content, Shell: operatorpayload.ActionShell})
	require.NoError(t, err)

	sign := func(sessID string, count uint32) (int, OperatorPayloadSignFinishResponse) {
		beginRec := doSignBegin(t, f.server, f.principal, sessID, bytes.NewReader(beginBody))
		require.Equal(t, http.StatusOK, beginRec.Code, "body: %s", beginRec.Body.String())
		var begin struct {
			Data OperatorPayloadSignBeginResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &begin))
		body := buildSignAssertionBody(t, f.priv, f.credID, tvRPID, tvOrigin, begin.Data.Assertion.Response.Challenge.String(), count)
		rec := doSignFinish(t, f.server, f.principal, sessID, body)
		var finish struct {
			Data OperatorPayloadSignFinishResponse `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &finish)
		return rec.Code, finish.Data
	}

	code, first := sign("core-sess-1", 1)
	require.Equal(t, http.StatusOK, code)
	code, _ = sign("core-sess-2", 2)
	require.Equal(t, http.StatusOK, code)

	// The stored counter is now 2; the first (Publication-style) assertion still verifies.
	env := operatorpayload.Envelope{
		Content: first.Envelope.Content, Shell: first.Envelope.Shell, Targets: first.Envelope.Targets,
		Nonce: first.Envelope.Nonce, ExpiresAt: first.Envelope.ExpiresAt, ExecutionContext: first.Envelope.ExecutionContext,
	}
	proof := &OperatorWebAuthnProof{AuthenticatorData: first.AuthenticatorData, ClientDataJSON: first.ClientDataJSON, Signature: first.Signature, CredentialID: first.CredentialID}
	_, err = f.server.VerifyAssertion(coreAccount(t, f), env, proof)
	require.NoError(t, err)

	// The ceremony finish still refuses a non-advancing count (stored is 2).
	code, _ = sign("core-sess-3", 2)
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestSignCountAdvances(t *testing.T) {
	assert.True(t, signCountAdvances(0, 0), "both zero: authenticator without counter")
	assert.True(t, signCountAdvances(0, 1))
	assert.True(t, signCountAdvances(3, 4))
	assert.False(t, signCountAdvances(3, 3))
	assert.False(t, signCountAdvances(3, 2))
	assert.False(t, signCountAdvances(3, 0))
}

func TestWithAdvancedSignCount_DoesNotMutateSource(t *testing.T) {
	acct := &account{Credentials: []WebAuthnCredential{{ID: []byte("a"), SignCount: 1}, {ID: []byte("b"), SignCount: 5}}}
	updated := withAdvancedSignCount(acct, []byte("b"), 9)
	assert.Equal(t, uint32(5), acct.Credentials[1].SignCount)
	assert.Equal(t, uint32(9), updated.Credentials[1].SignCount)
	assert.Equal(t, uint32(1), updated.Credentials[0].SignCount)
	assert.Equal(t, uint32(9), storedSignCount(&updated, []byte("b")))
	assert.Equal(t, uint32(0), storedSignCount(&updated, []byte("zzz")))
}

func TestSignThrottleKeys(t *testing.T) {
	assert.Equal(t, "session:s1", signSessionThrottleKey("s1"))
	assert.Equal(t, "ip:1.2.3.4", signIPThrottleKey("1.2.3.4"))

	f := newWebAuthnActionFixture(t)
	for i := 0; i < 10; i++ {
		f.server.recordSignFailures("core-throttle", "")
	}
	blocked, _ := f.server.checkSignThrottle(signSessionThrottleKey("core-throttle"))
	assert.True(t, blocked)
	blocked, _ = f.server.checkSignThrottle(signIPThrottleKey(""))
	assert.False(t, blocked, "an empty IP key is never recorded")
}
