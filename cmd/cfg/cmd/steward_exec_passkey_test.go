// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/softauthn"
)

const (
	passkeyExecRunID   = "run-passkey-1"
	passkeyExecCommand = "echo passkey"
	passkeyExecShell   = "bash"
)

// passkeyBeginView is the begin response data this test controller sends.
type passkeyBeginView struct {
	Assertion    *protocol.CredentialAssertion `json:"assertion"`
	Envelope     passkeySignedEnvelope         `json:"envelope"`
	EnvelopeHash string                        `json:"envelope_hash"`
}

// passkeyExecController is a test controller for `cfg steward exec --passkey`. It
// runs the real sign ceremony (go-webauthn BeginLogin with the envelope's challenge
// hash, then full assertion verification) and verifies the proof on
// POST /api/v1/runs/command against the envelope rebuilt from that request, the way
// features/controller/api does. Login, CSRF and logout are delegated to the
// webLoginServer of the fixture the authenticator is registered against.
type passkeyExecController struct {
	t     *testing.T
	srv   *httptest.Server
	url   string
	login *webLoginServer
	auth  *softauthn.Authenticator

	targets []StewardInfo

	// beginMutate edits the begin response before it is sent (nil: honest).
	beginMutate func(resp *passkeyBeginView)
	// tamperProof makes finish return a proof signed for a different envelope.
	tamperProof bool
	// beginStatus, when set, makes begin answer this status with beginError.
	beginStatus int
	beginError  string

	mu            sync.Mutex
	pending       map[string]operatorpayload.Envelope // session cookie -> envelope awaiting finish
	beginBodies   [][]byte
	dispatchBody  []byte
	dispatchError string
	begins        int
	finishes      int
	dispatches    int
}

func newPasskeyExecController(t *testing.T, targets []StewardInfo) *passkeyExecController {
	t.Helper()
	c := &passkeyExecController{
		t:       t,
		targets: targets,
		pending: map[string]operatorpayload.Envelope{},
	}
	c.srv = httptest.NewUnstartedServer(http.HandlerFunc(c.serve))
	tlsCert, _ := newLocalhostTLSCert(t)
	c.srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}
	c.srv.StartTLS()
	t.Cleanup(c.srv.Close)
	c.url = strings.Replace(c.srv.URL, "127.0.0.1", "localhost", 1)
	return c
}

func (c *passkeyExecController) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.srv.Certificate().Raw}))
}

func (c *passkeyExecController) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/v1/web/"):
		c.login.serve(w, r)
		return
	}
	session, ok := c.authenticate(w, r)
	if !ok {
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
		writeRunAPIResponse(w, c.targets)
	case r.Method == http.MethodPost && r.URL.Path == operatorPayloadSignBeginPath:
		c.begin(w, r, session)
	case r.Method == http.MethodPost && r.URL.Path == operatorPayloadSignFinishPath:
		c.finish(w, r, session)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runs/command":
		c.dispatch(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runs/"+passkeyExecRunID:
		writeRunAPIResponse(w, map[string]interface{}{
			"run_id": passkeyExecRunID, "status": "completed",
			"job_count": len(c.targets), "completed_jobs": len(c.targets), "failed_jobs": 0,
		})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runs/"+passkeyExecRunID+"/jobs":
		jobs := make([]map[string]interface{}, 0, len(c.targets))
		for _, m := range c.targets {
			jobs = append(jobs, map[string]interface{}{
				"job_id": "job-" + m.ID, "device_id": m.ID, "status": "completed", "output": "passkey\n", "exit_code": 0,
			})
		}
		writeRunAPIResponse(w, jobs)
	default:
		http.NotFound(w, r)
	}
}

// authenticate requires a live web session and, on unsafe methods, its CSRF token.
func (c *passkeyExecController) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	c.login.mu.Lock()
	defer c.login.mu.Unlock()
	session, ok := c.login.session(r)
	if !ok {
		c.login.fail(w, http.StatusUnauthorized, "Session expired or invalid")
		return "", false
	}
	if r.Method != http.MethodGet && !c.login.csrfOK(r, session) {
		c.login.fail(w, http.StatusForbidden, "CSRF token mismatch")
		return "", false
	}
	return session, true
}

func (c *passkeyExecController) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// verifyProof runs the controller's assertion verification of proof over envelope.
func (c *passkeyExecController) verifyProof(envelope operatorpayload.Envelope, proof passkeyWebAuthnProof) error {
	hash, err := operatorpayload.ChallengeHash(envelope)
	if err != nil {
		return err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id": b64(proof.CredentialID), "rawId": b64(proof.CredentialID), "type": "public-key",
		"response": map[string]string{
			"authenticatorData": b64(proof.AuthenticatorData),
			"clientDataJSON":    b64(proof.ClientDataJSON),
			"signature":         b64(proof.Signature),
		},
	})
	require.NoError(c.t, err)
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return err
	}
	wa := c.login.wa
	creds := c.login.user.creds
	if len(creds) == 0 || !bytes.Equal(creds[0].ID, proof.CredentialID) {
		return assert.AnError
	}
	return parsed.Verify(b64(hash[:]), wa.Config.RPID, "", wa.Config.RPOrigins, nil, nil,
		protocol.TopOriginImplicitVerificationMode, false, true, true, creds[0].PublicKey, wa.Config.Signature)
}

func (c *passkeyExecController) begin(w http.ResponseWriter, r *http.Request, session string) {
	var req struct {
		Selector         string `json:"selector"`
		Content          []byte `json:"content"`
		Shell            string `json:"shell"`
		ExecutionContext string `json:"execution_context"`
	}
	raw := readAll(c.t, r)
	require.NoError(c.t, json.Unmarshal(raw, &req))

	c.mu.Lock()
	defer c.mu.Unlock()
	c.begins++
	c.beginBodies = append(c.beginBodies, raw)
	if c.beginStatus != 0 {
		c.writeError(w, c.beginStatus, c.beginError)
		return
	}

	targets := make([]string, 0, len(c.targets))
	for _, m := range c.targets {
		targets = append(targets, m.ID)
	}
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	require.NoError(c.t, err)
	envelope := operatorpayload.Envelope{
		Content: req.Content, Shell: req.Shell, Targets: targets,
		Nonce: hex.EncodeToString(nonce), ExpiresAt: time.Now().Add(5 * time.Minute),
		ExecutionContext: req.ExecutionContext,
	}
	hash, err := operatorpayload.ChallengeHash(envelope)
	require.NoError(c.t, err)
	assertion, _, err := c.login.wa.BeginLogin(c.login.user,
		webauthn.WithUserVerification(protocol.VerificationRequired), webauthn.WithChallenge(hash[:]))
	require.NoError(c.t, err)
	c.pending[session] = envelope

	resp := &passkeyBeginView{
		Assertion: assertion,
		Envelope: passkeySignedEnvelope{
			Content: envelope.Content, Shell: envelope.Shell, Targets: envelope.Targets,
			Nonce: envelope.Nonce, ExpiresAt: envelope.ExpiresAt, ExecutionContext: envelope.ExecutionContext,
		},
		EnvelopeHash: hex.EncodeToString(hash[:]),
	}
	if c.beginMutate != nil {
		c.beginMutate(resp)
	}
	writeRunAPIResponse(w, resp)
}

func (c *passkeyExecController) finish(w http.ResponseWriter, r *http.Request, session string) {
	body := readAll(c.t, r)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.finishes++
	envelope, ok := c.pending[session]
	delete(c.pending, session)
	if !ok {
		c.writeError(w, http.StatusBadRequest, "No active sign session")
		return
	}
	if c.tamperProof {
		body = c.proofForOtherEnvelope(envelope)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	require.NoError(c.t, err)
	proof := passkeyWebAuthnProof{
		AuthenticatorData: []byte(parsed.Raw.AssertionResponse.AuthenticatorData),
		ClientDataJSON:    []byte(parsed.Raw.AssertionResponse.ClientDataJSON),
		Signature:         []byte(parsed.Raw.AssertionResponse.Signature),
		CredentialID:      parsed.RawID,
	}
	if !c.tamperProof {
		if err := c.verifyProof(envelope, proof); err != nil {
			c.writeError(w, http.StatusBadRequest, "WebAuthn verification failed")
			return
		}
	}
	writeRunAPIResponse(w, proof)
}

// proofForOtherEnvelope returns an assertion body signed by the registered
// authenticator over an envelope whose content differs from envelope's.
func (c *passkeyExecController) proofForOtherEnvelope(envelope operatorpayload.Envelope) []byte {
	other := envelope
	other.Content = []byte("tampered " + string(envelope.Content))
	hash, err := operatorpayload.ChallengeHash(other)
	require.NoError(c.t, err)
	opts, err := json.Marshal(protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{
		Challenge: hash[:], RelyingPartyID: "localhost",
	}})
	require.NoError(c.t, err)
	body, err := c.auth.Assert(opts)
	require.NoError(c.t, err)
	return body
}

func (c *passkeyExecController) dispatch(w http.ResponseWriter, r *http.Request) {
	raw := readAll(c.t, r)
	var req struct {
		Content   string                `json:"content"`
		Shell     string                `json:"shell"`
		Signature json.RawMessage       `json:"signature"`
		WebAuthn  *passkeyWebAuthnProof `json:"webauthn"`
		Targets   []string              `json:"targets"`
		Nonce     string                `json:"nonce"`
		ExpiresAt string                `json:"expires_at"`
	}
	require.NoError(c.t, json.Unmarshal(raw, &req))

	c.mu.Lock()
	defer c.mu.Unlock()
	c.dispatches++
	c.dispatchBody = raw

	switch {
	case len(req.Signature) > 0 && req.WebAuthn != nil:
		c.writeError(w, http.StatusBadRequest, "provide exactly one operator proof")
		return
	case req.WebAuthn == nil:
		c.writeError(w, http.StatusBadRequest, "ad-hoc execution requires an operator signature")
		return
	}
	content, err := base64.StdEncoding.DecodeString(req.Content)
	require.NoError(c.t, err)
	expires, err := time.Parse(time.RFC3339, req.ExpiresAt)
	require.NoError(c.t, err)
	err = c.verifyProof(operatorpayload.Envelope{
		Content: content, Shell: req.Shell, Targets: req.Targets, Nonce: req.Nonce, ExpiresAt: expires,
	}, *req.WebAuthn)
	if err != nil {
		c.dispatchError = err.Error()
		c.writeError(w, http.StatusBadRequest, "invalid operator signature")
		return
	}
	writeRunAPIResponse(w, map[string]string{"run_id": passkeyExecRunID})
}

func readAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	require.NoError(t, err)
	return buf.Bytes()
}

func (c *passkeyExecController) counts() (begins, finishes, dispatches int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.begins, c.finishes, c.dispatches
}

// newPasskeyExecEnv registers an authenticator against a login server, binds it to a
// passkeyExecController that serves targets, and points the exec globals at it.
func newPasskeyExecEnv(t *testing.T, targets []StewardInfo) *passkeyExecController {
	t.Helper()
	saveExecGlobals(t)
	origPasskey := stewardExecPasskey
	t.Cleanup(func() { stewardExecPasskey = origPasskey })

	ctl := newPasskeyExecController(t, targets)
	f := newWebLoginFixture(t, func(rec *authenticatorRecord, _ *webLoginServer) {
		rec.ControllerURL = ctl.url
		rec.CACertPEM = ctl.caPEM()
	})
	ctl.login = f.webLoginServer
	rec, err := loadRegisteredAuthenticator(context.Background(), f.name)
	require.NoError(t, err)
	ctl.auth, err = rec.authenticator()
	require.NoError(t, err)

	stewardURL = ""
	stewardTLSInsecure = false
	stewardExecCommand = passkeyExecCommand
	stewardExecShell = passkeyExecShell
	stewardExecTimeout = 30 * time.Second
	stewardExecPasskey = true
	runWaitPollInterval = time.Millisecond
	return ctl
}

func oneStewardTarget() []StewardInfo {
	return []StewardInfo{{ID: "host-abc", DNA: &StewardInfoDNA{Hostname: "host-abc"}}}
}

// rechallenge makes the begin response's challenge match its (mutated) envelope, so
// a test isolates the one field it changed.
func rechallenge(t *testing.T, resp *passkeyBeginView) {
	t.Helper()
	hash, err := operatorpayload.ChallengeHash(resp.Envelope.envelope())
	require.NoError(t, err)
	resp.Assertion.Response.Challenge = hash[:]
}

func TestExecPasskey_FlagRegisteredAndOffByDefault(t *testing.T) {
	f := stewardExecCmd.Flags().Lookup("passkey")
	require.NotNil(t, f, "exec must have --passkey")
	assert.Equal(t, "false", f.DefValue)
	assert.Contains(t, f.Usage, "--authenticator")
}

// Required: against a controller running the real sign ceremony and run-command proof
// verification, the dispatch succeeds with a webauthn object and no signature, and no
// execution_context anywhere in the sign or dispatch requests.
func TestExecPasskey_DispatchesWebAuthnProofWithoutSignatureOrExecutionContext(t *testing.T) {
	ctl := newPasskeyExecEnv(t, oneStewardTarget())

	require.NoError(t, runRunCommandSingle(stewardExecCmd, []string{"host-abc"}))

	begins, finishes, dispatches := ctl.counts()
	assert.Equal(t, 1, begins)
	assert.Equal(t, 1, finishes)
	assert.Equal(t, 1, dispatches, "the controller verified the proof and accepted the dispatch")

	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(ctl.dispatchBody, &body))
	assert.NotContains(t, body, "signature", "exactly one proof: no X.509 signature")
	assert.NotContains(t, body, "execution_context", "the steward default execution context applies")
	require.Contains(t, body, "webauthn")

	var proof passkeyWebAuthnProof
	require.NoError(t, json.Unmarshal(body["webauthn"], &proof))
	assert.NotEmpty(t, proof.AuthenticatorData)
	assert.NotEmpty(t, proof.ClientDataJSON)
	assert.NotEmpty(t, proof.Signature)
	assert.NotEmpty(t, proof.CredentialID)

	var targets []string
	require.NoError(t, json.Unmarshal(body["targets"], &targets))
	assert.Equal(t, []string{"host-abc"}, targets)
	assert.Contains(t, body, "nonce")
	assert.Contains(t, body, "expires_at")
	assert.Contains(t, body, "timeout_seconds")

	require.Len(t, ctl.beginBodies, 1)
	assert.NotContains(t, string(ctl.beginBodies[0]), "execution_context")
}

func TestExecPasskey_MultiHostEnvelopeBindsEveryResolvedTarget(t *testing.T) {
	ctl := newPasskeyExecEnv(t, []StewardInfo{
		{ID: "host-a", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "host-b", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	})
	stewardYes = true

	require.NoError(t, runRunCommandSingle(stewardExecCmd, []string{"glob:host-*"}))

	var body struct {
		Targets []string `json:"targets"`
	}
	require.NoError(t, json.Unmarshal(ctl.dispatchBody, &body))
	assert.Equal(t, []string{"host-a", "host-b"}, body.Targets)
}

// Required: --passkey without --authenticator fails before any network call.
func TestExecPasskey_WithoutAuthenticatorFailsBeforeAnyNetworkCall(t *testing.T) {
	saveExecGlobals(t)
	origPasskey, origSel := stewardExecPasskey, authenticatorSelection
	t.Cleanup(func() { stewardExecPasskey, authenticatorSelection = origPasskey, origSel })

	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv(authenticatorEnvVar, "")
	authenticatorSelection = ""
	stewardURL = srv.URL
	stewardTLSInsecure = true
	stewardExecCommand = passkeyExecCommand
	stewardExecShell = passkeyExecShell
	stewardExecPasskey = true

	err := runRunCommandSingle(stewardExecCmd, []string{"host-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--passkey requires --authenticator")

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, requests, "no request may reach the controller")
}

func TestExecPasskey_CannotCombineWithSigningCredential(t *testing.T) {
	ctl := newPasskeyExecEnv(t, oneStewardTarget())
	signingCredentialSelector = "some-credential"

	err := runRunCommandSingle(stewardExecCmd, []string{"host-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--signing-credential")

	begins, finishes, dispatches := ctl.counts()
	assert.Zero(t, begins+finishes+dispatches)
}

// Required: a begin response whose command, shell, execution context, target set or
// challenge differs from what the CLI chose is refused client-side, and the sign
// finish endpoint is never called.
func TestExecPasskey_RefusesBeginResponseThatDiffersFromRequest(t *testing.T) {
	cases := map[string]struct {
		mutate  func(t *testing.T, resp *passkeyBeginView)
		wantErr string
	}{
		"different command": {
			mutate: func(t *testing.T, resp *passkeyBeginView) {
				resp.Envelope.Content = []byte("rm -rf /")
				rechallenge(t, resp)
			},
			wantErr: "content differs",
		},
		"different shell": {
			mutate: func(t *testing.T, resp *passkeyBeginView) {
				resp.Envelope.Shell = "sh"
				rechallenge(t, resp)
			},
			wantErr: "shell differs",
		},
		"execution context set": {
			mutate: func(t *testing.T, resp *passkeyBeginView) {
				resp.Envelope.ExecutionContext = "logged_in_user"
				rechallenge(t, resp)
			},
			wantErr: "execution context",
		},
		"extra target": {
			mutate: func(t *testing.T, resp *passkeyBeginView) {
				resp.Envelope.Targets = append(resp.Envelope.Targets, "host-other")
				rechallenge(t, resp)
			},
			wantErr: "did not resolve",
		},
		"no targets": {
			mutate: func(t *testing.T, resp *passkeyBeginView) {
				resp.Envelope.Targets = nil
			},
			wantErr: "no targets",
		},
		"non-matching challenge": {
			mutate: func(_ *testing.T, resp *passkeyBeginView) {
				flipped := append([]byte(nil), resp.Assertion.Response.Challenge...)
				flipped[0] ^= 0xff
				resp.Assertion.Response.Challenge = flipped
			},
			wantErr: "challenge does not match",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctl := newPasskeyExecEnv(t, oneStewardTarget())
			ctl.beginMutate = func(resp *passkeyBeginView) { tc.mutate(t, resp) }

			err := runRunCommandSingle(stewardExecCmd, []string{"host-abc"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "refusing to sign")
			assert.Contains(t, err.Error(), tc.wantErr)

			begins, finishes, dispatches := ctl.counts()
			assert.Equal(t, 1, begins)
			assert.Zero(t, finishes, "the authenticator must not sign: no finish call")
			assert.Zero(t, dispatches)
		})
	}
}

// Required: a proof for a different envelope is refused by the controller, and the
// CLI reports the controller's error.
func TestExecPasskey_ProofForDifferentEnvelopeRefusedByController(t *testing.T) {
	ctl := newPasskeyExecEnv(t, oneStewardTarget())
	ctl.tamperProof = true

	err := runRunCommandSingle(stewardExecCmd, []string{"host-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid operator signature")

	_, finishes, dispatches := ctl.counts()
	assert.Equal(t, 1, finishes)
	assert.Equal(t, 1, dispatches)
	assert.NotEmpty(t, ctl.dispatchError, "the controller's assertion verification rejected the proof")
}

func TestExecPasskey_SignBeginErrorIsReportedAndNothingDispatched(t *testing.T) {
	ctl := newPasskeyExecEnv(t, oneStewardTarget())
	ctl.beginStatus = http.StatusConflict
	ctl.beginError = "No WebAuthn credentials registered"

	err := runRunCommandSingle(stewardExecCmd, []string{"host-abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "passkey sign begin failed")
	assert.Contains(t, err.Error(), "No WebAuthn credentials registered")

	_, finishes, dispatches := ctl.counts()
	assert.Zero(t, finishes)
	assert.Zero(t, dispatches)
}

func TestExecPasskey_UnregisteredAuthenticatorFailsBeforeSignCeremony(t *testing.T) {
	ctl := newPasskeyExecEnv(t, oneStewardTarget())
	authenticatorSelection = "missing-authenticator"

	err := runRunCommandSingle(stewardExecCmd, []string{"host-abc"})
	require.Error(t, err)

	begins, _, _ := ctl.counts()
	assert.Zero(t, begins)
}

func TestCheckPasskeyBeginResponse_AcceptsHonestEnvelope(t *testing.T) {
	content := []byte("hostname")
	env := passkeySignedEnvelope{
		Content: content, Shell: "bash", Targets: []string{"a", "b"},
		Nonce: "n0nce", ExpiresAt: time.Now().Add(time.Minute),
	}
	hash, err := operatorpayload.ChallengeHash(env.envelope())
	require.NoError(t, err)
	opts, err := json.Marshal(protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{Challenge: hash[:]}})
	require.NoError(t, err)
	begin := &passkeySignBeginResponse{Assertion: opts, Envelope: env}

	require.NoError(t, checkPasskeyBeginResponse(begin, content, "bash", []string{"a", "b", "c"}))

	begin.Assertion = json.RawMessage(`{`)
	err = checkPasskeyBeginResponse(begin, content, "bash", []string{"a", "b"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed")
}
