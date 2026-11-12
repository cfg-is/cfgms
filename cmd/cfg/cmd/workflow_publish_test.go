// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpkg "github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

const (
	publishTestTenant = "tenant-a"
	publishTestSigner = "account-1"
	publishTestName   = "nightly-patch"
	publishTestSemver = "1.2.0"
)

// publishPending is the ceremony state publish/begin leaves for publish/finish.
type publishPending struct {
	session webauthn.SessionData
	nonce   string
	expires time.Time
	hash    [32]byte
}

// publishServer extends the passkey-login test controller with the publish ceremony of
// features/controller/api/handlers_workflow_publish.go: begin issues a challenge equal
// to the ChallengeHash of the real workflow publication envelope, and finish rebuilds
// that envelope from the CURRENT stored version and verifies the assertion with the
// real go-webauthn login verification. It is guarded by the embedded server's mutex.
type publishServer struct {
	*webLoginFixture

	versions  map[string]*wfpkg.VersionedWorkflow
	pending   map[string]publishPending
	published []wfpkg.Publication

	policyOff         bool   // begin refuses with 403 PUBLISH_DISABLED
	editAfterBegin    bool   // the version is edited right after begin answers
	beginVersion      string // when set, begin names this version instead of the requested one
	finishHashFor     string // when set, finish reports this content hash
	begins, finishes  int
	issuedChallenges  [][]byte
	finishedOnVersion []string
}

func newPublishServer(t *testing.T) *publishServer {
	t.Helper()
	f := newWebLoginFixture(t, nil)
	ps := &publishServer{
		webLoginFixture: f,
		versions: map[string]*wfpkg.VersionedWorkflow{
			publishTestName + "@" + publishTestSemver: {
				Workflow:        wfpkg.Workflow{Name: publishTestName, Version: publishTestSemver, Steps: []wfpkg.Step{{Name: "patch", Type: wfpkg.StepTypeTask}}},
				SemanticVersion: wfpkg.SemanticVersion{Major: 1, Minor: 2},
			},
		},
		pending: map[string]publishPending{},
	}
	f.srv.Config.Handler = http.HandlerFunc(ps.serve)
	return ps
}

func (ps *publishServer) serve(w http.ResponseWriter, r *http.Request) {
	name, version, step, ok := splitPublishPath(r.URL.Path)
	if !ok || r.Method != http.MethodPost {
		ps.webLoginServer.serve(w, r)
		return
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.requests++
	session, live := ps.session(r)
	if !live {
		ps.fail(w, http.StatusUnauthorized, "Session expired or invalid")
		return
	}
	if !ps.csrfOK(r, session) {
		ps.fail(w, http.StatusForbidden, "CSRF token mismatch")
		return
	}
	switch step {
	case "begin":
		ps.begin(w, session, name, version)
	case "finish":
		ps.finish(w, r, session, name, version)
	default:
		http.NotFound(w, r)
	}
}

// splitPublishPath parses /api/v1/workflows/{id}/versions/{version}/publish/{step}.
func splitPublishPath(p string) (name, version, step string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) != 8 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "workflows" ||
		parts[4] != "versions" || parts[6] != "publish" {
		return "", "", "", false
	}
	return parts[3], parts[5], parts[7], true
}

func (ps *publishServer) apiError(w http.ResponseWriter, status int, code, message string) {
	ps.reply(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (ps *publishServer) stored(name, version string) *wfpkg.VersionedWorkflow {
	return ps.versions[name+"@"+version]
}

func (ps *publishServer) begin(w http.ResponseWriter, session, name, version string) {
	ps.begins++
	if ps.policyOff {
		ps.apiError(w, http.StatusForbidden, "PUBLISH_DISABLED", "Workflow publishing is disabled")
		return
	}
	vw := ps.stored(name, version)
	if vw == nil {
		ps.apiError(w, http.StatusNotFound, "NOT_FOUND", "workflow version not found")
		return
	}
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	expires := time.Now().Add(operatorpayload.WorkflowEnvelopeMaxTTL).UTC().Truncate(time.Second)
	envelope, contentHash, err := wfpkg.PublicationEnvelope(publishTestTenant, vw, nonce, expires)
	if err != nil {
		ps.apiError(w, http.StatusBadRequest, "INVALID_ENVELOPE", "Workflow version cannot be published")
		return
	}
	hash, err := operatorpayload.ChallengeHash(envelope)
	if err != nil {
		ps.apiError(w, http.StatusBadRequest, "INVALID_ENVELOPE", "Workflow version cannot be published")
		return
	}
	assertion, sd, err := ps.wa.BeginLogin(ps.user,
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithChallenge(hash[:]))
	if err != nil {
		ps.apiError(w, http.StatusInternalServerError, "WEBAUTHN_BEGIN_ERROR", "Failed to begin publish ceremony")
		return
	}
	ps.pending[session] = publishPending{session: *sd, nonce: nonce, expires: expires, hash: hash}
	ps.issuedChallenges = append(ps.issuedChallenges, hash[:])

	named := vw.SemanticVersion.String()
	if ps.beginVersion != "" {
		named = ps.beginVersion
	}
	ps.reply(w, http.StatusOK, map[string]any{"data": map[string]any{
		"assertion":    assertion,
		"name":         vw.Name,
		"version":      named,
		"content_hash": contentHash,
	}})
	if ps.editAfterBegin {
		vw.Steps[0].Name = "edited-after-begin"
	}
}

func (ps *publishServer) finish(w http.ResponseWriter, r *http.Request, session, name, version string) {
	ps.finishes++
	pending, ok := ps.pending[session]
	delete(ps.pending, session) // single use, whatever the outcome
	if !ok {
		ps.apiError(w, http.StatusBadRequest, "NO_ACTIVE_PUBLISH_SESSION", "No active publish session — call begin first")
		return
	}
	vw := ps.stored(name, version)
	if vw == nil {
		ps.apiError(w, http.StatusNotFound, "NOT_FOUND", "workflow version not found")
		return
	}
	envelope, contentHash, err := wfpkg.PublicationEnvelope(publishTestTenant, vw, pending.nonce, pending.expires)
	if err != nil {
		ps.apiError(w, http.StatusConflict, "INVALID_ENVELOPE", "Workflow version cannot be published")
		return
	}
	if rebuilt, err := operatorpayload.ChallengeHash(envelope); err != nil || rebuilt != pending.hash {
		ps.apiError(w, http.StatusConflict, "VERSION_CHANGED",
			"Workflow version changed since the publish ceremony began — restart with begin")
		return
	}
	// The assertion must verify over the challenge begin issued, under the account's
	// registered credential.
	if _, err := ps.wa.FinishLogin(ps.user, pending.session, r); err != nil {
		ps.apiError(w, http.StatusBadRequest, "WEBAUTHN_VERIFY_ERROR", "WebAuthn verification failed")
		return
	}
	ps.published = append(ps.published, wfpkg.Publication{
		ContentHash: contentHash, Nonce: pending.nonce, ExpiresAt: pending.expires,
		SignerAccountID: publishTestSigner, SignedAt: time.Now().UTC(),
	})
	ps.finishedOnVersion = append(ps.finishedOnVersion, vw.SemanticVersion.String())
	reported := contentHash
	if ps.finishHashFor != "" {
		reported = ps.finishHashFor
	}
	ps.reply(w, http.StatusOK, map[string]any{"data": map[string]any{
		"name":              vw.Name,
		"version":           vw.SemanticVersion.String(),
		"content_hash":      reported,
		"signer_account_id": publishTestSigner,
		"signed_at":         time.Now().UTC(),
	}})
}

// storedHash is the canonical hash of the stored version as the controller computes it.
func (ps *publishServer) storedHash(t *testing.T) string {
	t.Helper()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	h, err := wfpkg.CanonicalWorkflowHash(ps.stored(publishTestName, publishTestSemver))
	require.NoError(t, err)
	return h
}

func (ps *publishServer) counts() (begins, finishes int, published []wfpkg.Publication) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.begins, ps.finishes, append([]wfpkg.Publication(nil), ps.published...)
}

// runPublish executes `cfg workflow publish ...` through the root command, so flag
// parsing, the command's registration and cobra's finalizers (which end the web
// session) all run as they do for the shipped binary.
func runPublish(t *testing.T, args ...string) (string, error) {
	t.Helper()
	origURL, origServer, origJSON := workflowURL, workflowServerName, workflowPublishJSON
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append([]string{"workflow", "publish"}, args...))
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		workflowURL, workflowServerName, workflowPublishJSON = origURL, origServer, origJSON
	})
	err := rootCmd.Execute()
	return out.String(), err
}

func TestWorkflowPublishCmd_RegisteredOnWorkflowGroup(t *testing.T) {
	sub, _, err := workflowCmd.Find([]string{"publish"})
	require.NoError(t, err)
	assert.Same(t, workflowPublishCmd, sub)
	assert.Equal(t, "publish <id> <version>", sub.Use)
	for _, flag := range []string{"url", "server-name", "json"} {
		assert.NotNil(t, sub.Flags().Lookup(flag), "--%s must be a publish flag", flag)
	}
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("authenticator"), "--authenticator is inherited from the root command")
}

// Required: against a controller running real publish-ceremony verification, publish
// succeeds and the output carries name, version, content hash and signer.
func TestWorkflowPublish_SucceedsAndPrintsPublication(t *testing.T) {
	ps := newPublishServer(t)

	out, err := runPublish(t, publishTestName, publishTestSemver, "--authenticator", ps.name)
	require.NoError(t, err, out)

	hash := ps.storedHash(t)
	assert.Contains(t, out, publishTestName)
	assert.Contains(t, out, publishTestSemver)
	assert.Contains(t, out, hash, "the content hash of the published version is printed")
	assert.Contains(t, out, publishTestSigner)

	begins, finishes, published := ps.counts()
	assert.Equal(t, 1, begins)
	assert.Equal(t, 1, finishes)
	require.Len(t, published, 1, "the controller verified the assertion and stored one publication")
	assert.Equal(t, hash, published[0].ContentHash)

	// The login session did not outlive the command.
	_, _, logouts := ps.stats()
	assert.Equal(t, 1, logouts)
	for _, tok := range ps.sessionTokens() {
		assert.Equal(t, http.StatusUnauthorized, ps.replay(t, tok), "the session is revoked once the command ends")
	}
}

// The assertion is made over the begin challenge as issued: the controller verified it
// against the ChallengeHash of the publication envelope it built at begin.
func TestWorkflowPublish_AssertionIsOverTheIssuedChallenge(t *testing.T) {
	ps := newPublishServer(t)

	out, err := runPublish(t, publishTestName, publishTestSemver, "--authenticator", ps.name)
	require.NoError(t, err, out)

	ps.mu.Lock()
	defer ps.mu.Unlock()
	require.Len(t, ps.issuedChallenges, 1)
	require.Len(t, ps.published, 1, "finish verified the assertion over the challenge begin issued")
}

func TestWorkflowPublish_JSONOutput(t *testing.T) {
	ps := newPublishServer(t)

	out, err := runPublish(t, publishTestName, publishTestSemver, "--authenticator", ps.name, "--json")
	require.NoError(t, err, out)

	var got workflowPublishResult
	require.NoError(t, json.Unmarshal([]byte(out), &got), out)
	assert.Equal(t, publishTestName, got.Name)
	assert.Equal(t, publishTestSemver, got.Version)
	assert.Equal(t, ps.storedHash(t), got.ContentHash)
	assert.Equal(t, publishTestSigner, got.SignerAccountID)
	assert.False(t, got.SignedAt.IsZero())
}

func TestWorkflowPublish_AuthenticatorFromEnvironment(t *testing.T) {
	ps := newPublishServer(t)
	authenticatorSelection = ""
	t.Setenv(authenticatorEnvVar, ps.name)

	out, err := runPublish(t, publishTestName, publishTestSemver)
	require.NoError(t, err, out)
	_, _, published := ps.counts()
	assert.Len(t, published, 1)
}

// Required: without --authenticator the command fails before any network call.
func TestWorkflowPublish_RequiresAuthenticatorBeforeAnyNetworkCall(t *testing.T) {
	ps := newPublishServer(t)
	authenticatorSelection = ""
	t.Setenv(authenticatorEnvVar, "")
	before, _, _ := ps.stats()

	out, err := runPublish(t, publishTestName, publishTestSemver, "--url", ps.url)
	require.Error(t, err, out)
	assert.ErrorIs(t, err, errWorkflowPublishNeedsAuthenticator)
	assert.Contains(t, err.Error(), "--authenticator")
	assert.Contains(t, err.Error(), "passkey", "the error names the passkey web session requirement")

	after, _, _ := ps.stats()
	assert.Equal(t, before, after, "no request reached the controller")
	begins, _, _ := ps.counts()
	assert.Zero(t, begins)
}

// A refusal that needs no controller: nothing is sent for an invalid name or version,
// or for an authenticator that is not registered.
func TestWorkflowPublish_RefusesBeforeAnyNetworkCall(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"invalid workflow name", []string{"bad name!", publishTestSemver, "--authenticator", "agent-1"}, "workflow name"},
		{"invalid version", []string{publishTestName, "latest", "--authenticator", "agent-1"}, "MAJOR.MINOR.PATCH"},
		{"unknown authenticator", []string{publishTestName, publishTestSemver, "--authenticator", "nobody"}, "nobody"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPublishServer(t)
			out, err := runPublish(t, tc.args...)
			require.Error(t, err, out)
			assert.Contains(t, err.Error(), tc.want)
			requests, _, _ := ps.stats()
			assert.Zero(t, requests, "no request reached the controller")
		})
	}
}

// Required: a server refusal exits non-zero (the command returns an error) carrying
// the server's code, and nothing is published.
func TestWorkflowPublish_ServerRefusals(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(ps *publishServer)
		version  string
		wantCode string
		finishes int
	}{
		{
			name:     "publish policy off",
			setup:    func(ps *publishServer) { ps.policyOff = true },
			version:  publishTestSemver,
			wantCode: "PUBLISH_DISABLED",
			finishes: 0,
		},
		{
			name:     "version changed between begin and finish",
			setup:    func(ps *publishServer) { ps.editAfterBegin = true },
			version:  publishTestSemver,
			wantCode: "VERSION_CHANGED",
			finishes: 1,
		},
		{
			name:     "version not stored",
			setup:    func(ps *publishServer) {},
			version:  "9.9.9",
			wantCode: "NOT_FOUND",
			finishes: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPublishServer(t)
			tc.setup(ps)

			out, err := runPublish(t, publishTestName, tc.version, "--authenticator", ps.name)
			require.Error(t, err, out)
			assert.Contains(t, err.Error(), tc.wantCode, "the error carries the server's code")
			assert.NotContains(t, out, "Workflow published")

			_, finishes, published := ps.counts()
			assert.Equal(t, tc.finishes, finishes)
			assert.Empty(t, published, "a refused ceremony publishes nothing")

			_, _, logouts := ps.stats()
			assert.Equal(t, 1, logouts, "the session ends even when the publish is refused")
		})
	}
}

// The command never signs a challenge the controller issued for a different version
// than the one the operator named.
func TestWorkflowPublish_RefusesToSignForADifferentVersion(t *testing.T) {
	ps := newPublishServer(t)
	ps.beginVersion = "1.2.1"

	out, err := runPublish(t, publishTestName, publishTestSemver, "--authenticator", ps.name)
	require.Error(t, err, out)
	assert.Contains(t, err.Error(), "1.2.1")

	_, finishes, published := ps.counts()
	assert.Zero(t, finishes, "no assertion was submitted")
	assert.Empty(t, published)
}

// A finish that reports a content hash other than the one begin announced is not
// reported as a success.
func TestWorkflowPublish_RefusesInconsistentFinishHash(t *testing.T) {
	ps := newPublishServer(t)
	ps.finishHashFor = strings.Repeat("0", 64)

	out, err := runPublish(t, publishTestName, publishTestSemver, "--authenticator", ps.name)
	require.Error(t, err, out)
	assert.Contains(t, err.Error(), "inconsistent")
	assert.NotContains(t, out, "Workflow published")
}

func TestWorkflowPublishStepError(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"code and message", `{"error":{"code":"FORBIDDEN","message":"Insufficient permissions"}}`, "publish refused at begin (status 403): FORBIDDEN: Insufficient permissions"},
		{"code only", `{"error":{"code":"THROTTLED"}}`, "publish refused at begin (status 403): THROTTLED"},
		{"plain string error", `{"error":"nope"}`, "publish refused at begin (status 403): nope"},
		{"not json", `<html>`, "publish refused at begin (status 403)"},
		{"empty", ``, "publish refused at begin (status 403)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.EqualError(t, workflowPublishStepError("begin", http.StatusForbidden, []byte(tc.body)), tc.want)
		})
	}

	t.Run("server text cannot forge log lines", func(t *testing.T) {
		body := `{"error":{"code":"X","message":"line one\nINFO forged entry"}}`
		err := workflowPublishStepError("finish", http.StatusConflict, []byte(body))
		assert.NotContains(t, err.Error(), "\n")
	})
}

func TestDecodeWorkflowPublishStep_MalformedResponses(t *testing.T) {
	for _, body := range []string{``, `not json`, `{}`, `{"data":"a string"}`} {
		rec := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
		var out workflowPublishResult
		err := decodeWorkflowPublishStep("finish", rec, &out)
		require.Error(t, err, "body %q", body)
		assert.Contains(t, err.Error(), "malformed")
	}
}

func TestWorkflowPublishPath_EscapesSegments(t *testing.T) {
	assert.Equal(t, "/api/v1/workflows/wf/versions/1.2.0/publish/begin", workflowPublishPath("wf", "1.2.0", "begin"))
	assert.Equal(t, "/api/v1/workflows/a%2Fb/versions/1.0.0/publish/finish", workflowPublishPath("a/b", "1.0.0", "finish"))
}
