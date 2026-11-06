// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
//
// Tests for the workflow publish ceremony (ADR-036 section 4). They drive the real
// handlers with a synthetic ECDSA P-256 authenticator: a real keypair whose COSE public key
// is the only thing the account stores, and real signatures over the server's challenge.
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
)

const publishTenant = "tenant-a"

type publishFixture struct {
	server   *Server
	handler  *WorkflowHandler
	store    *workflow.WorkflowStore
	username string
	priv     *ecdsa.PrivateKey
	credID   []byte
	counter  uint32
	nextSess int
}

func newPublishFixture(t *testing.T) *publishFixture {
	t.Helper()
	server, _ := setupWebAuthnServer(t, tvRPID, []string{tvOrigin})
	const username = "publisher"
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username:    username,
		TenantID:    publishTenant,
		Permissions: []string{workflow.PublishPermission},
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	priv, pubKey := generateSyntheticCredential(t)
	credID := []byte("publish-cred")
	injectSignCredential(t, server, username, credID, pubKey, 0)

	h, configStore := newTestWorkflowHandler(t)
	server.workflowHandler = h
	return &publishFixture{
		server: server, handler: h, username: username, priv: priv, credID: credID,
		store: workflow.NewWorkflowStore(configStore, publishTenant),
	}
}

func publishTestWorkflow(version string) *workflow.VersionedWorkflow {
	sv, err := workflow.ParseSemanticVersion(version)
	if err != nil {
		panic(err)
	}
	return &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{
			Name:    "publish-wf",
			Version: version,
			Steps:   []workflow.Step{{Name: "step1", Type: workflow.StepTypeTask}},
		},
		SemanticVersion: *sv,
	}
}

func (f *publishFixture) seed(t *testing.T, version string) *workflow.VersionedWorkflow {
	t.Helper()
	vw := publishTestWorkflow(version)
	require.NoError(t, f.store.StoreWorkflow(context.Background(), vw))
	return vw
}

func (f *publishFixture) principal(t *testing.T, tenant string) *Principal {
	return &Principal{ID: testAccountID(t, f.server, f.username), TenantID: tenant}
}

// call invokes publish/begin or publish/finish as the fixture account.
func (f *publishFixture) call(t *testing.T, step, version, sessID, tenant string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/publish-wf/versions/"+version+"/publish/"+step, body)
	req = withPrincipal(req, f.principal(t, tenant))
	req = mux.SetURLVars(req, map[string]string{"id": "publish-wf", "version": version})
	req = req.WithContext(context.WithValue(req.Context(), webSessionIDContextKey, sessID))
	rec := httptest.NewRecorder()
	if step == "begin" {
		f.server.handleWorkflowPublishBegin(rec, req)
	} else {
		f.server.handleWorkflowPublishFinish(rec, req)
	}
	return rec
}

func (f *publishFixture) begin(t *testing.T, version, sessID string) string {
	t.Helper()
	rec := f.call(t, "begin", version, sessID, publishTenant, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data WorkflowPublishBeginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data.Assertion.Response.Challenge.String()
}

func (f *publishFixture) assertion(t *testing.T, challenge string, flags byte) *bytes.Reader {
	f.counter++
	return buildSignAssertionBodyFlags(t, f.priv, f.credID, tvRPID, tvOrigin, challenge, f.counter, flags)
}

// publish runs a full begin and finish and returns the finish response.
func (f *publishFixture) publish(t *testing.T, version string) *httptest.ResponseRecorder {
	t.Helper()
	f.nextSess++
	sess := "publish-sess-" + string(rune('a'+f.nextSess))
	challenge := f.begin(t, version, sess)
	return f.call(t, "finish", version, sess, publishTenant, f.assertion(t, challenge, 0x05))
}

func (f *publishFixture) stored(t *testing.T, version string) *workflow.VersionedWorkflow {
	t.Helper()
	sv, err := workflow.ParseSemanticVersion(version)
	require.NoError(t, err)
	vw, err := f.store.GetWorkflow(context.Background(), "publish-wf", *sv)
	require.NoError(t, err)
	return vw
}

func (f *publishFixture) verify(t *testing.T, vw *workflow.VersionedWorkflow) error {
	return f.server.VerifyWorkflowPublication(context.Background(), publishTenant, vw)
}

func (f *publishFixture) publishedVersion(t *testing.T, version string) *workflow.VersionedWorkflow {
	t.Helper()
	f.seed(t, version)
	rec := f.publish(t, version)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	vw := f.stored(t, version)
	require.NotNil(t, vw.Publication)
	return vw
}

func (f *publishFixture) mutateAccount(t *testing.T, fn func(*account)) {
	t.Helper()
	acct, err := f.server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	fn(acct)
	require.NoError(t, f.server.persistAccount(context.Background(), acct, "test-mutator"))
	f.server.cacheAccount(acct)
}

func TestWorkflowPublish_BeginFinishStoresPublicationOnExactVersion(t *testing.T) {
	f := newPublishFixture(t)
	f.seed(t, "1.0.0")
	f.seed(t, "1.0.1")

	rec := f.publish(t, "1.0.0")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var raw struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	for _, forbidden := range []string{"nonce", "challenge", "assertion", "session", "envelope", "expires_at", "signature"} {
		assert.NotContains(t, raw.Data, forbidden, "finish must not return ceremony state")
	}

	published := f.stored(t, "1.0.0")
	require.NotNil(t, published.Publication)
	acct, err := f.server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	assert.Equal(t, acct.ID, published.Publication.SignerAccountID)
	assert.NoError(t, f.verify(t, published))
	assert.Nil(t, f.stored(t, "1.0.1").Publication, "only the addressed version is published")
	assert.Equal(t, uint32(1), acct.Credentials[0].SignCount, "the sign count advances")
}

func TestWorkflowPublish_AssertionDoesNotVerifyForOtherVersionOrEditedDefinition(t *testing.T) {
	f := newPublishFixture(t)
	published := f.publishedVersion(t, "1.0.0")

	other := publishTestWorkflow("1.0.1")
	other.Publication = published.Publication
	assert.Error(t, f.verify(t, other), "an assertion for 1.0.0 must not verify for 1.0.1")

	edited := f.stored(t, "1.0.0")
	edited.Steps[0].Name = "edited"
	assert.Error(t, f.verify(t, edited), "an assertion must not verify for an edited definition")
}

func TestWorkflowPublish_FinishReplayFailsAndSignCountMustAdvance(t *testing.T) {
	f := newPublishFixture(t)
	f.seed(t, "1.0.0")

	challenge := f.begin(t, "1.0.0", "replay-sess")
	body := f.assertion(t, challenge, 0x05)
	raw := body.Size()
	buf := make([]byte, raw)
	_, _ = body.ReadAt(buf, 0)
	require.Equal(t, http.StatusOK, f.call(t, "finish", "1.0.0", "replay-sess", publishTenant, bytes.NewReader(buf)).Code)

	replay := f.call(t, "finish", "1.0.0", "replay-sess", publishTenant, bytes.NewReader(buf))
	assert.Equal(t, http.StatusBadRequest, replay.Code, "the ceremony is single use")

	// A fresh ceremony whose assertion reuses the stored sign count is a cloned authenticator.
	challenge = f.begin(t, "1.0.0", "clone-sess")
	f.counter--
	stale := f.call(t, "finish", "1.0.0", "clone-sess", publishTenant, f.assertion(t, challenge, 0x05))
	assert.Equal(t, http.StatusBadRequest, stale.Code, "a sign count that does not advance is refused")
}

func TestWorkflowPublish_UsesOnlyTheRegisteredPublicKey(t *testing.T) {
	src, err := os.ReadFile("handlers_workflow_publish.go")
	require.NoError(t, err)
	for _, banned := range []string{"PrivateKey", "GenerateKey", "ecdsa.Sign", "ed25519.Sign", "rsa.Sign"} {
		assert.NotContains(t, string(src), banned, "the publish path must not read or generate private key material")
	}

	f := newPublishFixture(t)
	published := f.publishedVersion(t, "1.0.0")
	acct, err := f.server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	require.Len(t, acct.Credentials, 1)
	assert.NoError(t, f.verify(t, published), "verification needs only the account's registered public key")

	stored, err := json.Marshal(published.Publication)
	require.NoError(t, err)
	assert.NotContains(t, strings.ToLower(string(stored)), "public_key", "no public key is stored as trust")
}

func TestWorkflowPublish_SelfGeneratedKeyNotRegisteredIsDenied(t *testing.T) {
	f := newPublishFixture(t)
	f.seed(t, "1.0.0")
	rogue, _ := generateSyntheticCredential(t)

	challenge := f.begin(t, "1.0.0", "rogue-sess")
	body := buildSignAssertionBodyFlags(t, rogue, f.credID, tvRPID, tvOrigin, challenge, 1, 0x05)
	rec := f.call(t, "finish", "1.0.0", "rogue-sess", publishTenant, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an assertion from an unregistered key is refused")
	assert.Nil(t, f.stored(t, "1.0.0").Publication)

	// A stored publication that verifies only against a self-generated key is denied.
	genuine := f.publishedVersion(t, "1.0.1")
	forged := *genuine
	pub := *genuine.Publication
	pub.Signature = signWithKey(t, rogue, f, genuine)
	forged.Publication = &pub
	assert.Error(t, f.verify(t, &forged))
}

// signWithKey re-signs the publication's own authenticator data and client data under key
// and returns the base64url signature.
func signWithKey(t *testing.T, key *ecdsa.PrivateKey, f *publishFixture, vw *workflow.VersionedWorkflow) string {
	t.Helper()
	body := buildSignAssertionBodyFlags(t, key, f.credID, tvRPID, tvOrigin, "unused", 1, 0x05)
	var parsed struct {
		Response struct {
			Signature string `json:"signature"`
		} `json:"response"`
	}
	buf := make([]byte, body.Size())
	_, _ = body.ReadAt(buf, 0)
	require.NoError(t, json.Unmarshal(buf, &parsed))
	return parsed.Response.Signature
}

func TestWorkflowPublish_DeniedAfterSignerLosesCredentialAccountOrPermission(t *testing.T) {
	cases := []struct {
		name   string
		revoke func(t *testing.T, f *publishFixture)
	}{
		{"passkey removed", func(t *testing.T, f *publishFixture) {
			f.mutateAccount(t, func(a *account) { a.Credentials = nil })
		}},
		{"account disabled", func(t *testing.T, f *publishFixture) {
			f.mutateAccount(t, func(a *account) { a.Disabled = true })
		}},
		{"account deleted", func(t *testing.T, f *publishFixture) {
			rec := deleteAccount(t, f.server, testAdminPrincipal(), f.username)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		}},
		{"permission removed", func(t *testing.T, f *publishFixture) {
			f.mutateAccount(t, func(a *account) { a.Permissions = nil })
		}},
		{"moved to another tenant", func(t *testing.T, f *publishFixture) {
			f.mutateAccount(t, func(a *account) { a.TenantID = "tenant-z" })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPublishFixture(t)
			published := f.publishedVersion(t, "1.0.0")
			require.NoError(t, f.verify(t, published))
			tc.revoke(t, f)
			assert.Error(t, f.verify(t, published))
		})
	}
}

func TestWorkflowPublish_RefusesUserVerificationUnsetAndWrongOrigin(t *testing.T) {
	f := newPublishFixture(t)
	f.seed(t, "1.0.0")

	challenge := f.begin(t, "1.0.0", "uv-sess")
	noUV := buildSignAssertionBodyFlags(t, f.priv, f.credID, tvRPID, tvOrigin, challenge, 1, 0x01)
	assert.Equal(t, http.StatusBadRequest, f.call(t, "finish", "1.0.0", "uv-sess", publishTenant, noUV).Code)

	challenge = f.begin(t, "1.0.0", "origin-sess")
	wrongOrigin := buildSignAssertionBodyFlags(t, f.priv, f.credID, tvRPID, "https://evil.example", challenge, 1, 0x05)
	assert.Equal(t, http.StatusBadRequest, f.call(t, "finish", "1.0.0", "origin-sess", publishTenant, wrongOrigin).Code)

	assert.Nil(t, f.stored(t, "1.0.0").Publication)
}

func TestWorkflowPublish_EditBetweenBeginAndFinishIsRefused(t *testing.T) {
	f := newPublishFixture(t)
	vw := f.seed(t, "1.0.0")

	challenge := f.begin(t, "1.0.0", "edit-sess")
	vw.Steps[0].Name = "edited-after-begin"
	require.NoError(t, f.store.StoreWorkflow(context.Background(), vw))

	rec := f.call(t, "finish", "1.0.0", "edit-sess", publishTenant, f.assertion(t, challenge, 0x05))
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Nil(t, f.stored(t, "1.0.0").Publication)
}

func TestWorkflowPublish_CreateAndUpdateNeverStoreAPublication(t *testing.T) {
	f := newPublishFixture(t)
	published := f.publishedVersion(t, "1.0.0")
	router := newWorkflowRouter(f.handler)
	caller := &Principal{ID: "wf-writer", TenantID: publishTenant, ImplicitAdmin: true}

	smuggled := map[string]any{
		"name": "smuggle-wf", "version": "1.0.0",
		"steps":       []workflow.Step{{Name: "s", Type: workflow.StepTypeTask}},
		"publication": published.Publication,
	}
	body, err := json.Marshal(smuggled)
	require.NoError(t, err)
	rec := serveWorkflowAs(router, requestAsPrincipal(t, http.MethodPost, "/workflows", "", caller, body))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	created, err := f.store.GetLatestWorkflow(context.Background(), "smuggle-wf")
	require.NoError(t, err)
	assert.Nil(t, created.Publication, "create must not store a supplied publication")

	smuggled["name"] = "publish-wf"
	body, err = json.Marshal(smuggled)
	require.NoError(t, err)
	rec = serveWorkflowAs(router, requestAsPrincipal(t, http.MethodPut, "/workflows/publish-wf", "publish-wf", caller, body))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Nil(t, f.stored(t, "1.0.0").Publication, "a PUT over a published version leaves it without a Publication")
}

func TestWorkflowPublish_CallerOutsideTenantGets404(t *testing.T) {
	f := newPublishFixture(t)
	f.seed(t, "1.0.0")
	rec := f.call(t, "begin", "1.0.0", "other-sess", "tenant-b", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

func TestWorkflowPublish_PublishedVersionCopiedToAnotherTenantIsDenied(t *testing.T) {
	f := newPublishFixture(t)
	published := f.publishedVersion(t, "1.0.0")
	require.NoError(t, f.verify(t, published))

	copied := *published
	err := f.server.VerifyWorkflowPublication(context.Background(), "tenant-b", &copied)
	assert.Error(t, err, "the rebuilt envelope includes the tenant, so a verbatim copy is denied")
}

func TestWorkflowPublish_AuditFailureFailsThePublish(t *testing.T) {
	f := newPublishFixture(t)
	f.seed(t, "1.0.0")
	f.server.auditManager = nil

	rec := f.publish(t, "1.0.0")
	assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Nil(t, f.stored(t, "1.0.0").Publication, "an unaudited publish must not stand")
}

func TestWorkflowPublish_SignerWithoutPermissionCannotBegin(t *testing.T) {
	f := newPublishFixture(t)
	f.seed(t, "1.0.0")
	f.mutateAccount(t, func(a *account) { a.Permissions = nil })
	rec := f.call(t, "begin", "1.0.0", "noperm-sess", publishTenant, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
