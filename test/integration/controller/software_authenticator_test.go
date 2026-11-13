// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package controller

// Issue #6151: the server half of Epic #6075 (ADR-021 Amendments 10 and 11), proved
// end to end against a real running controller: real storage, real certificates, real
// HTTPS, the real audit manager. A CFGMS software authenticator (pkg/softauthn, the
// same core cfg runs) is driven on two accounts, because direct presence is held only
// through root scope:
//
//   - a tenant-scoped account (its tenant listed through the API server's setter for
//     the controller.cfg list, its flag set through the tap-gated route) enrolls, logs
//     in with a passkey, signs an operator payload and publishes a workflow;
//   - a dedicated root agent account (the controller.cfg root_agent_accounts setting on,
//     its flag set, no bound certificate) enrolls, logs in, gives direct presence for a
//     guarded request and approves a module with it.
//
// Then the account flag is cleared and, separately, the tenant is removed from the list
// (or the root-agent setting is turned off), and every step is shown refused. The
// shapes the policy never admits, and an unlisted child tenant, are shown unable to
// register one at all.
//
// The root-scope operator that taps for the flag and holds the break-glass crossing
// into the tenant holds a zero-AAGUID credential built by pkg/testutil/webauthntest
// and a bound admin certificate: the software-authenticator policy never applies to it.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgapi "github.com/cfgis/cfgms/features/controller/api"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/controller/server"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
)

const (
	swaRPID        = "localhost"
	swaRootTenant  = "root"
	swaTenant      = "msp-a"
	swaChildTenant = "client-1"
	swaSteward     = "swa-steward-1"

	swaCookieSession = "__Host-cfgms_session"
	swaCookieCSRF    = "__Host-cfgms_csrf"
	swaCookiePreCSRF = "__Host-cfgms_csrf_pre"

	swaSoftwareCode = "SOFTWARE_AUTHENTICATOR_NOT_ALLOWED"
)

// swaAgentPermissions is what a dedicated tenant agent account holds in its tenant. A
// root agent account holds no stored permissions: the controller gives it the fixed
// root agent allowlist (ADR-021 Amendment 11).
var swaAgentPermissions = []string{
	"operator-payload:sign", "workflow:publish", "workflow:write", "workflow:read", "workflow:list",
	"module:approve", "cli-login:approve",
}

// swaResp is one HTTP response.
type swaResp struct {
	Status int
	Header http.Header
	Body   []byte
}

// errCode returns the code of the API error envelope, or "".
func (r swaResp) errCode() string {
	var e struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(r.Body, &e) != nil || e.Error == nil {
		return ""
	}
	return e.Error.Code
}

// data decodes the "data" member of the API envelope into v.
func (r swaResp) data(t *testing.T, v interface{}) {
	t.Helper()
	decodeEnvelope(t, r.Body, v)
}

func (r swaResp) String() string { return fmt.Sprintf("%d %s", r.Status, string(r.Body)) }

func swaDo(t *testing.T, c *http.Client, method, target string, body []byte, hdr map[string]string) swaResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rd)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return swaResp{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

func swaJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func swaBodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// swaEnv is one running controller with its tenant tree, the root-scope operator
// that taps, and a pending module bundle.
type swaEnv struct {
	t      *testing.T
	ctrl   *server.Server
	api    *cfgapi.Server
	base   string
	origin string
	caPool *x509.CertPool
	admin  *http.Client
	tapper *swaTapper

	pendingModule string // address of a pending module bundle
	seq           int
}

// swaTapper is the root-scope operator account: it holds the break-glass crossing
// into the tenant, creates the tenant accounts, and taps for the flag route.
type swaTapper struct {
	client *http.Client
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
}

func newSWAEnv(t *testing.T) *swaEnv {
	t.Helper()
	var pendingAddr bundle.ContentAddress
	ctrl, _, base, _, admin := startHealthTestControllerWithConfig(t, func(cfg *controllerConfig.Config) {
		c, err := cache.New(moduleCacheDirFor(cfg))
		require.NoError(t, err, "seed module cache")
		pendingAddr = seedModuleBundle(t, c, "cfgms", "hyperv", "0.2.1")
	})
	e := &swaEnv{t: t, ctrl: ctrl, base: base, origin: presenceRelayOrigin(t, base), admin: admin}

	e.api = ctrl.GetAPIServer()
	require.NotNil(t, e.api, "controller must expose its API server")
	wa, err := cfgapi.NewWebAuthnFromConfig(swaRPID, swaRPID, []string{e.origin})
	require.NoError(t, err)
	e.api.SetWebAuthn(wa)

	caPEM, err := ctrl.GetCertificateManager().GetCACertificate()
	require.NoError(t, err)
	e.caPool = x509.NewCertPool()
	require.True(t, e.caPool.AppendCertsFromPEM(caPEM))

	// The pending bundle's address as GET /modules/approvals reports it.
	resp := swaDo(t, admin, http.MethodGet, base+"/api/v1/modules/approvals", nil, nil)
	require.Equal(t, http.StatusOK, resp.Status, resp.String())
	var pending struct {
		Pending []struct {
			Address string `json:"address"`
			Name    string `json:"name"`
		} `json:"pending"`
	}
	resp.data(t, &pending)
	require.Len(t, pending.Pending, 1)
	require.Equal(t, pendingAddr.Name, pending.Pending[0].Name)
	e.pendingModule = pending.Pending[0].Address

	e.buildTenantTree()
	e.tapper = e.newTapper()
	e.breakGlassInto(swaTenant)
	e.createChildTenant()
	require.NoError(t, ctrl.GetControllerService().RegisterSteward(swaSteward, swaTenant, "", "active"))
	return e
}

// buildTenantTree creates the root tenant the way deployment bootstrap does (through
// the tenant manager: the API creates no top-level tenant) and the MSP tenant below it.
func (e *swaEnv) buildTenantTree() {
	t := e.t
	mgr := e.ctrl.GetTenantManager()
	require.NotNil(t, mgr, "controller tenant manager")
	_, err := mgr.CreateTenant(context.Background(), &tenant.TenantRequest{ID: swaRootTenant, Name: "root"})
	require.NoError(t, err, "create root tenant")
	require.Equal(t, swaRootTenant, mgr.RootTenantID(context.Background()))

	resp := swaDo(t, e.admin, http.MethodPost, e.base+"/api/v1/tenants",
		swaJSON(t, map[string]string{"id": swaTenant, "name": "msp-a", "parent_id": swaRootTenant}), nil)
	require.Equal(t, http.StatusCreated, resp.Status, "create MSP tenant: %s", resp)
}

// createChildTenant creates the child of the MSP tenant; it needs the crossing.
func (e *swaEnv) createChildTenant() {
	resp := swaDo(e.t, e.tapper.client, http.MethodPost, e.base+"/api/v1/tenants",
		swaJSON(e.t, map[string]string{"id": swaChildTenant, "name": "client-1", "parent_id": swaTenant}), nil)
	require.Equal(e.t, http.StatusCreated, resp.Status, "create child tenant: %s", resp)
}

// newTapper creates the root-scope operator: an account bound to a fresh admin
// certificate and holding one ordinary (zero-AAGUID) WebAuthn credential.
func (e *swaEnv) newTapper() *swaTapper {
	t := e.t
	const username = "swa-operator"
	client, cert := newAdminMTLSClient(t, e.ctrl, username)

	resp := swaDo(t, e.admin, http.MethodPost, e.base+"/api/v1/accounts",
		swaJSON(t, map[string]interface{}{"username": username, "root_scope": true}), nil)
	require.Equal(t, http.StatusCreated, resp.Status, "create operator account: %s", resp)
	e.bindAdminCert(username, cert)

	key, _ := webauthntest.NewKey(t)
	credID := []byte("swa-operator-hardware-credential")
	registerVirtualCredential(t, client, e.base, username, swaRPID, e.origin, key, credID)
	return &swaTapper{client: client, key: key, credID: credID}
}

// bindAdminCert binds an admin certificate to the account, as the bootstrap admin does.
func (e *swaEnv) bindAdminCert(username string, cert *x509.Certificate) {
	resp := swaDo(e.t, e.admin, http.MethodPost, e.base+"/api/v1/accounts/"+username+"/certs/bind",
		swaJSON(e.t, map[string]string{
			"serial": cert.SerialNumber.String(), "fingerprint": certFingerprint(cert), "label": "swa test",
		}), nil)
	require.Equal(e.t, http.StatusCreated, resp.Status, "bind certificate to %s: %s", username, resp)
}

// breakGlassInto opens the crossing the operator needs to act on a tenant below root.
func (e *swaEnv) breakGlassInto(tenant string) {
	resp := swaDo(e.t, e.tapper.client, http.MethodPost, e.base+"/api/v1/tenants/"+tenant+"/break-glass",
		swaJSON(e.t, map[string]string{
			"reason_category": "account_recovery",
			"justification":   "integration test creates the first account in the tenant",
		}), nil)
	require.Equal(e.t, http.StatusCreated, resp.Status, "break-glass into %s: %s", tenant, resp)
}

// presenceToken runs the CLI presence relay for the operator: lodge, a real WebAuthn
// presence ceremony with its credential, collect. The token is bound to the exact
// request (method, path, body, permission).
func (e *swaEnv) presenceToken(tp *swaTapper, method, path string, body []byte, permission string) string {
	t := e.t
	lodge := swaDo(t, tp.client, http.MethodPost, e.base+"/api/v1/cli-presence/lodge",
		swaJSON(t, map[string]string{
			"method": method, "path": path, "body_sha256": swaBodyHash(body), "permission": permission,
		}), nil)
	require.Equal(t, http.StatusCreated, lodge.Status, "lodge presence: %s", lodge)
	var lodged struct {
		RequestID string `json:"request_id"`
	}
	lodge.data(t, &lodged)

	begin := swaDo(t, tp.client, http.MethodPost,
		e.base+"/api/v1/webauthn/presence/begin?cli_presence_request_id="+lodged.RequestID, nil, nil)
	require.Equal(t, http.StatusOK, begin.Status, "presence begin: %s", begin)
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	begin.data(t, &opts)

	tp.count++
	assertion := webauthntest.Assert(t, tp.key, tp.credID, swaRPID, e.origin, opts.PublicKey.Challenge,
		webauthntest.WithSignCount(tp.count)).Body()
	finish := swaDo(t, tp.client, http.MethodPost,
		e.base+"/api/v1/webauthn/presence/finish?cli_presence_request_id="+lodged.RequestID, assertion, nil)
	require.Equal(t, http.StatusOK, finish.Status, "presence finish: %s", finish)

	collect := swaDo(t, tp.client, http.MethodPost, e.base+"/api/v1/cli-presence/"+lodged.RequestID+"/collect", nil, nil)
	require.Equal(t, http.StatusOK, collect.Status, "collect presence: %s", collect)
	var collected struct {
		Status        string `json:"status"`
		PresenceToken string `json:"presence_token"`
	}
	collect.data(t, &collected)
	require.Equal(t, "collected", collected.Status)
	require.NotEmpty(t, collected.PresenceToken)
	return collected.PresenceToken
}

// setFlag taps and calls PUT /accounts/{username}/software-authenticator.
func (e *swaEnv) setFlag(username string, enabled bool) swaResp {
	path := "/api/v1/accounts/" + username + "/software-authenticator"
	body := swaJSON(e.t, map[string]bool{"enabled": enabled})
	token := e.presenceToken(e.tapper, http.MethodPut, path, body, "account:set-software-authenticator")
	return swaDo(e.t, e.tapper.client, http.MethodPut, e.base+path, body, map[string]string{"X-Presence-Token": token})
}

// mustSetFlag sets the flag and requires the controller to report the new value.
func (e *swaEnv) mustSetFlag(username string, enabled bool) {
	resp := e.setFlag(username, enabled)
	require.Equal(e.t, http.StatusOK, resp.Status, "set flag on %s: %s", username, resp)
	var out struct {
		Enabled bool `json:"allow_software_authenticator"`
	}
	resp.data(e.t, &out)
	require.Equal(e.t, enabled, out.Enabled)
}

// createAccount creates an account as the operator and returns its enrollment token.
func (e *swaEnv) createAccount(req map[string]interface{}) (token string, resp swaResp) {
	resp = swaDo(e.t, e.tapper.client, http.MethodPost, e.base+"/api/v1/accounts", swaJSON(e.t, req), nil)
	if resp.Status == http.StatusCreated || resp.Status == http.StatusOK { // 200: an existing account re-issued
		var out struct {
			Token string `json:"enrollment_magic_link"`
		}
		resp.data(e.t, &out)
		token = out.Token
	}
	return token, resp
}

// swaAgent is a dedicated agent account with a software authenticator.
type swaAgent struct {
	e        *swaEnv
	username string
	token    string
	auth     *softauthn.Authenticator
	root     bool // a root-scope agent account rather than a tenant account
}

// newAgent creates a tenant account that holds the agent permissions and a software
// authenticator that is not yet enrolled.
func (e *swaEnv) newAgent(prefix, tenant string) *swaAgent {
	t := e.t
	e.seq++
	username := fmt.Sprintf("%s-%d", prefix, e.seq)
	token, resp := e.createAccount(map[string]interface{}{
		"username": username, "tenant_id": tenant, "permissions": swaAgentPermissions,
	})
	require.Equal(t, http.StatusCreated, resp.Status, "create agent account: %s", resp)
	require.NotEmpty(t, token)
	return &swaAgent{e: e, username: username, token: token, auth: e.newSoftAuthenticator()}
}

// newRootAgent creates a root-scope account and a software authenticator that is not
// yet enrolled. The caller turns the root-agent setting on and sets the flag.
func (e *swaEnv) newRootAgent(prefix string) *swaAgent {
	t := e.t
	e.seq++
	username := fmt.Sprintf("%s-%d", prefix, e.seq)
	token, resp := e.createAccount(map[string]interface{}{"username": username, "root_scope": true})
	require.Equal(t, http.StatusCreated, resp.Status, "create root agent account: %s", resp)
	require.NotEmpty(t, token)
	return &swaAgent{e: e, username: username, token: token, auth: e.newSoftAuthenticator(), root: true}
}

// newSoftAuthenticator is a CFGMS software authenticator with a fresh P-256 key.
func (e *swaEnv) newSoftAuthenticator() *softauthn.Authenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(e.t, err)
	credID := make([]byte, 32)
	_, err = rand.Read(credID)
	require.NoError(e.t, err)
	a, err := softauthn.New(softauthn.Config{Signer: key, RPID: swaRPID, Origin: e.origin, CredentialID: credID})
	require.NoError(e.t, err)
	return a
}

// enroll runs the first-passkey enrollment ceremony the enrollment link opens.
// It returns the finish response; a begin that is refused is a test failure.
func (a *swaAgent) enroll() swaResp {
	t := a.e.t
	hdr := map[string]string{"X-Enrollment-Token": a.token}
	plain := a.e.plainClient(nil)
	begin := swaDo(t, plain, http.MethodPost, a.e.base+"/api/v1/web/passkey/enroll/begin", nil, hdr)
	require.Equal(t, http.StatusOK, begin.Status, "enroll begin: %s", begin)
	var options json.RawMessage
	begin.data(t, &options)
	registration, err := a.auth.Register(options)
	require.NoError(t, err)
	return swaDo(t, plain, http.MethodPost, a.e.base+"/api/v1/web/passkey/enroll/finish", registration, hdr)
}

// credentialIDs lists the account's registered credentials through the operator.
func (a *swaAgent) credentialIDs() []string {
	t := a.e.t
	resp := swaDo(t, a.e.tapper.client, http.MethodGet, a.e.base+"/api/v1/accounts/"+a.username+"/webauthn/credentials", nil, nil)
	require.Equal(t, http.StatusOK, resp.Status, resp.String())
	var out struct {
		Credentials []struct {
			ID string `json:"id"`
		} `json:"credentials"`
	}
	resp.data(t, &out)
	ids := make([]string, 0, len(out.Credentials))
	for _, c := range out.Credentials {
		ids = append(ids, c.ID)
	}
	return ids
}

// plainClient is a client with no certificate: the way a web session or a CLI login
// reaches the controller. jar may be nil.
func (e *swaEnv) plainClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: e.caPool, MinVersion: tls.VersionTLS12},
		},
	}
}

// swaSession is one web session (cookie jar and CSRF token) of an agent.
type swaSession struct {
	e      *swaEnv
	client *http.Client
	u      *url.URL
}

func (s *swaSession) cookie(name string) string {
	for _, c := range s.client.Jar.Cookies(s.u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// do sends a request on the session; unsafe methods carry the session CSRF token.
func (s *swaSession) do(method, path string, body []byte, hdr map[string]string) swaResp {
	h := map[string]string{}
	for k, v := range hdr {
		h[k] = v
	}
	if method != http.MethodGet {
		h["X-CSRF-Token"] = s.cookie(swaCookieCSRF)
	}
	return swaDo(s.e.t, s.client, method, s.e.base+path, body, h)
}

// login runs the usernameless passkey login with the software authenticator. The
// session is nil unless the controller issued one; the response is the finish step's.
func (a *swaAgent) login() (*swaSession, swaResp) {
	t := a.e.t
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	u, err := url.Parse(a.e.base)
	require.NoError(t, err)
	s := &swaSession{e: a.e, client: a.e.plainClient(jar), u: u}

	csrf := swaDo(t, s.client, http.MethodGet, a.e.base+"/api/v1/web/csrf", nil, nil)
	require.Equal(t, http.StatusOK, csrf.Status, "pre-session csrf: %s", csrf)
	pre := s.cookie(swaCookiePreCSRF)
	require.NotEmpty(t, pre)

	begin := swaDo(t, s.client, http.MethodPost, a.e.base+"/api/v1/web/passkey/login/begin", []byte("{}"),
		map[string]string{"X-CSRF-Token": pre})
	require.Equal(t, http.StatusOK, begin.Status, "login begin: %s", begin)
	var options json.RawMessage
	begin.data(t, &options)
	assertion, err := a.auth.Assert(options)
	require.NoError(t, err)

	finish := swaDo(t, s.client, http.MethodPost, a.e.base+"/api/v1/web/passkey/login/finish", assertion, nil)
	if finish.Status != http.StatusOK || s.cookie(swaCookieSession) == "" {
		return nil, finish
	}
	return s, finish
}

// mustLogin logs in and requires a session.
func (a *swaAgent) mustLogin() *swaSession {
	s, resp := a.login()
	require.NotNil(a.e.t, s, "passkey login with the software authenticator: %s", resp)
	return s
}

// presence runs the direct presence ceremony for one guarded request and returns the
// presence token.
func (a *swaAgent) presence(s *swaSession, method, path string, body []byte, permission string) (string, swaResp) {
	t := a.e.t
	begin := s.do(http.MethodPost, "/api/v1/webauthn/presence/begin", swaJSON(t, map[string]string{
		"method": method, "path": path, "body_hash": swaBodyHash(body), "permission_id": permission,
	}), nil)
	if begin.Status != http.StatusOK {
		return "", begin
	}
	var options json.RawMessage
	begin.data(t, &options)
	assertion, err := a.auth.Assert(options)
	require.NoError(t, err)
	finish := s.do(http.MethodPost, "/api/v1/webauthn/presence/finish", assertion, nil)
	if finish.Status != http.StatusOK {
		return "", finish
	}
	var out struct {
		Token string `json:"presence_token"`
	}
	finish.data(t, &out)
	require.NotEmpty(t, out.Token)
	return out.Token, finish
}

// signPayload runs the operator-payload sign ceremony for a command on the tenant's
// steward. It returns the finish response (or the begin response when begin failed).
func (a *swaAgent) signPayload(s *swaSession) swaResp {
	t := a.e.t
	begin := s.do(http.MethodPost, "/api/v1/operator-payload/sign/begin", swaJSON(t, map[string]interface{}{
		"selector": "all", "content": []byte("echo hello"), "shell": "bash",
	}), nil)
	if begin.Status != http.StatusOK {
		return begin
	}
	var out struct {
		Assertion json.RawMessage `json:"assertion"`
	}
	begin.data(t, &out)
	assertion, err := a.auth.Assert(out.Assertion)
	require.NoError(t, err)
	return s.do(http.MethodPost, "/api/v1/operator-payload/sign/finish", assertion, nil)
}

// createWorkflow stores one workflow version in the tenant as the root-scope operator,
// which gives presence for the create (workflow:write is presence-gated) with its own
// credential. The version is then published by the agent.
func (e *swaEnv) createWorkflow(tenantID, name, version string) {
	t := e.t
	path := "/api/v1/workflows?tenant=" + tenantID
	body := swaJSON(t, map[string]interface{}{
		"name": name, "version": version,
		"steps": []map[string]string{{"name": "step1", "type": "task"}},
	})
	token := e.presenceToken(e.tapper, http.MethodPost, path, body, "workflow:write")
	created := swaDo(t, e.tapper.client, http.MethodPost, e.base+path, body, map[string]string{"X-Presence-Token": token})
	require.Equal(t, http.StatusCreated, created.Status, "create workflow: %s", created)
}

// publishWorkflow runs the publish ceremony for a stored version.
func (a *swaAgent) publishWorkflow(s *swaSession, name, version string) swaResp {
	t := a.e.t
	base := "/api/v1/workflows/" + name + "/versions/" + version + "/publish/"
	begin := s.do(http.MethodPost, base+"begin", nil, nil)
	if begin.Status != http.StatusOK {
		return begin
	}
	var out struct {
		Assertion json.RawMessage `json:"assertion"`
	}
	begin.data(t, &out)
	assertion, err := a.auth.Assert(out.Assertion)
	require.NoError(t, err)
	return s.do(http.MethodPost, base+"finish", assertion, nil)
}

// cliLogin runs the CLI login handshake: the CLI lodges a request, the agent's web
// session approves it, the CLI collects the Bearer token. The token is bound to the
// credential that approved it.
func (a *swaAgent) cliLogin(approver *swaSession) string {
	t := a.e.t
	verifierRaw := make([]byte, 32)
	_, err := rand.Read(verifierRaw)
	require.NoError(t, err)
	verifier := hex.EncodeToString(verifierRaw)
	plain := a.e.plainClient(nil)

	lodge := swaDo(t, plain, http.MethodPost, a.e.base+"/api/v1/cli-login/lodge",
		swaJSON(t, map[string]string{"verifier_hash": swaBodyHash([]byte(verifier))}), nil)
	require.Equal(t, http.StatusCreated, lodge.Status, "cli-login lodge: %s", lodge)
	var lodged struct {
		RequestID string `json:"request_id"`
		UserCode  string `json:"user_code"`
	}
	lodge.data(t, &lodged)

	approve := approver.do(http.MethodPost, "/api/v1/cli-login/"+lodged.RequestID+"/approve",
		swaJSON(t, map[string]string{"user_code": lodged.UserCode}), nil)
	require.Equal(t, http.StatusOK, approve.Status, "cli-login approve: %s", approve)

	collect := swaDo(t, plain, http.MethodPost, a.e.base+"/api/v1/cli-login/"+lodged.RequestID+"/collect", nil,
		map[string]string{"Authorization": "Bearer " + verifier})
	require.Equal(t, http.StatusOK, collect.Status, "cli-login collect: %s", collect)
	var collected struct {
		Status string `json:"status"`
		Token  string `json:"token"`
	}
	collect.data(t, &collected)
	require.Equal(t, "collected", collected.Status)
	require.NotEmpty(t, collected.Token)
	return collected.Token
}

// bearerGet issues the same read a session proves itself with, over a CLI Bearer token.
func (e *swaEnv) bearerGet(token string) swaResp {
	return swaDo(e.t, e.plainClient(nil), http.MethodGet, e.base+"/api/v1/workflows", nil,
		map[string]string{"Authorization": "Bearer " + token})
}

// live issues the read a web session proves itself with.
func (s *swaSession) live() swaResp { return s.do(http.MethodGet, "/api/v1/workflows", nil, nil) }

// requireEnded asserts that the controller ended a session on this request.
func requireEnded(t *testing.T, what string, resp swaResp) {
	t.Helper()
	assert.Equal(t, http.StatusUnauthorized, resp.Status, "%s must be refused: %s", what, resp)
	assert.Equal(t, "SESSION_REVOKED", resp.errCode(), "%s", what)
}

// swaAudit is one audit event, reduced to what the assertions read.
type swaAudit struct {
	Action string
	UserID string
	Result business.AuditResult
	Detail map[string]interface{}
}

// audit returns every audit event the controller has recorded.
func (e *swaEnv) audit() []swaAudit {
	t := e.t
	mgr := e.ctrl.GetAuditManager()
	require.NotNil(t, mgr, "controller audit manager")
	require.NoError(t, mgr.Flush(context.Background()))
	entries, err := mgr.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	out := make([]swaAudit, 0, len(entries))
	for _, en := range entries {
		out = append(out, swaAudit{Action: en.Action, UserID: en.UserID, Result: en.Result, Detail: en.Details})
	}
	return out
}

// softwareMarked reports whether an event carries the software marker: the
// software_authenticator detail, or (for a registration that was refused before a
// credential was stored) the CFGMS software AAGUID.
func (ev swaAudit) softwareMarked() bool {
	if marked, _ := ev.Detail["software_authenticator"].(bool); marked {
		return true
	}
	aaguid, _ := ev.Detail["aaguid"].(string)
	return aaguid == hex.EncodeToString(softauthn.AAGUID[:])
}

// auditCount counts the events with the action and result that carry the marker.
func auditCount(events []swaAudit, action string, result business.AuditResult) int {
	n := 0
	for _, ev := range events {
		if ev.Action == action && ev.Result == result && ev.softwareMarked() {
			n++
		}
	}
	return n
}

// approvePath is the approve route of the seeded pending module bundle.
func (e *swaEnv) approvePath() string {
	return "/api/v1/modules/approvals/" + e.pendingModule + "/approve"
}

// markedEvents returns the events with the action and result that carry the software marker.
func markedEvents(events []swaAudit, action string, result business.AuditResult) []swaAudit {
	var out []swaAudit
	for _, ev := range events {
		if ev.Action == action && ev.Result == result && ev.softwareMarked() {
			out = append(out, ev)
		}
	}
	return out
}

// requireStepAudit asserts that a step left exactly one marked success event that
// names the credential and the software AAGUID. It returns the event.
func requireStepAudit(t *testing.T, events []swaAudit, action, credID string) swaAudit {
	t.Helper()
	marked := markedEvents(events, action, business.AuditResultSuccess)
	if !assert.Len(t, marked, 1, "%s must leave one marked event", action) {
		return swaAudit{}
	}
	ev := marked[0]
	assert.Equal(t, true, ev.Detail["software_authenticator"], action)
	assert.Equal(t, credID, ev.Detail["credential_id"], action)
	assert.Equal(t, hex.EncodeToString(softauthn.AAGUID[:]), ev.Detail["aaguid"], action)
	return ev
}

// requireRootScopeMarker asserts whether an event carries the root_scope marker that
// tells a root agent's use from tenant use.
func requireRootScopeMarker(t *testing.T, ev swaAudit, want bool) {
	t.Helper()
	got, _ := ev.Detail["root_scope"].(bool)
	assert.Equal(t, want, got, "%s root_scope marker", ev.Action)
}

// flagEvents counts the successful flag-change events for the account whose new value is next.
func flagEvents(events []swaAudit, username string, next bool) int {
	n := 0
	for _, ev := range events {
		if ev.Action == "account.software_authenticator_flag_changed" && ev.Result == business.AuditResultSuccess &&
			ev.Detail["account"] == username && ev.Detail["new"] == next {
			n++
		}
	}
	return n
}

// TestSoftwareAuthenticator_PolicyOnJourney is the first [REQUIRED TEST] for a tenant
// account: with the tenant listed and the account flag on, a software authenticator
// completes enrollment, login, sign finish and publish finish, and a CLI login.
func TestSoftwareAuthenticator_PolicyOnJourney(t *testing.T) {
	e := newSWAEnv(t)
	e.api.SetSoftwareAuthenticatorTenants([]string{swaTenant})
	agent := e.newAgent("swa-journey", swaTenant)
	e.mustSetFlag(agent.username, true)

	enrolled := agent.enroll()
	require.Equal(t, http.StatusCreated, enrolled.Status, "software enrollment: %s", enrolled)
	require.Len(t, agent.credentialIDs(), 1)

	s := agent.mustLogin()
	assert.Equal(t, http.StatusOK, s.live().Status, "the passkey session works")

	t.Run("a tenant account holds no presence permission", func(t *testing.T) {
		// module:approve carries RequireUserPresence: the controller answers the bare
		// request with a presence challenge. The direct presence endpoints need
		// webauthn:assert-presence, which a tenant account never holds (the root agent
		// journey is where presence is given), so the ceremony is refused for it.
		approve := s.do(http.MethodPost, e.approvePath(), nil, nil)
		require.Equal(t, http.StatusUnauthorized, approve.Status, "%s", approve)
		assert.Contains(t, approve.Header.Get("WWW-Authenticate"), `presence="required"`)
		token, resp := agent.presence(s, http.MethodPost, e.approvePath(), nil, "module:approve")
		assert.Empty(t, token)
		assert.Equal(t, http.StatusForbidden, resp.Status, "%s", resp)
		assert.Equal(t, "INSUFFICIENT_PERMISSIONS", resp.errCode())
	})

	t.Run("operator-payload sign", func(t *testing.T) {
		resp := agent.signPayload(s)
		require.Equal(t, http.StatusOK, resp.Status, "sign finish: %s", resp)
		var signed struct {
			Envelope struct {
				Targets []string `json:"targets"`
			} `json:"envelope"`
		}
		resp.data(t, &signed)
		assert.Equal(t, []string{swaSteward}, signed.Envelope.Targets)
	})

	t.Run("workflow publish", func(t *testing.T) {
		e.createWorkflow(swaTenant, "swa-journey-wf", "1.0.0")
		resp := agent.publishWorkflow(s, "swa-journey-wf", "1.0.0")
		require.Equal(t, http.StatusOK, resp.Status, "publish finish: %s", resp)
		var published struct {
			SignerAccountID string `json:"signer_account_id"`
			ContentHash     string `json:"content_hash"`
		}
		resp.data(t, &published)
		assert.NotEmpty(t, published.SignerAccountID)
		assert.NotEmpty(t, published.ContentHash)
	})

	t.Run("CLI login session", func(t *testing.T) {
		token := agent.cliLogin(s)
		assert.Equal(t, http.StatusOK, e.bearerGet(token).Status, "the CLI session works")
	})

	t.Run("audit", func(t *testing.T) {
		// Each step the software authenticator took left one event that names the
		// credential and carries software_authenticator: true.
		events := e.audit()
		credID := agent.auth.CredentialID()
		b64, hexID := base64.RawURLEncoding.EncodeToString(credID), hex.EncodeToString(credID)
		requireStepAudit(t, events, "account.passkey_enrolled", b64)
		requireRootScopeMarker(t, requireStepAudit(t, events, "web.passkey.login.success", b64), false)
		requireStepAudit(t, events, "operator_payload.dispatch", hexID)
		requireStepAudit(t, events, "workflow.publish", b64)
		assert.Equal(t, 1, flagEvents(events, agent.username, true), "the flag change is audited")
	})
}

// TestSoftwareAuthenticator_RootAgentJourney is the second [REQUIRED TEST]: with
// root_agent_accounts on and the flag set on a dedicated root-scope account, a software
// authenticator completes enrollment, login, a presence-gated request (presence begin
// and finish) and module approve with that presence, and each step is audited with the
// software marker (login and presence also carry root_scope).
func TestSoftwareAuthenticator_RootAgentJourney(t *testing.T) {
	e := newSWAEnv(t)
	e.api.SetSoftwareAuthenticatorRootAgentAccounts(true)
	agent := e.newRootAgent("swa-root-journey")
	e.mustSetFlag(agent.username, true)

	enrolled := agent.enroll()
	require.Equal(t, http.StatusCreated, enrolled.Status, "software enrollment: %s", enrolled)
	require.Len(t, agent.credentialIDs(), 1)

	s := agent.mustLogin()
	assert.Equal(t, http.StatusOK, s.live().Status, "the passkey session works")

	var presenceToken string
	t.Run("presence-gated request", func(t *testing.T) {
		bare := s.do(http.MethodPost, e.approvePath(), nil, nil)
		require.Equal(t, http.StatusUnauthorized, bare.Status, "%s", bare)
		assert.Contains(t, bare.Header.Get("WWW-Authenticate"), `presence="required"`)

		token, resp := agent.presence(s, http.MethodPost, e.approvePath(), nil, "module:approve")
		require.Equal(t, http.StatusOK, resp.Status, "presence begin and finish: %s", resp)
		require.NotEmpty(t, token)
		presenceToken = token
	})

	t.Run("module approve", func(t *testing.T) {
		require.NotEmpty(t, presenceToken, "the presence ceremony must have succeeded")
		resp := s.do(http.MethodPost, e.approvePath(), nil, map[string]string{"X-Presence-Token": presenceToken})
		require.Equal(t, http.StatusOK, resp.Status, "module approve: %s", resp)

		list := swaDo(t, e.admin, http.MethodGet, e.base+"/api/v1/modules/approvals", nil, nil)
		require.Equal(t, http.StatusOK, list.Status, list.String())
		var pending struct {
			Pending []struct{} `json:"pending"`
		}
		list.data(t, &pending)
		assert.Empty(t, pending.Pending, "the module is no longer pending approval")
	})

	t.Run("audit", func(t *testing.T) {
		events := e.audit()
		b64 := base64.RawURLEncoding.EncodeToString(agent.auth.CredentialID())
		requireStepAudit(t, events, "account.passkey_enrolled", b64)
		requireRootScopeMarker(t, requireStepAudit(t, events, "web.passkey.login.success", b64), true)
		presenceEv := requireStepAudit(t, events, "web.presence.success", b64)
		requireRootScopeMarker(t, presenceEv, true)
		assert.Equal(t, 1, flagEvents(events, agent.username, true), "the flag change is audited")

		// The approval event itself names the acting account, not the credential: it is
		// attributed to the software authenticator through the presence event of the same
		// account that authorised it.
		var approved []swaAudit
		for _, ev := range events {
			if ev.Action == "module.bundle.approved" && ev.Result == business.AuditResultSuccess {
				approved = append(approved, ev)
			}
		}
		if assert.Len(t, approved, 1, "module approve must leave one event") {
			assert.NotEmpty(t, presenceEv.UserID)
			assert.Equal(t, presenceEv.UserID, approved[0].UserID, "approved by the account that gave presence")
		}
	})
}

// swaPolicyOff is one way the policy stops permitting a software credential, for a
// tenant account or for a root agent account.
type swaPolicyOff struct {
	name       string
	root       bool
	clearsFlag bool
	off        func(e *swaEnv, a *swaAgent)
	on         func(e *swaEnv, a *swaAgent)
}

var swaPolicyOffModes = []swaPolicyOff{
	{name: "tenant account flag cleared", clearsFlag: true,
		off: func(e *swaEnv, a *swaAgent) { e.mustSetFlag(a.username, false) },
		on:  func(e *swaEnv, a *swaAgent) { e.mustSetFlag(a.username, true) }},
	{name: "tenant removed from the list",
		off: func(e *swaEnv, _ *swaAgent) { e.api.SetSoftwareAuthenticatorTenants(nil) },
		on:  func(e *swaEnv, _ *swaAgent) { e.api.SetSoftwareAuthenticatorTenants([]string{swaTenant}) }},
	{name: "root agent flag cleared by another root caller", root: true, clearsFlag: true,
		off: func(e *swaEnv, a *swaAgent) { e.mustSetFlag(a.username, false) },
		on:  func(e *swaEnv, a *swaAgent) { e.mustSetFlag(a.username, true) }},
	{name: "root_agent_accounts turned off", root: true,
		off: func(e *swaEnv, _ *swaAgent) { e.api.SetSoftwareAuthenticatorRootAgentAccounts(false) },
		on:  func(e *swaEnv, _ *swaAgent) { e.api.SetSoftwareAuthenticatorRootAgentAccounts(true) }},
}

// swaTenantSessions are the sessions a tenant agent holds before the policy goes off,
// one per refused step, so each refusal is its own.
type swaTenantSessions struct {
	sign, publish *swaSession
	workflow      string
	cli           string
}

// openTenantSessions creates the workflow and the sessions the tenant-only steps use.
func (e *swaEnv) openTenantSessions(agent *swaAgent) swaTenantSessions {
	e.seq++
	ts := swaTenantSessions{workflow: fmt.Sprintf("swa-off-wf-%d", e.seq)}
	e.createWorkflow(swaTenant, ts.workflow, "1.0.0")
	ts.sign, ts.publish = agent.mustLogin(), agent.mustLogin()
	ts.cli = agent.cliLogin(agent.mustLogin())
	return ts
}

// requireLoginRefused asserts that a new passkey login with the credential is refused.
func requireLoginRefused(t *testing.T, agent *swaAgent) {
	t.Helper()
	s, resp := agent.login()
	assert.Nil(t, s, "login must not issue a session: %s", resp)
	assert.Equal(t, http.StatusBadRequest, resp.Status, "login finish: %s", resp)
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", resp.errCode())
}

// requireNothingDeleted asserts the credential works again once the policy is back on.
func requireNothingDeleted(t *testing.T, agent *swaAgent) {
	t.Helper()
	restored, resp := agent.login()
	require.NotNil(t, restored, "login after the policy is back on: %s", resp)
	assert.Equal(t, http.StatusOK, restored.live().Status)
}

// TestSoftwareAuthenticator_PolicyOffRefusesEveryStep is the third and fifth
// [REQUIRED TEST]. A tenant account's login, presence, sign, publish and live web and
// CLI-login Bearer sessions are each refused after its flag is cleared and again after
// its tenant is removed from the list. A root agent account's login and presence
// ceremony (refused at presence/begin) and its live session are each refused after its
// flag is cleared by another root caller and again after root_agent_accounts is turned
// off. Every session is established while the policy is on and used once after it
// turns off, so each refusal is its own. Each mode runs on its own controller.
func TestSoftwareAuthenticator_PolicyOffRefusesEveryStep(t *testing.T) {
	for _, mode := range swaPolicyOffModes {
		t.Run(mode.name, func(t *testing.T) {
			// One controller per mode: the refused logins count against the per-IP
			// failed-login throttle, which would otherwise block the next mode's logins.
			e := newSWAEnv(t)
			e.api.SetSoftwareAuthenticatorTenants([]string{swaTenant})
			e.api.SetSoftwareAuthenticatorRootAgentAccounts(true)

			var agent *swaAgent
			if mode.root {
				agent = e.newRootAgent("swa-root-off")
			} else {
				agent = e.newAgent("swa-off", swaTenant)
			}
			e.mustSetFlag(agent.username, true)
			require.Equal(t, http.StatusCreated, agent.enroll().Status)

			presenceS, liveS := agent.mustLogin(), agent.mustLogin()
			var ts swaTenantSessions
			if !mode.root {
				ts = e.openTenantSessions(agent)
				require.Equal(t, http.StatusOK, e.bearerGet(ts.cli).Status, "precondition: the CLI session works")
			}
			require.Equal(t, http.StatusOK, liveS.live().Status, "precondition: the web session works")

			mode.off(e, agent)

			requireLoginRefused(t, agent)

			// Presence is refused at the ceremony's first step, on a session the credential proved.
			token, presence := agent.presence(presenceS, http.MethodPost, e.approvePath(), nil, "module:approve")
			assert.Empty(t, token)
			requireEnded(t, "presence/begin", presence)

			if !mode.root {
				requireEnded(t, "operator-payload sign", agent.signPayload(ts.sign))
				requireEnded(t, "workflow publish", agent.publishWorkflow(ts.publish, ts.workflow, "1.0.0"))
				requireEnded(t, "live CLI-login session", e.bearerGet(ts.cli))
				assert.Equal(t, http.StatusUnauthorized, e.bearerGet(ts.cli).Status, "the CLI session was revoked, not just refused once")
			}

			// A live web session ends on its next request, and stays ended.
			requireEnded(t, "live web session", liveS.live())
			assert.Equal(t, http.StatusUnauthorized, liveS.live().Status, "the web session was revoked, not just refused once")

			// The refused login is an audit event carrying the software marker.
			events := e.audit()
			assert.GreaterOrEqual(t, len(markedEvents(events, "web.passkey.login.failure", business.AuditResultDenied))+
				len(markedEvents(events, "web.passkey.login.failure", business.AuditResultFailure)), 1, "refused login")
			if mode.clearsFlag {
				assert.Equal(t, 1, flagEvents(events, agent.username, false), "clearing the flag is audited")
			}

			// Nothing was deleted: the credential works again once the policy is back on.
			mode.on(e, agent)
			requireNothingDeleted(t, agent)
		})
	}
}

// denialReasons lists the reason of every refused registration that names the software AAGUID.
func denialReasons(events []swaAudit) []string {
	var out []string
	for _, ev := range markedEvents(events, "account.passkey_registration_denied", business.AuditResultDenied) {
		reason, _ := ev.Detail["reason"].(string)
		out = append(out, reason)
	}
	return out
}

// TestSoftwareAuthenticator_RegistrationRefusedOutsideThePolicy is the fourth
// [REQUIRED TEST]: a root-scope account cannot register a software authenticator while
// root_agent_accounts is off even with the flag set; cfgms-admin and an account with a
// bound admin certificate are refused even with it on; an account with an empty tenant
// and an account in the root tenant are refused; and a listed parent does not cover an
// unlisted child tenant. A listed tenant's account and an eligible root agent register
// in the same run, so the refusals are the policy and not a broken setup. Each refusal
// is an event naming the software AAGUID and the reason.
func TestSoftwareAuthenticator_RegistrationRefusedOutsideThePolicy(t *testing.T) {
	e := newSWAEnv(t)
	// The root tenant is listed too: it is refused by shape, not by the list. The child
	// tenant is deliberately not listed.
	e.api.SetSoftwareAuthenticatorTenants([]string{swaTenant, swaRootTenant})
	e.api.SetSoftwareAuthenticatorRootAgentAccounts(true)

	control := e.newAgent("swa-listed", swaTenant)
	e.mustSetFlag(control.username, true)
	require.Equal(t, http.StatusCreated, control.enroll().Status, "a flagged account in a listed tenant registers")
	rootControl := e.newRootAgent("swa-root-eligible")
	e.mustSetFlag(rootControl.username, true)
	require.Equal(t, http.StatusCreated, rootControl.enroll().Status, "an eligible root agent account registers")

	refused := func(t *testing.T, username, token string) {
		t.Helper()
		agent := &swaAgent{e: e, username: username, token: token, auth: e.newSoftAuthenticator()}
		resp := agent.enroll()
		assert.Equal(t, http.StatusForbidden, resp.Status, "software enrollment: %s", resp)
		assert.Equal(t, swaSoftwareCode, resp.errCode())
		assert.Empty(t, agent.credentialIDs(), "no credential was stored")
	}
	flagRefused := func(t *testing.T, username string) {
		t.Helper()
		flag := e.setFlag(username, true)
		assert.Equal(t, http.StatusBadRequest, flag.Status, "the flag cannot be set: %s", flag)
		assert.Equal(t, swaSoftwareCode, flag.errCode())
	}

	t.Run("root-scope account while root_agent_accounts is off, even with the flag set", func(t *testing.T) {
		token, resp := e.createAccount(map[string]interface{}{"username": "swa-root-off", "root_scope": true})
		require.Equal(t, http.StatusCreated, resp.Status, "%s", resp)
		e.mustSetFlag("swa-root-off", true) // the setting is on here, so the flag can be set
		e.api.SetSoftwareAuthenticatorRootAgentAccounts(false)
		defer e.api.SetSoftwareAuthenticatorRootAgentAccounts(true)
		refused(t, "swa-root-off", token)
		flagRefused(t, "swa-root-off")
	})

	t.Run("cfgms-admin", func(t *testing.T) {
		token, resp := e.createAccount(map[string]interface{}{
			"username": "cfgms-admin", "root_scope": true, "reset_credentials": true,
		})
		require.Equal(t, http.StatusOK, resp.Status, "re-issue the system admin enrollment link: %s", resp)
		flagRefused(t, "cfgms-admin")
		refused(t, "cfgms-admin", token)
	})

	t.Run("account with a bound admin certificate, even with the flag set", func(t *testing.T) {
		token, resp := e.createAccount(map[string]interface{}{"username": "swa-root-cert", "root_scope": true})
		require.Equal(t, http.StatusCreated, resp.Status, "%s", resp)
		e.mustSetFlag("swa-root-cert", true) // no certificate is bound yet
		_, cert := newAdminMTLSClient(t, e.ctrl, "swa-root-cert")
		e.bindAdminCert("swa-root-cert", cert)
		refused(t, "swa-root-cert", token)
		flagRefused(t, "swa-root-cert")
	})

	t.Run("account with an empty tenant", func(t *testing.T) {
		token, resp := e.createAccount(map[string]interface{}{"username": "swa-no-tenant"})
		require.Equal(t, http.StatusCreated, resp.Status, "%s", resp)
		flagRefused(t, "swa-no-tenant")
		refused(t, "swa-no-tenant", token)
	})

	t.Run("account in the root tenant", func(t *testing.T) {
		token, resp := e.createAccount(map[string]interface{}{"username": "swa-root-tenant", "tenant_id": swaRootTenant})
		require.Equal(t, http.StatusCreated, resp.Status, "%s", resp)
		flagRefused(t, "swa-root-tenant")
		refused(t, "swa-root-tenant", token)
	})

	t.Run("listed parent does not cover an unlisted child", func(t *testing.T) {
		token, resp := e.createAccount(map[string]interface{}{"username": "swa-child", "tenant_id": swaChildTenant})
		require.Equal(t, http.StatusCreated, resp.Status, "%s", resp)
		e.mustSetFlag("swa-child", true) // the flag may be set ahead of the list
		refused(t, "swa-child", token)

		// Listing the child is what admits it.
		e.api.SetSoftwareAuthenticatorTenants([]string{swaTenant, swaChildTenant})
		agent := &swaAgent{e: e, username: "swa-child", token: token, auth: e.newSoftAuthenticator()}
		assert.Equal(t, http.StatusCreated, agent.enroll().Status, "the listed child registers")
	})

	t.Run("audit", func(t *testing.T) {
		events := e.audit()
		assert.ElementsMatch(t, []string{
			"root_agent_setting_off", "root_agent_flag_unset", "root_agent_cert_bound", "policy", "policy", "policy",
		}, denialReasons(events), "each refused registration is an event naming the software AAGUID and its reason")
		assert.Equal(t, 3, auditCount(events, "account.passkey_enrolled", business.AuditResultSuccess),
			"the admitted registrations (listed tenant, root agent, listed child) are marked")
	})
}
