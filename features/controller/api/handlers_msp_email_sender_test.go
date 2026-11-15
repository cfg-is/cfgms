// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	mspSenderPassword = "Zq9-msp-sender-pass-5521"
	mspSenderUsername = "msp-mailer-user"
)

// mspSenderEnv is a server with the tenant tree root > msp-a > client-1, root >
// msp-b, the MSP sender store wired, and the routes registered on a real router.
type mspSenderEnv struct {
	server *Server
	router *mux.Router
	logs   *senderLogCapture
}

func newMSPSenderEnv(t *testing.T) *mspSenderEnv {
	t.Helper()
	logs := &senderLogCapture{}
	server := setupCrossingTestServerWithLogger(t, logs)
	seedTenantTree(t, server)
	_, cs := newApprovalStore(t)
	st, err := NewMSPEmailSenderStore(cs)
	require.NoError(t, err)
	server.SetMSPEmailSenderStore(st)
	router := mux.NewRouter()
	registerMSPEmailSenderRoutes(server, router)
	return &mspSenderEnv{server: server, router: router, logs: logs}
}

func mspSenderAdmin(tenantID string) *Principal {
	return &Principal{ID: tenantID + "-admin", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
}

// do serves the request through the registered route (permission middleware
// included) as principal p.
func (e *mspSenderEnv) do(t *testing.T, p *Principal, method, tenantID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/tenants/"+tenantID+"/email-sender", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, p.TenantID)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scopeForVerifiedAdminCert(p.TenantID))
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

func mspSenderBody(over map[string]interface{}) string {
	m := map[string]interface{}{
		"host": "smtp.msp-a.example", "port": 587, "tls_mode": "starttls",
		"from": "ops@msp-a.example", "username": mspSenderUsername, "password": mspSenderPassword,
	}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func decodeMSPSender(t *testing.T, rec *httptest.ResponseRecorder) mspEmailSenderResponse {
	t.Helper()
	var env struct {
		Data mspEmailSenderResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	return env.Data
}

// stored returns what the stores hold for mspID.
func (e *mspSenderEnv) stored(t *testing.T, mspID string) (*MSPEmailSender, string) {
	t.Helper()
	sender, err := e.server.MSPEmailSenderStore().Get(context.Background(), mspID)
	require.NoError(t, err)
	pw, err := e.server.readMSPEmailPassword(context.Background(), mspID)
	require.NoError(t, err)
	return sender, pw
}

func TestMSPEmailSender_PermissionGate(t *testing.T) {
	env := newMSPSenderEnv(t)

	t.Run("an implicit admin of the MSP reaches every route", func(t *testing.T) {
		admin := mspSenderAdmin("msp-a")
		assert.Equal(t, http.StatusOK, env.do(t, admin, http.MethodGet, "msp-a", "").Code)
		assert.Equal(t, http.StatusOK, env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(nil)).Code)
		assert.Equal(t, http.StatusOK, env.do(t, admin, http.MethodDelete, "msp-a", "").Code)
	})

	t.Run("an explicit permission list without the permission gets 403", func(t *testing.T) {
		p := &Principal{ID: "limited", TenantID: "msp-a", Assurance: session.AssuranceStrong,
			Permissions: []string{"tenant:read", "tenant:update", "notification:configure"}}
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			rec := env.do(t, p, method, "msp-a", mspSenderBody(nil))
			assert.Equal(t, http.StatusForbidden, rec.Code, method)
		}
		sender, pw := env.stored(t, "msp-a")
		assert.Nil(t, sender)
		assert.Empty(t, pw)
	})

	t.Run("an explicit permission list holding it is admitted", func(t *testing.T) {
		p := &Principal{ID: "holder", TenantID: "msp-a", Assurance: session.AssuranceStrong,
			Permissions: []string{"notification:configure-msp"}}
		assert.Equal(t, http.StatusOK, env.do(t, p, http.MethodGet, "msp-a", "").Code)
	})
}

func TestMSPEmailSender_BelowStrongAssuranceRefused(t *testing.T) {
	env := newMSPSenderEnv(t)
	for _, level := range []session.AssuranceLevel{session.AssuranceBasic, session.AssuranceMachine} {
		p := mspSenderAdmin("msp-a")
		p.Assurance = level
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			rec := env.do(t, p, method, "msp-a", mspSenderBody(nil))
			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, rec.Code, "%s at %s", method, level)
		}
	}
	// A basic-assurance caller is sent to step up rather than refused outright.
	p := mspSenderAdmin("msp-a")
	p.Assurance = session.AssuranceBasic
	rec := env.do(t, p, http.MethodPut, "msp-a", mspSenderBody(nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")

	sender, pw := env.stored(t, "msp-a")
	assert.Nil(t, sender, "a refused PUT stores nothing")
	assert.Empty(t, pw)
}

func TestMSPEmailSender_SetReadReplaceRemove(t *testing.T) {
	env := newMSPSenderEnv(t)
	admin := mspSenderAdmin("msp-a")

	rec := env.do(t, admin, http.MethodGet, "msp-a", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, mspEmailSenderResponse{}, decodeMSPSender(t, rec), "nothing is configured at first")

	rec = env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	want := mspEmailSenderResponse{
		Configured: true, PasswordPresent: true, Host: "smtp.msp-a.example", Port: 587,
		TLSMode: "starttls", From: "ops@msp-a.example", Username: mspSenderUsername,
	}
	assert.Equal(t, want, decodeMSPSender(t, rec))

	rec = env.do(t, admin, http.MethodGet, "msp-a", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, want, decodeMSPSender(t, rec))
	assert.NotContains(t, rec.Body.String(), mspSenderPassword, "the password is write-only")
	assert.NotContains(t, strings.ToLower(rec.Body.String()), `"password"`)
	_, pw := env.stored(t, "msp-a")
	assert.Equal(t, mspSenderPassword, pw)

	// A settings-only edit keeps the stored password.
	rec = env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(map[string]interface{}{
		"host": "mail.msp-a.example", "port": 465, "tls_mode": "implicit_tls", "password": nil}))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	got := decodeMSPSender(t, rec)
	assert.Equal(t, "mail.msp-a.example", got.Host)
	assert.Equal(t, 465, got.Port)
	assert.True(t, got.PasswordPresent)
	sender, pw := env.stored(t, "msp-a")
	require.NotNil(t, sender)
	assert.Equal(t, "mail.msp-a.example", sender.Host)
	assert.Equal(t, mspSenderPassword, pw, "the password survived a settings-only edit")

	// A replacement with a new password replaces it.
	rec = env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(map[string]interface{}{"password": "new-pass-8842"}))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	_, pw = env.stored(t, "msp-a")
	assert.Equal(t, "new-pass-8842", pw)

	// An omitted tls_mode stores the default.
	rec = env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(map[string]interface{}{"tls_mode": nil, "port": nil}))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "starttls", decodeMSPSender(t, rec).TLSMode)

	rec = env.do(t, admin, http.MethodDelete, "msp-a", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, mspEmailSenderResponse{}, decodeMSPSender(t, rec))
	sender, pw = env.stored(t, "msp-a")
	assert.Nil(t, sender, "the record is removed")
	assert.Empty(t, pw, "the password is removed")

	rec = env.do(t, admin, http.MethodGet, "msp-a", "")
	assert.Equal(t, mspEmailSenderResponse{}, decodeMSPSender(t, rec))

	// Removing an absent sender is not an error.
	assert.Equal(t, http.StatusOK, env.do(t, admin, http.MethodDelete, "msp-a", "").Code)
}

func TestMSPEmailSender_TenantIsolation(t *testing.T) {
	env := newMSPSenderEnv(t)
	adminA := mspSenderAdmin("msp-a")
	adminB := mspSenderAdmin("msp-b")
	require.Equal(t, http.StatusOK, env.do(t, adminB, http.MethodPut, "msp-b",
		mspSenderBody(map[string]interface{}{"host": "smtp.msp-b.example"})).Code)

	for _, target := range []string{"msp-b", "client-1", "no-such-tenant", "root"} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			rec := env.do(t, adminA, method, target, mspSenderBody(nil))
			assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s", method, target)
			assert.Contains(t, rec.Body.String(), "TENANT_NOT_FOUND", "%s %s", method, target)
		}
	}

	// A client-tenant admin cannot reach its parent MSP's sender, nor its own tenant's.
	client := mspSenderAdmin("client-1")
	for _, target := range []string{"msp-a", "client-1"} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			assert.Equal(t, http.StatusNotFound, env.do(t, client, method, target, mspSenderBody(nil)).Code, "%s %s", method, target)
		}
	}

	sender, pw := env.stored(t, "msp-b")
	require.NotNil(t, sender)
	assert.Equal(t, "smtp.msp-b.example", sender.Host, "MSP B's sender is untouched")
	assert.Equal(t, mspSenderPassword, pw)
	for _, id := range []string{"msp-a", "client-1"} {
		sender, pw = env.stored(t, id)
		assert.Nil(t, sender, id)
		assert.Empty(t, pw, id)
	}
}

func TestMSPEmailSender_RootScopedCaller(t *testing.T) {
	env := newMSPSenderEnv(t)
	ctx := context.Background()
	root := rootScopedPrincipal("root-op-1")
	root.CertSerial = "msp-sender-test-serial"
	admin := mspSenderAdmin("msp-a")
	require.Equal(t, http.StatusOK, env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(nil)).Code)

	// No crossing: the crossing challenge on every verb, and nothing is disclosed.
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := env.do(t, root, method, "msp-a", mspSenderBody(map[string]interface{}{"host": "evil.example"}))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, method)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "tenant-crossing", method)
		assert.NotContains(t, rec.Body.String(), "smtp.msp-a.example", method)
		assert.NotContains(t, rec.Body.String(), "ops@msp-a.example", method)
	}

	now := time.Now().UTC()
	require.NoError(t, env.server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-1", TenantID: "msp-a", Kind: business.TenantCrossingKindGrant,
		GrantedBy: "msp-a-admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	rec := env.do(t, root, http.MethodGet, "msp-a", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	got := decodeMSPSender(t, rec)
	assert.True(t, got.Configured)
	assert.True(t, got.PasswordPresent)
	assert.NotContains(t, rec.Body.String(), mspSenderPassword)

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		rec = env.do(t, root, method, "msp-a", mspSenderBody(map[string]interface{}{"host": "evil.example"}))
		require.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", method, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "ROOT_SCOPED_CANNOT_EDIT_EMAIL_SENDER", method)
	}
	sender, pw := env.stored(t, "msp-a")
	require.NotNil(t, sender)
	assert.Equal(t, "smtp.msp-a.example", sender.Host, "root could not replace the sender")
	assert.Equal(t, mspSenderPassword, pw, "root could not remove the password")

	// The crossing covers msp-a only: a client tenant is still no sender target.
	assert.Equal(t, http.StatusNotFound, env.do(t, root, http.MethodGet, "client-1", "").Code)
}

func TestMSPEmailSender_InvalidBodiesStoreNothing(t *testing.T) {
	env := newMSPSenderEnv(t)
	admin := mspSenderAdmin("msp-a")

	for name, body := range map[string]string{
		"unknown field":         mspSenderBody(map[string]interface{}{"extra": "x"}),
		"plaintext mode":        mspSenderBody(map[string]interface{}{"tls_mode": "plaintext"}),
		"port 25":               mspSenderBody(map[string]interface{}{"port": 25}),
		"empty host":            mspSenderBody(map[string]interface{}{"host": ""}),
		"host with a slash":     mspSenderBody(map[string]interface{}{"host": "smtp.example/x"}),
		"missing password":      mspSenderBody(map[string]interface{}{"password": nil}),
		"empty password":        mspSenderBody(map[string]interface{}{"password": ""}),
		"empty from":            mspSenderBody(map[string]interface{}{"from": ""}),
		"from with a name":      mspSenderBody(map[string]interface{}{"from": "Ops <ops@msp-a.example>"}),
		"not json":              `{`,
		"empty body":            ``,
		"trailing data":         mspSenderBody(nil) + `{}`,
		"wrong type for a port": `{"host":"h.example","port":"587","from":"a@b.example","password":"x"}`,
		"oversized body":        mspSenderBody(map[string]interface{}{"username": strings.Repeat("u", 9000)}),
	} {
		rec := env.do(t, admin, http.MethodPut, "msp-a", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), mspSenderPassword, name)
		sender, pw := env.stored(t, "msp-a")
		assert.Nil(t, sender, "%s stores no record", name)
		assert.Empty(t, pw, "%s stores no password", name)
	}

	// Once a sender exists, an invalid settings-only edit changes nothing either.
	require.Equal(t, http.StatusOK, env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(nil)).Code)
	for name, body := range map[string]string{
		"port 25":        mspSenderBody(map[string]interface{}{"port": 25, "password": nil}),
		"plaintext mode": mspSenderBody(map[string]interface{}{"tls_mode": "none", "password": nil}),
		"bad password":   mspSenderBody(map[string]interface{}{"host": "other.example", "password": "line\nbreak"}),
	} {
		rec := env.do(t, admin, http.MethodPut, "msp-a", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
	}
	sender, pw := env.stored(t, "msp-a")
	require.NotNil(t, sender)
	assert.Equal(t, "smtp.msp-a.example", sender.Host)
	assert.Equal(t, mspSenderPassword, pw)
}

func TestMSPEmailSender_Unwired(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	_, err := server.tenantManager.GetTenant(context.Background(), testRootTenantID)
	require.NoError(t, err)
	seedTenantTree(t, server)
	router := mux.NewRouter()
	registerMSPEmailSenderRoutes(server, router)
	env := &mspSenderEnv{server: server, router: router}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := env.do(t, mspSenderAdmin("msp-a"), method, "msp-a", mspSenderBody(nil))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, method)
	}
}

func TestMSPEmailSender_AuditAndLogsCarryNoSecret(t *testing.T) {
	env := newMSPSenderEnv(t)
	admin := mspSenderAdmin("msp-a")

	require.Equal(t, http.StatusOK, env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(nil)).Code)
	set := auditEntriesByAction(t, env.server, "tenant.email_sender_updated")
	require.Len(t, set, 1)
	require.Equal(t, http.StatusOK, env.do(t, admin, http.MethodDelete, "msp-a", "").Code)
	removed := auditEntriesByAction(t, env.server, "tenant.email_sender_removed")
	require.Len(t, removed, 1)

	for _, e := range append(set, removed...) {
		assert.Equal(t, "msp-a", e.TenantID)
		assert.Equal(t, "msp-a-admin", e.UserID)
		assert.Equal(t, business.AuditSeverityHigh, e.Severity)
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		for _, secret := range []string{mspSenderPassword, mspSenderUsername} {
			assert.NotContains(t, string(raw), secret)
		}
	}
	assert.Equal(t, "smtp.msp-a.example", set[0].Details["host"])
	assert.EqualValues(t, 587, set[0].Details["port"])
	assert.Equal(t, "starttls", set[0].Details["tls_mode"])
	assert.Equal(t, "ops@msp-a.example", set[0].Details["from"])
	assert.NotContains(t, set[0].Details, "username")
	assert.NotContains(t, set[0].Details, "password")
	assert.Equal(t, "smtp.msp-a.example", removed[0].Details["host"], "the removal names the sender it removed")

	// A refused or invalid request writes no audit event.
	env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(map[string]interface{}{"port": 25}))
	env.do(t, mspSenderAdmin("msp-b"), http.MethodDelete, "msp-a", "")
	assert.Len(t, auditEntriesByAction(t, env.server, "tenant.email_sender_updated"), 1)
	assert.Len(t, auditEntriesByAction(t, env.server, "tenant.email_sender_removed"), 1)

	logs := env.logs.captured()
	assert.NotContains(t, logs, mspSenderPassword)
	assert.NotContains(t, logs, mspSenderUsername)
	assert.NotContains(t, logs, "smtp.msp-a.example", "the routes log ids only")
}

func TestMSPEmailSender_ConcurrentWritesStayConsistent(t *testing.T) {
	env := newMSPSenderEnv(t)
	admin := mspSenderAdmin("msp-a")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(map[string]interface{}{"host": fmt.Sprintf("h%d.msp-a.example", i)}))
			} else {
				env.do(t, admin, http.MethodDelete, "msp-a", "")
			}
		}(i)
	}
	wg.Wait()
	// Whatever order won, the pair is whole: a record and its password, or neither.
	sender, pw := env.stored(t, "msp-a")
	assert.Equal(t, sender != nil, pw != "", "record and password are written and removed together")
}

// TestMSPEmailSender_RoundTripDeliversThroughResolver proves the stored sender is
// the one used: after a PUT a tamper alert for a tenant of the MSP goes through the
// MSP's mail server, and after a DELETE it goes through the platform's.
func TestMSPEmailSender_RoundTripDeliversThroughResolver(t *testing.T) {
	f := newSenderFixture(t)
	_, cs := newApprovalStore(t)
	st, err := NewMSPEmailSenderStore(cs)
	require.NoError(t, err)
	f.server.SetMSPEmailSenderStore(st)
	router := mux.NewRouter()
	registerMSPEmailSenderRoutes(f.server, router)
	env := &mspSenderEnv{server: f.server, router: router}

	// The test seams admit the in-process mail server (loopback, its port, its CA).
	orig := mspEmailAllowedPorts
	mspEmailAllowedPorts = []int{f.msp.Port}
	t.Cleanup(func() { mspEmailAllowedPorts = orig })
	f.server.emailMu.Lock()
	f.server.mspEmailExtra = map[string]interface{}{"root_ca_pem": f.msp.CAPEM}
	f.server.emailMu.Unlock()
	t.Cleanup(pkgconfig.AllowLoopbackForTesting())

	admin := mspSenderAdmin("msp-a")
	rec := env.do(t, admin, http.MethodPut, "msp-a", mspSenderBody(map[string]interface{}{
		"host": "localhost", "port": f.msp.Port, "tls_mode": "implicit_tls",
		"username": testSMTPUser, "password": testSMTPPassword,
	}))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	entry := f.alarm(t, "client-1")
	assert.Equal(t, "msp", entry.Details["sender"])
	assert.Equal(t, "sent", entry.Details["notification"])
	assert.Len(t, f.msp.Messages(), 1, "the MSP server carries the alert")
	assert.Empty(t, f.platform.Messages())

	rec = env.do(t, admin, http.MethodDelete, "msp-a", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	entry = f.alarm(t, "msp-a")
	assert.Equal(t, "platform", entry.Details["sender"])
	assert.Equal(t, "sent", entry.Details["notification"])
	assert.Len(t, f.msp.Messages(), 1, "the removed sender receives nothing more")
	assert.Len(t, f.platform.Messages(), 1, "the platform server carries the alert after removal")
}
