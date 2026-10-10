// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	_ "github.com/cfgis/cfgms/pkg/notification/providers/smtp" // register the smtp provider for the notifier under test
	"github.com/cfgis/cfgms/pkg/session"
)

const (
	testSMTPUser     = "mailer"
	testSMTPPassword = "Zq9-correct-horse-battery"
	testPasswordKey  = "notifications.email.password"
)

// emailTestSMTPServer is a minimal in-process implicit-TLS SMTP server.
type emailTestSMTPServer struct {
	ln       net.Listener
	CAPEM    string
	Port     int
	mu       sync.Mutex
	messages []string
}

func (s *emailTestSMTPServer) Messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.messages...)
}

func newEmailTestSMTPServer(t *testing.T) *emailTestSMTPServer {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{Organization: "notification-api-test", ValidityDays: 1})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	sc, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{CommonName: "localhost", DNSNames: []string{"localhost"}, ValidityDays: 1})
	require.NoError(t, err)
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	pair, err := cert.LoadTLSCertificate(sc.CertificatePEM, sc.PrivateKeyPEM)
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &emailTestSMTPServer{ln: ln, CAPEM: string(caPEM), Port: ln.Addr().(*net.TCPAddr).Port}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(tls.Server(c, tlsCfg))
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *emailTestSMTPServer) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(c)
	w := func(l string) { _, _ = c.Write([]byte(l + "\r\n")) }
	w("220 localhost ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch strings.ToUpper(strings.SplitN(line, " ", 2)[0]) {
		case "EHLO", "HELO":
			w("250-localhost")
			w("250 AUTH PLAIN")
		case "AUTH":
			parts := strings.Fields(line)
			var dec []byte
			if len(parts) == 3 {
				dec, _ = base64.StdEncoding.DecodeString(parts[2])
			}
			f := strings.Split(string(dec), "\x00")
			if len(f) == 3 && f[1] == testSMTPUser && f[2] == testSMTPPassword {
				w("235 ok")
			} else {
				w("535 authentication failed")
			}
		case "MAIL", "RCPT":
			w("250 ok")
		case "DATA":
			w("354 go")
			var sb strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				sb.WriteString(l)
			}
			s.mu.Lock()
			s.messages = append(s.messages, sb.String())
			s.mu.Unlock()
			w("250 queued")
		case "RSET":
			w("250 ok")
		case "QUIT":
			w("221 bye")
			return
		default:
			w("502 unsupported")
		}
	}
}

// newEmailTestServer returns an API server configured for implicit-TLS email
// against smtp, with no credential stored yet.
func newEmailTestServer(t *testing.T, smtp *emailTestSMTPServer) *Server {
	t.Helper()
	server := setupTestServer(t)
	server.cfg.Notifications = &config.NotificationsConfig{Email: &config.EmailConfig{
		Provider: "smtp", Host: "localhost", Port: smtp.Port, From: "cfgms@acme-corp.example",
		Username: testSMTPUser, TLSMode: "implicit_tls", PasswordSecretKey: testPasswordKey,
	}}
	server.emailExtra = map[string]interface{}{"root_ca_pem": smtp.CAPEM}
	server.initEmailNotifier(context.Background())
	return server
}

func emailStrongPrincipal() *Principal {
	return &Principal{ID: "root-admin", Name: "mtls-cert:root-admin", Assurance: session.AssuranceStrong, CertSerial: "test-serial", ImplicitAdmin: true}
}

// emailCall runs a handler through requirePermission as a root-scoped strong principal.
func emailCall(t *testing.T, server *Server, p *Principal, scope ctxkeys.TenantScope, method, path, body string, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scope)
	rec := httptest.NewRecorder()
	server.requirePermission("notification", "configure")(h).ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

func decodeEmailData(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "body: %s", rec.Body.String())
	return data
}

func TestEmail_NotConfigured_ReportsFalseAndNilAccessor(t *testing.T) {
	server := setupTestServer(t)
	assert.Nil(t, server.EmailNotifier())

	rec := emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodGet, "/api/v1/notifications/email", "", server.handleGetEmailSettings)
	require.Equal(t, http.StatusOK, rec.Code)
	data := decodeEmailData(t, rec)
	assert.Equal(t, false, data["configured"])
	assert.Equal(t, false, data["credential_present"])

	// Credential and test-send both refuse cleanly rather than panic.
	rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPut, "/x", `{"password":"p"}`, server.handlePutEmailCredential)
	assert.Equal(t, http.StatusConflict, rec.Code)
	rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPost, "/x", `{"to":"a@acme-corp.example"}`, server.handleTestEmail)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestEmail_CredentialStoredOnlyInSecretStore_ThenTestSendDelivers(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := newEmailTestServer(t, smtp)
	require.Nil(t, server.EmailNotifier(), "no credential yet, so no notifier")

	rec := emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodGet, "/x", "", server.handleGetEmailSettings)
	data := decodeEmailData(t, rec)
	assert.Equal(t, true, data["configured"])
	assert.Equal(t, false, data["credential_present"])

	rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPut, "/x", `{"password":"`+testSMTPPassword+`"}`, server.handlePutEmailCredential)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), testSMTPPassword)
	require.NotNil(t, server.EmailNotifier(), "notifier is rebuilt when the credential is stored")

	// Retrievable only through the secret store, under password_secret_key.
	sec, err := server.readEmailCredential(context.Background(), testPasswordKey)
	require.NoError(t, err)
	assert.Equal(t, testSMTPPassword, sec.Value)

	rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodGet, "/x", "", server.handleGetEmailSettings)
	assert.NotContains(t, rec.Body.String(), testSMTPPassword)
	assert.Equal(t, true, decodeEmailData(t, rec)["credential_present"])

	// No file under the data dir holds the password in cleartext.
	dataRoot := filepath.Dir(os.Getenv("CFGMS_SECRETS_REPO_PATH"))
	scanned := 0
	require.NoError(t, filepath.WalkDir(dataRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		scanned++
		assert.False(t, bytes.Contains(b, []byte(testSMTPPassword)), "cleartext password found in %s", p)
		return nil
	}))
	assert.Positive(t, scanned)

	// Test send delivers over TLS.
	rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPost, "/x", `{"to":"ops@acme-corp.example"}`, server.handleTestEmail)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	data = decodeEmailData(t, rec)
	assert.Equal(t, true, data["delivered"])
	recips := data["recipients"].([]interface{})
	require.Len(t, recips, 1)
	assert.Equal(t, "ops@acme-corp.example", recips[0].(map[string]interface{})["address"])
	require.Len(t, smtp.Messages(), 1)
}

func TestEmail_TestSend_WrongPassword_SanitizedFailure(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := newEmailTestServer(t, smtp)
	const wrong = "Wrong-pw-Xk3-do-not-leak"
	rec := emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPut, "/x", `{"password":"`+wrong+`"}`, server.handlePutEmailCredential)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPost, "/x", `{"to":"ops@acme-corp.example"}`, server.handleTestEmail)
	require.Equal(t, http.StatusOK, rec.Code)
	data := decodeEmailData(t, rec)
	assert.Equal(t, false, data["delivered"])
	assert.NotEmpty(t, data["failure_reason"])
	assert.NotContains(t, rec.Body.String(), wrong)
	assert.NotContains(t, rec.Body.String(), testSMTPPassword)
	assert.Empty(t, smtp.Messages())
}

func TestEmail_TestSend_InvalidRecipientRejected(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := newEmailTestServer(t, smtp)
	for _, to := range []string{``, `not-an-address`, `Ops <ops@acme-corp.example>`, "a@acme-corp.example\r\nBcc: b@acme-corp.example", `a@x.example, b@x.example`} {
		body, _ := json.Marshal(map[string]string{"to": to})
		rec := emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPost, "/x", string(body), server.handleTestEmail)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "to=%q", to)
	}
}

func TestEmail_TestSend_RequestSuppliedContentRejected(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := newEmailTestServer(t, smtp)
	rec := emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPut, "/x", `{"password":"`+testSMTPPassword+`"}`, server.handlePutEmailCredential)
	require.Equal(t, http.StatusOK, rec.Code)

	for _, body := range []string{
		`{"to":"ops@acme-corp.example","subject":"attacker subject"}`,
		`{"to":"ops@acme-corp.example","body":"attacker body"}`,
	} {
		rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPost, "/x", body, server.handleTestEmail)
		assert.Equal(t, http.StatusBadRequest, rec.Code, body)
	}
	assert.Empty(t, smtp.Messages(), "nothing is sent when content fields are supplied")

	rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPost, "/x", `{"to":"ops@acme-corp.example"}`, server.handleTestEmail)
	require.Equal(t, http.StatusOK, rec.Code)
	msgs := smtp.Messages()
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0], emailTestSubject)
}

func TestEmail_CredentialBodyBoundedAndRequired(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := newEmailTestServer(t, smtp)
	rec := emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPut, "/x", `{"password":""}`, server.handlePutEmailCredential)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	rec = emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPut, "/x", `{"password":"`+strings.Repeat("a", 8192)+`"}`, server.handlePutEmailCredential)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Nil(t, server.EmailNotifier())
}

func TestEmail_TenantScopedCallerRefusedOnAllEndpoints(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := newEmailTestServer(t, smtp)
	scope := ctxkeys.NewTenantScope("client-1")
	for name, h := range map[string]http.HandlerFunc{"get": server.handleGetEmailSettings, "put": server.handlePutEmailCredential, "test": server.handleTestEmail} {
		rec := emailCall(t, server, emailStrongPrincipal(), scope, http.MethodPost, "/x", `{"password":"p","to":"a@acme-corp.example"}`, h)
		assert.Equal(t, http.StatusForbidden, rec.Code, name)
	}
}

func TestEmail_RefusedWithoutPermissionOrBelowStrong(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := newEmailTestServer(t, smtp)
	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/notifications/email", ""},
		{http.MethodPut, "/api/v1/notifications/email/credential", `{"password":"p"}`},
		{http.MethodPost, "/api/v1/notifications/email/test", `{"to":"a@acme-corp.example"}`},
	}
	noPerm := NewTestKey(t, server, []string{"steward:list"})
	machine := NewTestKey(t, server, []string{"notification:configure"}) // holds the permission, but API keys are below AssuranceStrong
	for _, rt := range routes {
		for name, key := range map[string]string{"no-permission": noPerm, "below-strong": machine} {
			req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
			req.Header.Set("X-API-Key", key)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s %s", name, rt.method, rt.path)
		}
	}

	// A non-admin strong principal without the permission is refused too.
	p := &Principal{ID: "viewer", Assurance: session.AssuranceStrong, CertSerial: "s"}
	rec := emailCall(t, server, p, ctxkeys.NewRootScope(), http.MethodGet, "/x", "", server.handleGetEmailSettings)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestEmail_StartupBuildsNotifierWhenCredentialAlreadyStored(t *testing.T) {
	smtp := newEmailTestSMTPServer(t)
	server := newEmailTestServer(t, smtp)
	rec := emailCall(t, server, emailStrongPrincipal(), ctxkeys.NewRootScope(), http.MethodPut, "/x", `{"password":"`+testSMTPPassword+`"}`, server.handlePutEmailCredential)
	require.Equal(t, http.StatusOK, rec.Code)

	server.emailMu.Lock()
	server.emailNotifier = nil
	server.emailMu.Unlock()
	server.initEmailNotifier(context.Background())
	require.NotNil(t, server.EmailNotifier())
	assert.Equal(t, "smtp", server.EmailNotifier().Name())
}
