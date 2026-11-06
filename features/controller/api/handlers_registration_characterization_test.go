// Characterization tests for Server.handleRegister (Issue #5869). They pin the
// externally visible behavior (status codes, bodies, store effects) so the
// function can be decomposed without changing it.
package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/registration"
)

// handlersregistrationCharErrHook returns a hook error so handleRegister must
// fall back to quarantine rather than grant access.
type handlersregistrationCharErrHook struct{}

func (*handlersregistrationCharErrHook) Evaluate(_ context.Context, _ RegistrationInput) (ApprovalDecision, string, error) {
	return DecisionApprove, "", fmt.Errorf("hook failure injected by characterization test")
}

func handlersregistrationCharPost(server *Server, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/register", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	server.handleRegister(rec, req)
	return rec
}

func handlersregistrationCharSaveToken(t *testing.T, store registration.Store, token, tenant string) {
	t.Helper()
	require.NoError(t, store.SaveToken(context.Background(), &registration.Token{
		Token:         token,
		TenantID:      tenant,
		ControllerURL: "grpc://controller:7443",
	}))
}

func TestHandlersregistrationChar_RequestValidation(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&AlwaysApproveHook{})
	handlersregistrationCharSaveToken(t, tokenStore, "cfgms_reg_char_validation", "tenant-char")

	valid := RegistrationRequest{
		Token:          "cfgms_reg_char_validation",
		DeviceID:       testValidDeviceID,
		IdentityKeyPub: testValidIdentityKeyPub,
		CSRPEM:         testValidCSRPEM,
	}
	mutate := func(f func(*RegistrationRequest)) RegistrationRequest {
		r := valid
		f(&r)
		return r
	}

	cases := []struct {
		name string
		req  RegistrationRequest
		code int
		body string
	}{
		{"missing token", mutate(func(r *RegistrationRequest) { r.Token = "" }), http.StatusBadRequest, "Registration token is required"},
		{"unknown token", mutate(func(r *RegistrationRequest) { r.Token = "cfgms_reg_char_unknown" }), http.StatusUnauthorized, "Invalid or expired registration token"},
		{"bad device id", mutate(func(r *RegistrationRequest) { r.DeviceID = "NOT-HEX" }), http.StatusBadRequest, "device_id is required and must be a 64-character lowercase hex string"},
		{"bad key algorithm", mutate(func(r *RegistrationRequest) { r.KeyAlgorithm = "rsa" }), http.StatusBadRequest, "key_algorithm must be"},
		{"bad base64 key", mutate(func(r *RegistrationRequest) { r.IdentityKeyPub = "!!!not-base64" }), http.StatusBadRequest, "identity_key_pub is required and must be base64-encoded"},
		{"invalid public key", mutate(func(r *RegistrationRequest) { r.IdentityKeyPub = "AAAA" }), http.StatusBadRequest, "identity_key_pub is not a valid public key"},
		{"device id not bound to key", mutate(func(r *RegistrationRequest) { r.DeviceID = strings.Repeat("ab", 32) }), http.StatusBadRequest, "device_id must be the lowercase hex SHA-256"},
		{"missing csr", mutate(func(r *RegistrationRequest) { r.CSRPEM = "" }), http.StatusBadRequest, "csr_pem is required"},
		{"private key in csr", mutate(func(r *RegistrationRequest) {
			r.CSRPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
		}), http.StatusBadRequest, "private key material is not accepted"},
		{"unparseable csr", mutate(func(r *RegistrationRequest) { r.CSRPEM = "not a csr" }), http.StatusBadRequest, "invalid certificate signing request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postRegisterWithBody(server, tc.req)
			assert.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.body)
		})
	}

	t.Run("non-POST", func(t *testing.T) {
		rec := handlersregistrationCharPost(server, http.MethodGet, "")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Contains(t, rec.Body.String(), "Method not allowed")
	})
	t.Run("malformed body", func(t *testing.T) {
		rec := handlersregistrationCharPost(server, http.MethodPost, "{not json")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Invalid request body")
	})
}

func TestHandlersregistrationChar_NoTokenStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.registrationTokenStore = nil

	rec := postRegister(server, "cfgms_reg_char_nostore")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Registration service unavailable")
}

// An invalid CSR must be refused before any store write: no pending entry, no
// token claim, so a subsequent valid registration still succeeds.
func TestHandlersregistrationChar_InvalidCSRWritesNothing(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&quarantineHookForTest{})
	const tenant = "tenant-char-csr"
	handlersregistrationCharSaveToken(t, tokenStore, "cfgms_reg_char_csr", tenant)

	rec := postRegisterWithBody(server, RegistrationRequest{
		Token:          "cfgms_reg_char_csr",
		DeviceID:       testValidDeviceID,
		IdentityKeyPub: testValidIdentityKeyPub,
		CSRPEM:         "garbage",
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)

	entries, err := server.pendingStore.ListAll(context.Background(), tenant)
	require.NoError(t, err)
	assert.Empty(t, entries)

	// The claim was not consumed: a valid request is quarantined (202), not 409.
	rec = postRegister(server, "cfgms_reg_char_csr")
	assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
}

func TestHandlersregistrationChar_DuplicateDeviceIDScopedToTenant(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServerWithStewardStore(t, tokenStore, newTestCertManager(t))
	server.SetApprovalHook(&AlwaysApproveHook{})
	handlersregistrationCharSaveToken(t, tokenStore, "cfgms_reg_char_dup_a", "tenant-char-a")
	handlersregistrationCharSaveToken(t, tokenStore, "cfgms_reg_char_dup_b", "tenant-char-b")

	require.Equal(t, http.StatusOK, postRegister(server, "cfgms_reg_char_dup_a").Code)

	rec := postRegister(server, "cfgms_reg_char_dup_a")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "device_id already registered in this tenant")

	assert.Equal(t, http.StatusOK, postRegister(server, "cfgms_reg_char_dup_b").Code,
		"the same DeviceID in another tenant is a separate namespace")
}

func TestHandlersregistrationChar_HookFailureQuarantines(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	// No cert manager: a quarantined registration must never reach issuance.
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&handlersregistrationCharErrHook{})
	const tenant = "tenant-char-hook"
	handlersregistrationCharSaveToken(t, tokenStore, "cfgms_reg_char_hook", tenant)

	rec := postRegister(server, "cfgms_reg_char_hook")
	assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "client_cert")

	entries, err := server.pendingStore.ListPending(context.Background(), tenant)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestHandlersregistrationChar_QuarantineWithoutPendingStore(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&quarantineHookForTest{})
	server.pendingStore = nil
	handlersregistrationCharSaveToken(t, tokenStore, "cfgms_reg_char_nopending", "tenant-char-np")

	rec := postRegister(server, "cfgms_reg_char_nopending")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "Registration admission service unavailable")
}

func TestHandlersregistrationChar_ApproveWithoutCertManager(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&AlwaysApproveHook{})
	handlersregistrationCharSaveToken(t, tokenStore, "cfgms_reg_char_nocert", "tenant-char-nc")

	rec := postRegister(server, "cfgms_reg_char_nocert")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Certificate manager unavailable")
}

func TestHandlersregistrationChar_RejectWritesNoPending(t *testing.T) {
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)
	server.SetApprovalHook(&rejectHookForTest{})
	const tenant = "tenant-char-rej"
	handlersregistrationCharSaveToken(t, tokenStore, "cfgms_reg_char_rej", tenant)

	rec := postRegister(server, "cfgms_reg_char_rej")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "Registration rejected")
	entries, err := server.pendingStore.ListAll(context.Background(), tenant)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
